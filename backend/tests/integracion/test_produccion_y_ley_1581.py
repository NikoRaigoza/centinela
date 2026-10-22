"""Preparación para producción contra PostgreSQL real: Ley 1581 (autorización, supresión, retención), recuperación de
acceso con contraseña temporal, límite por IP y verificación de la configuración."""
from __future__ import annotations

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import text

from centinela.adaptadores.entrada.api.app import crear_app
from centinela.adaptadores.entrada.api.limite import LimitadorIP
from centinela.config import Configuracion
from centinela.dominio.usuario import VERSION_POLITICA
from tests.integracion.test_adjuntos_fraude_reportes_tiempo_real import FRAUDE, QUISHING, cliente_admin
from tests.integracion.test_flujo_analisis import CLAVE, LEGITIMO, armar_entorno, cliente_de, conectar_buzon

pytestmark = pytest.mark.integracion


@pytest.fixture
def entorno(config, limpiar, motor_owner):
    c, auth, gmail = armar_entorno(config, motor_owner)
    yield c, auth, gmail
    c.motor.dispose()


def _anonimo(c) -> TestClient:
    return TestClient(crear_app(c), base_url="http://testserver")


# ---------------------------------------------------------------------- Ley 1581
def test_registro_exige_autorizacion_y_la_guarda(entorno, motor_owner):
    c, *_ = entorno
    cli = _anonimo(c)
    datos = {"correo": "nuevo@gmail.com", "nombre": "Nueva Persona", "clave": CLAVE}
    r = cli.post("/api/auth/registro", json=datos)
    assert r.status_code == 422 and "autorizar el tratamiento" in r.json()["mensaje"]
    assert cli.post("/api/auth/registro", json={**datos, "acepta_politica": True}).status_code == 202
    with motor_owner.connect() as cx:
        version, en = cx.execute(text("SELECT consentimiento_version, consentimiento_en FROM centinela.usuario "
                                      "WHERE correo = 'nuevo@gmail.com'")).one()
    assert version == VERSION_POLITICA and en is not None


def test_informacion_legal_publica(entorno):
    c, *_ = entorno
    r = _anonimo(c).get("/api/publico/legal").json()
    assert r == {"version_politica": VERSION_POLITICA, "responsable": c.config.responsable_nombre,
                 "correo_contacto": c.config.responsable_correo, "dias_sin_riesgo": 30, "dias_casos": 365}


def test_eliminar_mi_cuenta_borra_todo_y_revoca_google(entorno, motor_owner):
    c, auth, gmail = entorno
    ana = cliente_de(c, "ana@gmail.com")
    buzon_id = conectar_buzon(ana, auth, gmail)
    for crudo in (QUISHING, FRAUDE, LEGITIMO):
        gmail.llega(crudo)
    ana.post(f"/api/buzones/{buzon_id}/revision")
    with motor_owner.connect() as cx:
        ana_id = cx.scalar(text("SELECT id FROM centinela.usuario WHERE correo = 'ana@gmail.com'"))
        assert cx.scalar(text("SELECT count(*) FROM centinela.caso")) == 2

    assert ana.post("/api/usuarios/yo/eliminacion", json={"clave": "equivocada-123"}).status_code == 401
    r = ana.post("/api/usuarios/yo/eliminacion", json={"clave": CLAVE})
    assert r.status_code == 204 and 'centinela_renovacion=""' in r.headers["set-cookie"]
    assert auth.revocados == ["rt-cod"]                                    # el permiso también se quitó en Google

    with motor_owner.connect() as cx:
        for tabla in ("buzon", "mensaje_analizado", "caso", "veredicto", "adjunto_analizado", "aviso"):
            assert cx.scalar(text(f"SELECT count(*) FROM centinela.{tabla}")) == 0, tabla  # noqa: S608 - nombres fijos
        assert cx.scalar(text("SELECT count(*) FROM centinela.usuario WHERE id = :i"), {"i": ana_id}) == 0
        assert cx.scalar(text("SELECT count(*) FROM centinela.sesion WHERE usuario_id = :i"), {"i": ana_id}) == 0
        # La auditoría se conserva (inmutable) y registra la supresión
        assert cx.scalar(text("SELECT count(*) FROM centinela.auditoria WHERE accion = 'usuario.eliminar' "
                              "AND exito AND usuario_id = :i"), {"i": ana_id}) == 1
    assert _anonimo(c).post("/api/auth/inicio", json={
        "correo": "ana@gmail.com", "clave": CLAVE}).status_code == 401


def test_el_unico_administrador_no_puede_eliminarse(entorno):
    c, *_ = entorno
    r = cliente_admin(c).post("/api/usuarios/yo/eliminacion", json={"clave": CLAVE})
    assert r.status_code == 409 and "único administrador" in r.json()["mensaje"]


def test_retencion_borra_lo_viejo_y_conserva_lo_abierto(entorno, motor_owner):
    c, auth, gmail = entorno
    ana = cliente_de(c, "ana@gmail.com")
    buzon_id = conectar_buzon(ana, auth, gmail)
    for crudo in (QUISHING, FRAUDE, LEGITIMO):
        gmail.llega(crudo)
    ana.post(f"/api/buzones/{buzon_id}/revision")
    casos = {x["asunto"]: x["id"] for x in ana.get("/api/casos").json()}
    ana.post(f"/api/casos/{casos['Favor']}/clasificacion", json={"decision": "confirmar"})      # caso cerrado
    with motor_owner.begin() as cx:                       # todo pasó hace 400 días
        cx.execute(text("UPDATE centinela.mensaje_analizado SET recibido_en = recibido_en - interval '400 days'"))
        cx.execute(text("UPDATE centinela.caso SET cerrado_en = cerrado_en - interval '400 days' WHERE cerrado_en IS NOT NULL"))

    r = c.aplicar_retencion.ejecutar()
    assert (r.mensajes_sin_riesgo, r.casos_cerrados) == (1, 1)            # el legítimo y el caso cerrado
    restantes = [x["asunto"] for x in ana.get("/api/casos").json()]
    assert restantes == ["Reactive su verificación"]                      # el caso abierto (en cuarentena) se queda
    assert c.aplicar_retencion.ejecutar().mensajes_sin_riesgo == 0        # idempotente
    with motor_owner.connect() as cx:
        assert cx.scalar(text("SELECT count(*) FROM centinela.auditoria WHERE accion = 'retencion.aplicar'")) == 2


# ---------------------------------------------------------------------- recuperación de acceso
def test_contrasena_temporal_del_administrador(entorno, motor_owner):
    c, *_ = entorno
    admin = cliente_admin(c)
    ana_id = next(u["id"] for u in admin.get("/api/admin/usuarios").json() if u["correo"] == "ana@gmail.com")
    vieja = cliente_de(c, "ana@gmail.com")                                # sesión abierta antes del restablecimiento

    temporal = admin.post(f"/api/admin/usuarios/{ana_id}/clave-temporal").json()["clave_temporal"]
    assert temporal.startswith("Temp-") and len(temporal) >= 15
    assert vieja.get("/api/buzones").status_code == 200        # el token de acceso dura 15 min, pero la renovación no:
    assert vieja.post("/api/auth/renovacion").status_code == 401
    cli = _anonimo(c)
    assert cli.post("/api/auth/inicio", json={"correo": "ana@gmail.com", "clave": CLAVE}).status_code == 401

    r = cli.post("/api/auth/inicio", json={"correo": "ana@gmail.com", "clave": temporal}).json()
    assert r["paso"] == "cambiar_clave" and r["acceso"] is None
    desafio = {"Authorization": f"Bearer {r['token_desafio']}"}
    assert cli.get("/api/buzones", headers=desafio).status_code == 401    # el desafío no sirve para usar el panel
    assert cli.post("/api/auth/clave-temporal", json={"nueva": temporal}, headers=desafio).status_code == 422
    r = cli.post("/api/auth/clave-temporal", json={"nueva": "Nueva-clave-2027"}, headers=desafio).json()
    assert r["paso"] == "completo" and r["acceso"]["usuario"]["debe_cambiar_clave"] is False
    assert cli.post("/api/auth/clave-temporal", json={"nueva": "Otra-clave-2028"}, headers=desafio).status_code == 401
    assert _anonimo(c).post("/api/auth/inicio", json={"correo": "ana@gmail.com",
                                                      "clave": "Nueva-clave-2027"}).json()["paso"] == "completo"
    with motor_owner.connect() as cx:
        assert cx.scalar(text("SELECT count(*) FROM centinela.auditoria WHERE accion = 'usuario.restablecer_clave'")) == 1

    assert cliente_de(c, "luis@gmail.com").post(f"/api/admin/usuarios/{ana_id}/clave-temporal").status_code == 403


# ---------------------------------------------------------------------- límite por IP
def test_limite_de_intentos_por_ip(entorno):
    c, *_ = entorno
    cli = _anonimo(c)
    codigos = [cli.post("/api/auth/inicio", json={"correo": f"x{i}@gmail.com", "clave": "Clave-mala-123"}).status_code
               for i in range(21)]
    assert codigos[:20] == [401] * 20 and codigos[20] == 429
    r = cli.post("/api/auth/inicio", json={"correo": "ana@gmail.com", "clave": CLAVE})
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0 and "Demasiados intentos" in r.json()["mensaje"]
    assert cli.get("/api/salud").status_code == 200                       # el resto de la API no se limita


def test_limitador_ventana_deslizante():
    t = {"ahora": 0.0}
    lim = LimitadorIP({"/x": (2, 60)}, reloj=lambda: t["ahora"])
    assert lim.permitir("/x", "1.1.1.1") is None and lim.permitir("/x", "1.1.1.1") is None
    assert lim.permitir("/x", "1.1.1.1") == 61
    assert lim.permitir("/x", "2.2.2.2") is None                          # otra IP no se ve afectada
    t["ahora"] = 60.5
    assert lim.permitir("/x", "1.1.1.1") is None


# ---------------------------------------------------------------------- configuración de producción
def _prod(**cambios) -> Configuracion:
    base = dict(entorno="produccion", jwt_secreto="k" * 20 + "Zq9" * 10, llave_cifrado=Fernet.generate_key().decode(),
                url_panel="https://centinela.me", gmail_redirect_uri="https://centinela.me/api/gmail/callback",
                origenes_cors=["https://centinela.me"], responsable_correo="contacto@centinela.me",
                bd_url="postgresql+psycopg://centinela_app:9f8e7d@bd/centinela",
                bd_url_migraciones="postgresql+psycopg://centinela_owner:1a2b3c@bd/centinela")
    return Configuracion(_env_file=None, **{**base, **cambios})


def test_configuracion_de_produccion():
    assert _prod().problemas_produccion() == []
    problemas = _prod(jwt_secreto="CAMBIAR" + "x" * 30, llave_cifrado="no-es-fernet", url_panel="http://centinela.me",
                      origenes_cors=["http://localhost:5173"], responsable_correo=None,
                      bd_url="postgresql+psycopg://centinela_app:centinela_app@localhost/centinela",
                      gmail_client_id="id", gmail_client_secret="s",
                      gmail_redirect_uri="https://otro.co/api/gmail/callback").problemas_produccion()
    assert len(problemas) == 7
    assert any("JWT" in p for p in problemas) and any("Fernet" in p for p in problemas)
    assert any("REDIRECT" in p for p in problemas) and any("RESPONSABLE_CORREO" in p for p in problemas)


def test_la_api_no_arranca_en_produccion_con_configuracion_insegura(config):
    from centinela.contenedor import construir

    c = construir(config.model_copy(update={"entorno": "produccion"}))
    with pytest.raises(RuntimeError, match="Configuración insegura"):
        crear_app(c)
    c.motor.dispose()


def test_sesiones_vencidas_se_borran(entorno, motor_owner):
    c, *_ = entorno
    cliente_de(c, "ana@gmail.com")
    with motor_owner.begin() as cx:
        cx.execute(text("UPDATE centinela.sesion SET creada_en = now() - interval '40 days', "
                        "expira_en = now() - interval '31 days'"))
    assert c.aplicar_retencion.ejecutar().sesiones == 1
    with motor_owner.connect() as cx:
        assert cx.scalar(text("SELECT count(*) FROM centinela.sesion")) == 0
