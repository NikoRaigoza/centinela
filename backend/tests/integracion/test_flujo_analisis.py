"""Flujo completo de la Fase 3 contra PostgreSQL real, con los modelos registrados y Gmail simulado:
llega un phishing → análisis → cuarentena → caso → aviso al dueño → revisión en el panel → liberación."""
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from centinela.adaptadores.entrada.api.app import crear_app
from centinela.adaptadores.salida.ml.registro import MANIFIESTO, leer_manifiesto, sha256_archivo
from centinela.aplicacion.casos_uso.acceso import AccionCuenta
from centinela.aplicacion.puertos import ModeloRegistrado
from centinela.contenedor import construir
from tests.gmail_falso import AutorizacionFalsa, BuzonGmailFalso, ProveedorGmailFalso, correo

pytestmark = pytest.mark.integracion
CLAVE = "Clave-segura-2026"
MODELOS = Path(__file__).resolve().parents[2] / "modelos"

PHISHING = correo(
    remitente="Bancolombia Alertas <alertas.bancolombia.co@gmail.com>", asunto="Su cuenta ha sido bloqueada",
    cuerpo="Estimado cliente, detectamos actividad inusual. Verifique su identidad de inmediato o su cuenta será "
           "suspendida en 24 horas. Ingrese su usuario y clave.",
    html='<p>Verifique su cuenta de inmediato.</p><a href="http://bancolombia-verificacion.top/login.php">www.bancolombia.com</a>',
    autenticacion="mx.google.com; dkim=pass; spf=pass; dmarc=pass", message_id="<phish@x>")
LEGITIMO = correo(remitente="Laura Gómez <laura.gomez@gmail.com>", asunto="Almuerzo del viernes",
                  cuerpo="Hola, confirmo el almuerzo del viernes a la una en el restaurante de siempre. Un abrazo.",
                  autenticacion="mx.google.com; dkim=pass; spf=pass; dmarc=pass", message_id="<legit@x>")


@pytest.fixture
def entorno(config, limpiar, motor_owner):
    with motor_owner.begin() as c:
        c.execute(text("TRUNCATE centinela.modelo_ml RESTART IDENTITY CASCADE"))
    config.dir_modelos = MODELOS
    proveedor, gmail = ProveedorGmailFalso(), BuzonGmailFalso("ana@gmail.com")
    auth = AutorizacionFalsa(proveedor)
    c = construir(config, autorizacion=auth, proveedor=proveedor)
    with c.uow() as uow:                                     # registra los modelos reales del repositorio
        for carpeta in (MODELOS / "enlaces" / "v3-prototipo", MODELOS / "contenido" / "v1-prototipo"):
            m = leer_manifiesto(carpeta)
            uow.modelos.registrar(ModeloRegistrado(0, m["tipo"], m["nombre"], m["version"],
                                                   str(carpeta.relative_to(MODELOS)), sha256_archivo(carpeta / MANIFIESTO),
                                                   m["dataset"], m["umbral_medio"], m["umbral_alto"], True, {}), activar=True)
        uow.confirmar()
    admin = c.crear_administrador.ejecutar("admin@centinela.co", "Admin", CLAVE)
    for correo_u in ("ana@gmail.com", "luis@gmail.com"):
        c.solicitar_registro.ejecutar(correo_u, "Persona", CLAVE)
    for u in c.listar_usuarios.ejecutar(admin.id):
        if not u.es_admin:
            c.cambiar_estado_cuenta.ejecutar(admin.id, u.id, AccionCuenta.APROBAR)
    yield c, auth, gmail
    c.motor.dispose()


def cliente_de(c, correo_u):
    cli = TestClient(crear_app(c), base_url="http://testserver")
    token = cli.post("/api/auth/inicio", json={"correo": correo_u, "clave": CLAVE}).json()["acceso"]["token_acceso"]
    cli.headers["Authorization"] = f"Bearer {token}"
    return cli


def test_phishing_a_cuarentena_aviso_y_liberacion(entorno):
    c, auth, gmail = entorno
    ana = cliente_de(c, "ana@gmail.com")
    auth.autoriza("cod", gmail)
    estado = parse_qs(urlparse(ana.post("/api/buzones/conexion").json()["url"]).query)["state"][0]
    assert ana.get("/api/gmail/callback", params={"state": estado, "code": "cod"}).status_code == 200
    buzon_id = ana.get("/api/buzones").json()[0]["id"]

    gid_phish, gid_legit = gmail.llega(PHISHING), gmail.llega(LEGITIMO)
    assert ana.post(f"/api/buzones/{buzon_id}/revision").json()["nuevos"] == 2

    # El phishing salió de la bandeja y quedó en cuarentena (sin borrarse); el legítimo no se tocó
    cuarentena = gmail.etiquetas["Centinela/Cuarentena"]
    assert cuarentena in gmail.mensajes[gid_phish]["etiquetas"] and "INBOX" not in gmail.mensajes[gid_phish]["etiquetas"]
    assert gmail.mensajes[gid_legit]["etiquetas"] == ["INBOX", "UNREAD"]

    # Un solo caso, en cuarentena, con máximo 3 razones claras
    casos = ana.get("/api/casos").json()
    assert len(casos) == 1
    caso = casos[0]
    assert caso["estado"] == "en_cuarentena" and caso["nivel"] == "alto" and caso["puede_liberarse"]
    assert 1 <= len(caso["razones"]) <= 3 and any("Bancolombia" in r for r in caso["razones"])

    # El aviso se inserta en el buzón del dueño y la siguiente revisión lo reconoce como propio (firma HMAC)
    assert c.enviar_avisos.ejecutar() == 1
    aviso = gmail.mensajes[f"g{len(gmail.mensajes)}"]
    assert b"Centinela detect" in aviso["crudo"]
    assert ana.post(f"/api/buzones/{buzon_id}/revision").json() == {"buzon_id": buzon_id, "nuevos": 0, "omitidos": 1,
                                                                  "estado": "activo", "error": None}
    assert c.enviar_avisos.ejecutar() == 0                                    # no se avisa dos veces

    detalle = ana.get(f"/api/casos/{caso['id']}").json()
    assert [e["tipo"] for e in detalle["historial"]] == ["creado", "cuarentena", "aviso"]
    assert detalle["enlaces"][0]["dominio"] == "bancolombia-verificacion.top"

    # Otra persona no puede ver ni liberar el caso
    luis = cliente_de(c, "luis@gmail.com")
    assert luis.get(f"/api/casos/{caso['id']}").status_code == 404
    assert luis.post(f"/api/casos/{caso['id']}/liberacion").status_code == 404

    # Ana lo libera: vuelve a la bandeja y queda la retroalimentación "legítimo"
    assert ana.post(f"/api/casos/{caso['id']}/liberacion").status_code == 204
    assert "INBOX" in gmail.mensajes[gid_phish]["etiquetas"] and cuarentena not in gmail.mensajes[gid_phish]["etiquetas"]
    assert ana.post(f"/api/casos/{caso['id']}/liberacion").status_code == 409            # ya no está en cuarentena
    ana.post(f"/api/casos/{caso['id']}/clasificacion", json={"decision": "reabrir"})
    ana.post(f"/api/casos/{caso['id']}/clasificacion", json={"decision": "confirmar", "comentario": "Sí era fraude"})
    with c.motor.connect() as conn:
        assert conn.scalar(text("SELECT etiqueta FROM centinela.retroalimentacion")) == "phishing"
        assert conn.scalar(text("SELECT count(*) FROM centinela.razon WHERE mostrada")) <= 3
        precision = conn.execute(text("SELECT verdaderos_positivos FROM centinela.v_precision_produccion")).scalar()
        assert precision == 1
        modelos = conn.execute(text("SELECT modelo_contenido_id IS NOT NULL, modelo_enlaces_id IS NOT NULL "
                                    "FROM centinela.veredicto WHERE nivel = 'alto'")).one()
        assert modelos == (True, True)                         # trazabilidad: qué versión de modelo decidió


def test_modo_solo_avisar_no_mueve_el_correo(entorno):
    c, auth, gmail = entorno
    ana = cliente_de(c, "ana@gmail.com")
    auth.autoriza("cod", gmail)
    estado = parse_qs(urlparse(ana.post("/api/buzones/conexion").json()["url"]).query)["state"][0]
    ana.get("/api/gmail/callback", params={"state": estado, "code": "cod"})
    buzon_id = ana.get("/api/buzones").json()[0]["id"]
    ana.patch(f"/api/buzones/{buzon_id}", json={"modo": "solo_avisar"})
    gid = gmail.llega(PHISHING)
    ana.post(f"/api/buzones/{buzon_id}/revision")
    etiquetas = gmail.mensajes[gid]["etiquetas"]
    assert "INBOX" in etiquetas and gmail.etiquetas["Centinela/Sospechoso"] in etiquetas
    assert ana.get("/api/casos").json()[0]["estado"] == "nuevo"


def test_analisis_manual_de_un_eml(entorno):
    c, _, _ = entorno
    ana = cliente_de(c, "ana@gmail.com")
    r = ana.post("/api/analisis", content=PHISHING, headers={"Content-Type": "message/rfc822"}).json()
    assert r["nivel"] == "alto" and len(r["razones"]) <= 3 and r["modelo_contenido_id"] and r["modelo_enlaces_id"]
    assert ana.post("/api/analisis", content=LEGITIMO, headers={"Content-Type": "message/rfc822"}).json()["nivel"] == "bajo"
    assert ana.post("/api/analisis", content=b"").status_code == 422
    with c.motor.connect() as conn:                            # no se guarda el correo, solo la auditoría
        assert conn.scalar(text("SELECT count(*) FROM centinela.mensaje_analizado")) == 0
        assert conn.scalar(text("SELECT count(*) FROM centinela.auditoria WHERE accion = 'analisis.manual'")) == 2
