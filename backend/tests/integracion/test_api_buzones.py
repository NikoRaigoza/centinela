"""Conexión de Gmail y revisión de buzones por HTTP, contra PostgreSQL real y un Gmail simulado."""
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from centinela.adaptadores.entrada.api.app import crear_app
from centinela.adaptadores.salida.postgres.repositorios import RepoBuzonesSql
from centinela.aplicacion.casos_uso.acceso import AccionCuenta
from centinela.contenedor import construir
from tests.gmail_falso import AutorizacionFalsa, BuzonGmailFalso, ProveedorGmailFalso, correo

pytestmark = pytest.mark.integracion
CLAVE = "Clave-segura-2026"


@pytest.fixture
def entorno(config, limpiar):
    proveedor = ProveedorGmailFalso()
    auth = AutorizacionFalsa(proveedor)
    c = construir(config, autorizacion=auth, proveedor=proveedor)
    admin = c.crear_administrador.ejecutar("admin@centinela.co", "Admin", CLAVE)
    for correo_u in ("ana@gmail.com", "luis@gmail.com"):
        c.solicitar_registro.ejecutar(correo_u, "Persona", CLAVE, True)
    for u in c.listar_usuarios.ejecutar(admin.id):
        if not u.es_admin:
            c.cambiar_estado_cuenta.ejecutar(admin.id, u.id, AccionCuenta.APROBAR)
    yield c, auth
    c.motor.dispose()


def cliente_de(c, correo_u):
    cli = TestClient(crear_app(c), base_url="http://testserver")
    token = cli.post("/api/auth/inicio", json={"correo": correo_u, "clave": CLAVE}).json()["acceso"]["token_acceso"]
    cli.headers["Authorization"] = f"Bearer {token}"
    return cli


def conectar(cli, auth, gmail, codigo="codigo-ana"):
    auth.autoriza(codigo, gmail)
    url = cli.post("/api/buzones/conexion").json()["url"]
    estado = parse_qs(urlparse(url).query)["state"][0]
    return cli.get("/api/gmail/callback", params={"state": estado, "code": codigo})


def test_conexion_revision_y_privacidad(entorno):
    c, auth = entorno
    ana = cliente_de(c, "ana@gmail.com")
    gmail = BuzonGmailFalso("ana@gmail.com")

    r = conectar(ana, auth, gmail)
    assert r.status_code == 200 and "ya está protegiendo ana@gmail.com" in r.text
    assert r.headers["content-security-policy"].startswith("default-src 'none'")
    buzon = ana.get("/api/buzones").json()[0]
    assert buzon["estado"] == "activo" and buzon["modo"] == "cuarentena_automatica"

    # El token de Gmail quedó cifrado en la BD (no es legible)
    with c.motor.connect() as conn:
        guardado = conn.scalar(text("SELECT refresh_token_cifrado FROM centinela.buzon"))
    assert b"rt-codigo-ana" not in bytes(guardado)

    # Llegan correos y se revisa el buzón
    gmail.llega(correo(message_id="<1@x>", adjuntos=[("factura.zip", b"PK..", "application/zip")]))
    gmail.llega(correo(message_id="<2@x>", remitente="DIAN <notificaciones@dian.gov.co>",
                       autenticacion="mx.google.com; dkim=pass; spf=pass; dmarc=pass"))
    r = ana.post(f"/api/buzones/{buzon['id']}/revision").json()
    assert r["nuevos"] == 2
    assert ana.post(f"/api/buzones/{buzon['id']}/revision").json()["nuevos"] == 0      # idempotente

    mensajes = ana.get(f"/api/buzones/{buzon['id']}/mensajes").json()
    dian = next(m for m in mensajes if m["remitente_correo"] == "notificaciones@dian.gov.co")
    assert (dian["spf"], dian["dkim"], dian["dmarc"]) == ("pass", "pass", "pass")
    with c.motor.connect() as conn:
        assert conn.scalar(text("SELECT extension FROM centinela.adjunto_analizado")) == "zip"

    # Otra persona no puede ver ni tocar el buzón de Ana; el admin ve el estado pero no los correos
    luis = cliente_de(c, "luis@gmail.com")
    assert luis.get(f"/api/buzones/{buzon['id']}/mensajes").status_code == 403
    assert luis.patch(f"/api/buzones/{buzon['id']}", json={"pausado": True}).status_code == 403
    admin = cliente_de_admin(c)
    assert [b["correo_gmail"] for b in admin.get("/api/admin/buzones").json()] == ["ana@gmail.com"]

    # Ajustes y desconexión
    r = ana.patch(f"/api/buzones/{buzon['id']}", json={"modo": "solo_avisar", "pausado": True}).json()
    assert (r["modo"], r["estado"]) == ("solo_avisar", "pausado")
    assert ana.delete(f"/api/buzones/{buzon['id']}").json()["estado"] == "revocado"
    assert auth.revocados == ["rt-codigo-ana"]


def cliente_de_admin(c):
    import pyotp
    cli = TestClient(crear_app(c), base_url="http://testserver")
    desafio = cli.post("/api/auth/inicio", json={"correo": "admin@centinela.co", "clave": CLAVE}).json()["token_desafio"]
    cab = {"Authorization": f"Bearer {desafio}"}
    secreto = cli.post("/api/auth/2fa/configuracion", headers=cab).json()["secreto"]
    acceso = cli.post("/api/auth/2fa/confirmacion", headers=cab, json={"codigo": pyotp.TOTP(secreto).now()}).json()
    cli.headers["Authorization"] = f"Bearer {acceso['acceso']['token_acceso']}"
    return cli


def test_callback_rechaza_otro_navegador_y_estado_alterado(entorno):
    c, auth = entorno
    ana = cliente_de(c, "ana@gmail.com")
    auth.autoriza("cod", BuzonGmailFalso("ana@gmail.com"))
    url = ana.post("/api/buzones/conexion").json()["url"]
    estado = parse_qs(urlparse(url).query)["state"][0]

    otro_navegador = TestClient(crear_app(c), base_url="http://testserver")           # sin la cookie
    r = otro_navegador.get("/api/gmail/callback", params={"state": estado, "code": "cod"})
    assert r.status_code == 400 and "mismo navegador" in r.text

    r = ana.get("/api/gmail/callback", params={"state": estado[:-4] + "AAAA", "code": "cod"})
    assert r.status_code == 400
    r = ana.get("/api/gmail/callback", params={"error": "access_denied"})
    assert r.status_code == 400 and "Cancelaste" in r.text
    assert ana.get("/api/buzones").json() == []


def test_reclamar_pendientes_con_dos_workers_a_la_vez(entorno, motor_owner):
    c, auth = entorno
    ana = cliente_de(c, "ana@gmail.com")
    conectar(ana, auth, BuzonGmailFalso("ana@gmail.com"))
    ahora = datetime.now(UTC) + timedelta(minutes=5)
    with Session(motor_owner) as s1, Session(motor_owner) as s2:
        primero = RepoBuzonesSql(s1).reclamar_pendientes(ahora, ahora, 10)       # transacción abierta
        segundo = RepoBuzonesSql(s2).reclamar_pendientes(ahora, ahora, 10)      # no espera: salta el bloqueado
        s1.commit()
        s2.commit()
    assert len(primero) == 1 and segundo == []


def test_reclamar_pendientes_reintenta_buzones_en_error(entorno, motor_owner):
    c, auth = entorno
    ana = cliente_de(c, "ana@gmail.com")
    conectar(ana, auth, BuzonGmailFalso("ana@gmail.com"))
    ahora = datetime.now(UTC) + timedelta(minutes=5)
    with Session(motor_owner) as s:
        s.execute(text("UPDATE centinela.buzon SET estado = 'error', ultima_revision_en = :t"), {"t": ahora})
        s.commit()
        repo = RepoBuzonesSql(s)
        assert repo.reclamar_pendientes(ahora, ahora, 10, None, ahora - timedelta(seconds=60)) == []    # muy pronto
        despues = ahora + timedelta(seconds=61)
        assert len(repo.reclamar_pendientes(despues, despues, 10, None, despues - timedelta(seconds=60))) == 1
        s.execute(text("UPDATE centinela.buzon SET refresh_token_cifrado = NULL, ultima_revision_en = NULL"))
        assert repo.reclamar_pendientes(despues, despues, 10) == []                # sin permiso no se reintenta
        s.rollback()
