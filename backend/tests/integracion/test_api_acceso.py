"""Flujo completo por HTTP contra PostgreSQL real: instalación, 2FA, registro, aprobación, sesiones."""
import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from centinela.adaptadores.entrada.api.app import crear_app
from centinela.adaptadores.entrada.api.rutas_acceso import COOKIE
from centinela.contenedor import construir

pytestmark = pytest.mark.integracion
CLAVE = "Clave-segura-2026"


@pytest.fixture
def entorno(config, limpiar):
    contenedor = construir(config)
    cliente = TestClient(crear_app(contenedor), base_url="http://testserver")
    yield contenedor, cliente
    contenedor.motor.dispose()


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _admin_con_2fa(c, cliente):
    """Crea el admin por consola y completa el primer ingreso con configuración de 2FA."""
    c.crear_administrador.ejecutar("admin@centinela.co", "Administración", CLAVE)
    r = cliente.post("/api/auth/inicio", json={"correo": "admin@centinela.co", "clave": CLAVE}).json()
    assert r["paso"] == "configurar_2fa" and r["acceso"] is None
    desafio = r["token_desafio"]
    conf = cliente.post("/api/auth/2fa/configuracion", headers=_bearer(desafio)).json()
    totp = pyotp.TOTP(conf["secreto"])
    act = cliente.post("/api/auth/2fa/confirmacion", headers=_bearer(desafio), json={"codigo": totp.now()})
    assert act.status_code == 200, act.text
    cuerpo = act.json()
    assert len(cuerpo["codigos_recuperacion"]) == 10
    return cuerpo["acceso"]["token_acceso"], totp


def test_salud_y_cabeceras_de_seguridad(entorno):
    _, cliente = entorno
    r = cliente.get("/api/salud")
    assert r.json() == {"estado": "ok", "base_de_datos": "ok"}
    assert r.headers["x-frame-options"] == "DENY" and r.headers["cache-control"] == "no-store"


def test_flujo_completo(entorno):
    c, cliente = entorno
    token_admin, _ = _admin_con_2fa(c, cliente)

    # 1. Un usuario se registra y queda pendiente
    r = cliente.post("/api/auth/registro", json={"correo": "ana@gmail.com", "nombre": "Ana Pérez", "clave": CLAVE})
    assert r.status_code == 202
    r = cliente.post("/api/auth/inicio", json={"correo": "ana@gmail.com", "clave": CLAVE})
    assert r.status_code == 403 and "revisión" in r.json()["mensaje"]

    # 2. El administrador lo aprueba (un usuario normal no puede ver esta ruta)
    pendientes = cliente.get("/api/admin/usuarios?estado=pendiente", headers=_bearer(token_admin)).json()
    assert [u["correo"] for u in pendientes] == ["ana@gmail.com"]
    r = cliente.post(f"/api/admin/usuarios/{pendientes[0]['id']}/aprobar", headers=_bearer(token_admin))
    assert r.json()["estado"] == "activo"

    # 3. El usuario ingresa: token de acceso en el cuerpo, renovación en cookie httpOnly
    r = cliente.post("/api/auth/inicio", json={"correo": "ana@gmail.com", "clave": CLAVE})
    cuerpo = r.json()
    assert cuerpo["paso"] == "completo"
    assert "httponly" in r.headers["set-cookie"].lower() and "samesite=strict" in r.headers["set-cookie"].lower()
    token = cuerpo["acceso"]["token_acceso"]
    assert cliente.get("/api/usuarios/yo", headers=_bearer(token)).json()["correo"] == "ana@gmail.com"
    assert cliente.get("/api/admin/usuarios", headers=_bearer(token)).status_code == 403

    # 4. Renovación con la cookie (rotación) y cierre de sesión
    vieja = cliente.cookies.get(COOKIE)
    r = cliente.post("/api/auth/renovacion")
    assert r.status_code == 200 and cliente.cookies.get(COOKIE) != vieja
    assert cliente.post("/api/auth/cierre").status_code == 204
    assert cliente.post("/api/auth/renovacion").status_code == 401

    # 5. Todo quedó auditado en la base de datos
    with c.motor.connect() as conn:
        acciones = set(conn.scalars(text("SELECT accion FROM centinela.auditoria")))
    assert {"usuario.crear_admin", "2fa.activar", "usuario.registro", "usuario.aprobar", "sesion.inicio",
            "sesion.cierre"} <= acciones


def test_admin_ingresa_con_segundo_factor(entorno):
    c, cliente = entorno
    _, totp = _admin_con_2fa(c, cliente)
    r = cliente.post("/api/auth/inicio", json={"correo": "admin@centinela.co", "clave": CLAVE}).json()
    assert r["paso"] == "verificar_2fa"
    malo = cliente.post("/api/auth/2fa/verificacion", headers=_bearer(r["token_desafio"]), json={"codigo": "000000"})
    assert malo.status_code == 401
    # un token de desafío no sirve como token de acceso
    assert cliente.get("/api/usuarios/yo", headers=_bearer(r["token_desafio"])).status_code == 401
    siguiente = totp.at(c.reloj.ahora(), counter_offset=1)    # el código del paso actual ya se usó al activar
    ok = cliente.post("/api/auth/2fa/verificacion", headers=_bearer(r["token_desafio"]), json={"codigo": siguiente})
    assert ok.status_code == 200, ok.text


def test_bloqueo_por_intentos(entorno):
    c, cliente = entorno
    cliente.post("/api/auth/registro", json={"correo": "luis@gmail.com", "nombre": "Luis", "clave": CLAVE})
    estados = [cliente.post("/api/auth/inicio", json={"correo": "luis@gmail.com", "clave": "Mala-clave-2026"}).status_code
               for _ in range(5)]
    assert estados == [401, 401, 401, 401, 423]
    r = cliente.post("/api/auth/inicio", json={"correo": "luis@gmail.com", "clave": CLAVE})
    assert r.status_code == 423 and "minuto" in r.json()["mensaje"]


def test_errores_en_espanol(entorno):
    _, cliente = entorno
    r = cliente.post("/api/auth/registro", json={"correo": "x@y.co", "nombre": "Xy", "clave": "corta"})
    assert r.status_code == 422 and r.json()["mensaje"].startswith("La contraseña")
    r = cliente.post("/api/auth/inicio", json={"correo": "x@y.co"})
    assert r.status_code == 422 and "clave" in r.json()["mensaje"]
