"""Casos de uso de acceso con adaptadores en memoria (sin PostgreSQL)."""
import pyotp
import pytest

from centinela.adaptadores.salida.seguridad import ServicioTotpPyotp
from centinela.aplicacion.casos_uso import acceso as a
from centinela.dominio.errores import AccesoDenegado, CredencialesInvalidas, CuentaBloqueada
from centinela.dominio.usuario import EstadoCuenta
from tests.fakes import CifradorFalso, FabricaFalsa, HasherFalso, RelojFijo

CLAVE = "Clave-segura-2026"


@pytest.fixture
def s():
    """Sistema armado con fakes: mismos casos de uso que en producción, otros adaptadores."""
    class S:
        pass
    x = S()
    x.uow, x.reloj, x.hasher, x.cif, x.totp = FabricaFalsa(), RelojFijo(), HasherFalso(), CifradorFalso(), ServicioTotpPyotp()
    x.registro = a.SolicitarRegistro(x.uow, x.reloj, x.hasher)
    x.crear_admin = a.CrearAdministrador(x.uow, x.reloj, x.hasher)
    x.inicio = a.IniciarSesion(x.uow, x.reloj, x.hasher)
    x.verificar = a.VerificarSegundoFactor(x.uow, x.reloj, x.totp, x.cif)
    x.config_2fa = a.IniciarConfiguracion2FA(x.uow, x.reloj, x.totp, x.cif)
    x.confirmar_2fa = a.ConfirmarConfiguracion2FA(x.uow, x.reloj, x.totp, x.cif)
    x.renovar = a.RenovarSesion(x.uow, x.reloj)
    x.cerrar = a.CerrarSesion(x.uow, x.reloj)
    x.estado = a.CambiarEstadoCuenta(x.uow, x.reloj)
    x.cambiar_clave = a.CambiarClave(x.uow, x.reloj, x.hasher)
    return x


def _codigo(s, secreto):
    return pyotp.TOTP(secreto).at(s.reloj.ahora())


def _usuario_aprobado(s, correo="ana@gmail.com"):
    adm = s.crear_admin.ejecutar("admin@centinela.co", "Admin", CLAVE)
    s.registro.ejecutar(correo, "Ana Pérez", CLAVE, True)
    u = s.uow.almacen.usuarios[2]
    s.estado.ejecutar(adm.id, u.id, a.AccionCuenta.APROBAR)
    return adm, u


def test_registro_queda_pendiente_y_no_revela_duplicados(s):
    s.registro.ejecutar("Ana@Gmail.com", "Ana", CLAVE, True)
    s.registro.ejecutar("ana@gmail.com", "Otra", CLAVE, True)           # no lanza error
    assert len(s.uow.almacen.usuarios) == 1
    assert s.uow.almacen.usuarios[1].estado is EstadoCuenta.PENDIENTE
    assert [e.accion for e in s.uow.almacen.auditoria] == ["usuario.registro", "usuario.registro_duplicado"]


def test_pendiente_no_puede_ingresar(s):
    s.registro.ejecutar("ana@gmail.com", "Ana", CLAVE, True)
    with pytest.raises(AccesoDenegado, match="revisión"):
        s.inicio.ejecutar("ana@gmail.com", CLAVE)


def test_usuario_sin_2fa_ingresa_directo(s):
    _usuario_aprobado(s)
    r = s.inicio.ejecutar("ana@gmail.com", CLAVE)
    assert r.paso is a.Paso.COMPLETO and r.sesion.token_renovacion


def test_credenciales_malas_mensaje_generico(s):
    _usuario_aprobado(s)
    with pytest.raises(CredencialesInvalidas) as e1:
        s.inicio.ejecutar("ana@gmail.com", "otra-clave-2026")
    with pytest.raises(CredencialesInvalidas) as e2:
        s.inicio.ejecutar("nadie@gmail.com", CLAVE)
    assert e1.value.mensaje == e2.value.mensaje


def test_bloqueo_tras_cinco_intentos(s):
    _usuario_aprobado(s)
    for _ in range(4):
        with pytest.raises(CredencialesInvalidas):
            s.inicio.ejecutar("ana@gmail.com", "mala-clave-2026")
    with pytest.raises(CuentaBloqueada):
        s.inicio.ejecutar("ana@gmail.com", "mala-clave-2026")
    with pytest.raises(CuentaBloqueada):                              # ni con la clave correcta
        s.inicio.ejecutar("ana@gmail.com", CLAVE)
    s.reloj.avanzar(minutes=16)
    assert s.inicio.ejecutar("ana@gmail.com", CLAVE).paso is a.Paso.COMPLETO


def test_admin_debe_configurar_2fa_y_luego_verificarlo(s):
    adm = s.crear_admin.ejecutar("admin@centinela.co", "Admin", CLAVE)
    r = s.inicio.ejecutar("admin@centinela.co", CLAVE)
    assert r.paso is a.Paso.CONFIGURAR_2FA and r.sesion is None

    datos = s.config_2fa.ejecutar(adm.id)
    assert datos.uri.startswith("otpauth://totp/Centinela")
    act = s.confirmar_2fa.ejecutar(adm.id, _codigo(s, datos.secreto), iniciar_sesion=True)
    assert len(act.codigos_recuperacion) == 10 and act.sesion is not None

    s.reloj.avanzar(seconds=60)
    assert s.inicio.ejecutar("admin@centinela.co", CLAVE).paso is a.Paso.VERIFICAR_2FA
    sesion = s.verificar.ejecutar(adm.id, _codigo(s, datos.secreto))
    assert sesion.usuario.id == adm.id
    with pytest.raises(CredencialesInvalidas, match="ya fue usado"):   # el mismo código no sirve dos veces
        s.verificar.ejecutar(adm.id, _codigo(s, datos.secreto))

    codigo = act.codigos_recuperacion[0]
    assert s.verificar.ejecutar(adm.id, codigo.upper())              # código de recuperación: una sola vez
    with pytest.raises(CredencialesInvalidas):
        s.verificar.ejecutar(adm.id, codigo)


def test_renovacion_rota_el_token_y_detecta_reuso(s):
    _usuario_aprobado(s)
    t1 = s.inicio.ejecutar("ana@gmail.com", CLAVE).sesion.token_renovacion
    t2 = s.renovar.ejecutar(t1).token_renovacion
    assert t2 != t1
    s.reloj.avanzar(seconds=30)
    with pytest.raises(CredencialesInvalidas):
        s.renovar.ejecutar(t1)                                        # token viejo reutilizado
    with pytest.raises(CredencialesInvalidas):
        s.renovar.ejecutar(t2)                                        # por seguridad, se cerró todo
    assert "sesion.reuso_detectado" in [e.accion for e in s.uow.almacen.auditoria]


def test_cierre_de_sesion(s):
    _usuario_aprobado(s)
    t = s.inicio.ejecutar("ana@gmail.com", CLAVE).sesion.token_renovacion
    s.cerrar.ejecutar(t)
    with pytest.raises(CredencialesInvalidas):
        s.renovar.ejecutar(t)


def test_desactivar_cierra_sesiones_y_solo_admin(s):
    adm, u = _usuario_aprobado(s)
    t = s.inicio.ejecutar("ana@gmail.com", CLAVE).sesion.token_renovacion
    with pytest.raises(AccesoDenegado):
        s.estado.ejecutar(u.id, adm.id, a.AccionCuenta.DESACTIVAR)    # un usuario no administra
    s.estado.ejecutar(adm.id, u.id, a.AccionCuenta.DESACTIVAR)
    with pytest.raises(CredencialesInvalidas):                       # sus sesiones quedaron cerradas
        s.renovar.ejecutar(t)
    with pytest.raises(AccesoDenegado, match="desactivada"):
        s.inicio.ejecutar("ana@gmail.com", CLAVE)


def test_cambiar_clave_cierra_otras_sesiones(s):
    _, u = _usuario_aprobado(s)
    vieja = s.inicio.ejecutar("ana@gmail.com", CLAVE).sesion.token_renovacion
    nueva = s.cambiar_clave.ejecutar(u.id, CLAVE, "Otra-clave-2027").token_renovacion
    s.reloj.avanzar(seconds=1)
    assert s.renovar.ejecutar(nueva)
    with pytest.raises(CredencialesInvalidas):
        s.inicio.ejecutar("ana@gmail.com", CLAVE)
    s.reloj.avanzar(seconds=30)
    with pytest.raises(CredencialesInvalidas):
        s.renovar.ejecutar(vieja)
