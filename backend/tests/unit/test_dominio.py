"""Pruebas del dominio: reglas puras, sin base de datos ni red."""
from datetime import UTC, datetime, timedelta

import pytest

from centinela.dominio.caso import Caso, EstadoCaso, TipoEvento
from centinela.dominio.errores import (
    AccesoDenegado,
    Conflicto,
    CredencialesInvalidas,
    DatoInvalido,
    TransicionInvalida,
)
from centinela.dominio.riesgo import Area, Gravedad, NivelRiesgo, Razon, Veredicto, seleccionar_razones
from centinela.dominio.usuario import EstadoCuenta, Rol, Usuario, normalizar_correo, validar_clave

T0 = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)


def admin(id_=1):
    return Usuario(id=id_, correo="admin@centinela.co", nombre="Admin", clave_hash="x",
                   rol=Rol.ADMINISTRADOR, estado=EstadoCuenta.ACTIVO)


# ----------------------------------------------------------------- usuario
@pytest.mark.parametrize("clave", ["corta1", "sololetrasaqui", "1234567890123", "x" * 120 + "1" * 10])
def test_clave_debil_rechazada(clave):
    with pytest.raises(DatoInvalido):
        validar_clave(clave)


def test_clave_no_puede_contener_el_correo():
    with pytest.raises(DatoInvalido):
        validar_clave("mariana2026segura", "mariana@gmail.com")
    validar_clave("Cafe-con-pan-2026", "mariana@gmail.com")


def test_correo_se_normaliza_y_valida():
    assert normalizar_correo("  Ana.Perez@Gmail.COM ") == "ana.perez@gmail.com"
    with pytest.raises(DatoInvalido):
        normalizar_correo("no-es-correo")


def test_bloqueo_tras_intentos_fallidos():
    u = Usuario.solicitar("ana@gmail.com", "Ana", "x", True, datetime(2026, 10, 20, tzinfo=UTC))
    assert not any(u.registrar_fallo(T0, 3, 15) for _ in range(2))
    assert u.registrar_fallo(T0, 3, 15) is True
    assert u.esta_bloqueado(T0 + timedelta(minutes=14))
    assert not u.esta_bloqueado(T0 + timedelta(minutes=15, seconds=1))
    u.registrar_acceso(T0)
    assert u.intentos_fallidos == 0 and u.bloqueado_hasta is None


def test_ciclo_de_vida_de_la_cuenta():
    u = Usuario.solicitar("ana@gmail.com", "Ana", "x", True, datetime(2026, 10, 20, tzinfo=UTC))
    u.id = 2
    with pytest.raises(AccesoDenegado):
        u.verificar_puede_ingresar()
    u.aprobar(admin(), T0)
    assert u.estado is EstadoCuenta.ACTIVO and u.aprobado_por == 1
    u.verificar_puede_ingresar()
    with pytest.raises(TransicionInvalida):
        u.aprobar(admin(), T0)
    u.desactivar(admin())
    u.reactivar(admin())
    assert u.estado is EstadoCuenta.ACTIVO


def test_solo_un_admin_cambia_cuentas_y_no_la_propia():
    u = Usuario.solicitar("ana@gmail.com", "Ana", "x", True, datetime(2026, 10, 20, tzinfo=UTC))
    u.id = 2
    otro = Usuario(id=3, correo="b@b.co", nombre="Bb", clave_hash="x", estado=EstadoCuenta.ACTIVO)
    with pytest.raises(AccesoDenegado):
        u.aprobar(otro, T0)
    a = admin()
    with pytest.raises(AccesoDenegado):
        a.desactivar(a)


def test_admin_obligado_a_2fa_y_codigo_no_reutilizable():
    a = admin()
    assert a.debe_configurar_2fa
    with pytest.raises(Conflicto):
        a.activar_2fa(100)
    a.preparar_2fa(b"secreto")
    a.activar_2fa(100)
    assert not a.debe_configurar_2fa
    with pytest.raises(CredencialesInvalidas):
        a.consumir_paso_totp(100)
    a.consumir_paso_totp(101)
    with pytest.raises(Conflicto):
        a.preparar_2fa(b"otro")


# ----------------------------------------------------------------- riesgo
def test_nivel_desde_probabilidad():
    assert NivelRiesgo.desde_probabilidad(0.29, 0.3, 0.7) is NivelRiesgo.BAJO
    assert NivelRiesgo.desde_probabilidad(0.30, 0.3, 0.7) is NivelRiesgo.MEDIO
    assert NivelRiesgo.desde_probabilidad(0.70, 0.3, 0.7) is NivelRiesgo.ALTO
    with pytest.raises(DatoInvalido):
        NivelRiesgo.desde_probabilidad(0.5, 0.8, 0.7)


def test_maximo_tres_razones_una_por_area_ordenadas():
    rs = [
        Razon(Area.ENLACE, Gravedad.BAJA, "enlace largo", 0.05),
        Razon(Area.SUPLANTACION, Gravedad.ALTA, "dice ser Bancolombia", 0.40),
        Razon(Area.CONTENIDO, Gravedad.ALTA, "urgencia", 0.30),
        Razon(Area.CONTENIDO, Gravedad.MEDIA, "pide datos", 0.20),
        Razon(Area.AUTENTICACION, Gravedad.MEDIA, "DMARC falló", 0.10),
    ]
    elegidas = seleccionar_razones(rs)
    assert [r.texto for r in elegidas] == ["dice ser Bancolombia", "urgencia", "DMARC falló"]


def test_veredicto_valida_probabilidades_y_exige_razones():
    with pytest.raises(DatoInvalido):
        Veredicto(p_final=1.2, nivel=NivelRiesgo.ALTO, resumen="x", razones=[Razon(Area.ENLACE, Gravedad.ALTA, "x")])
    with pytest.raises(DatoInvalido):
        Veredicto(p_final=0.9, nivel=NivelRiesgo.ALTO, resumen="x")
    v = Veredicto(p_final=0.1, nivel=NivelRiesgo.BAJO, resumen="Sin señales de riesgo",
                  razones=[Razon(Area.CONTENIDO, Gravedad.MEDIA, "texto algo sospechoso")])
    assert not v.amerita_caso and v.razones_visibles == []           # se guarda, pero no se muestra


# ----------------------------------------------------------------- caso
def test_flujo_de_caso_cuarentena_y_liberacion():
    c = Caso.abrir(mensaje_id=7, ahora=T0)
    c.transicionar(EstadoCaso.EN_CUARENTENA, T0)
    assert c.puede_liberarse and c.abierto
    c.transicionar(EstadoCaso.LIBERADO, T0, autor_id=2)
    assert not c.abierto and c.cerrado_en == T0
    c.transicionar(EstadoCaso.NUEVO, T0, autor_id=2)          # reabrir
    assert c.abierto and c.cerrado_en is None
    assert [e.tipo for e in c.eventos_nuevos] == [TipoEvento.CREADO, TipoEvento.CUARENTENA, TipoEvento.LIBERADO,
                                                 TipoEvento.REABIERTO]


@pytest.mark.parametrize("desde,hacia", [
    (EstadoCaso.NUEVO, EstadoCaso.LIBERADO),               # solo se libera lo que está en cuarentena
    (EstadoCaso.CONFIRMADO, EstadoCaso.LIBERADO),
    (EstadoCaso.EN_CUARENTENA, EstadoCaso.FALSO_POSITIVO),
])
def test_transiciones_invalidas(desde, hacia):
    c = Caso(mensaje_id=1, creado_en=T0, estado=desde)
    with pytest.raises(TransicionInvalida):
        c.transicionar(hacia, T0)


def test_nota_no_vacia():
    c = Caso.abrir(1, T0)
    with pytest.raises(DatoInvalido):
        c.agregar_nota("   ", 2, T0)
