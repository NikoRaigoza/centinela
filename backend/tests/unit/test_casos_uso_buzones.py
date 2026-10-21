"""Casos de uso de buzones con BD y Gmail en memoria."""
import pytest

from centinela.adaptadores.salida.lector_correo import LectorCorreoMime, firmar_aviso
from centinela.aplicacion.casos_uso import acceso as a
from centinela.aplicacion.casos_uso import buzones as bz
from centinela.dominio.buzon import EstadoBuzon, ModoCuarentena
from centinela.dominio.errores import AccesoDenegado, Conflicto, DatoInvalido
from tests.fakes import CifradorFalso, FabricaFalsa, HasherFalso, RelojFijo
from tests.gmail_falso import AutorizacionFalsa, BuzonGmailFalso, ProveedorGmailFalso, correo

CLAVE = "Clave-segura-2026"
CLAVE_AVISOS = b"avisos"


@pytest.fixture
def s():
    class S:
        pass
    x = S()
    x.uow, x.reloj, x.cif = FabricaFalsa(), RelojFijo(), CifradorFalso()
    x.proveedor = ProveedorGmailFalso()
    x.auth = AutorizacionFalsa(x.proveedor)
    x.gmail = BuzonGmailFalso()
    h = HasherFalso()
    adm = a.CrearAdministrador(x.uow, x.reloj, h).ejecutar("admin@centinela.co", "Admin", CLAVE)
    for correo_u in ("ana@gmail.com", "luis@gmail.com"):
        a.SolicitarRegistro(x.uow, x.reloj, h).ejecutar(correo_u, "Persona", CLAVE, True)
    for uid in (2, 3):
        a.CambiarEstadoCuenta(x.uow, x.reloj).ejecutar(adm.id, uid, a.AccionCuenta.APROBAR)
    x.iniciar = bz.IniciarConexionGmail(x.uow, x.reloj, x.auth)
    x.completar = bz.CompletarConexionGmail(x.uow, x.reloj, x.auth, x.proveedor, x.cif)
    x.revisar = bz.RevisarBuzon(x.uow, x.reloj, x.proveedor, LectorCorreoMime(CLAVE_AVISOS), x.cif)
    x.pendientes = bz.RevisarBuzonesPendientes(x.uow, x.reloj, x.revisar)
    x.desconectar = bz.DesconectarBuzon(x.uow, x.reloj, x.auth, x.cif)
    x.actualizar = bz.ActualizarBuzon(x.uow, x.reloj)
    return x


def conectar(s, usuario_id=2, codigo="c1", gmail=None):
    s.auth.autoriza(codigo, gmail or s.gmail)
    verificador = bz.nuevo_verificador_pkce()
    s.iniciar.ejecutar(usuario_id, "estado", verificador)
    return s.completar.ejecutar(usuario_id, codigo, verificador)


def test_conectar_guarda_token_cifrado_y_empieza_desde_ahora(s):
    s.gmail.llega(correo())                                  # llegó ANTES de conectar: no se analiza
    b = conectar(s)
    assert b.estado is EstadoBuzon.ACTIVO and b.ultimo_history_id == s.gmail.history_id
    assert b.refresh_token_cifrado != b"rt-c1" and s.cif.descifrar(b.refresh_token_cifrado) == "rt-c1"
    assert s.revisar.ejecutar(b.id).nuevos == 0


def test_permiso_no_concedido(s):
    with pytest.raises(DatoInvalido, match="permiso"):
        s.completar.ejecutar(2, "sin-permiso", "v")


def test_un_gmail_no_puede_quedar_en_dos_cuentas(s):
    conectar(s, usuario_id=2, codigo="c1")
    with pytest.raises(Conflicto):
        conectar(s, usuario_id=3, codigo="c2")
    assert "rt-c2" in s.auth.revocados


def test_revision_ingiere_solo_lo_nuevo_y_es_idempotente(s):
    b = conectar(s)
    s.gmail.llega(correo(message_id="<1@x>"))
    s.gmail.llega(correo(message_id="<2@x>"), etiquetas=("INBOX", "SENT"))     # enviado por la persona
    mid = "<aviso@centinela>"
    s.gmail.llega(correo(message_id=mid, extra={"X-Centinela-Alerta": firmar_aviso(CLAVE_AVISOS, mid)}))
    r = s.revisar.ejecutar(b.id)
    assert (r.nuevos, r.omitidos) == (1, 2)
    assert s.revisar.ejecutar(b.id).nuevos == 0                                 # nada nuevo, nada duplicado
    guardado = next(iter(s.uow.almacen.mensajes.values()))
    assert guardado.correo.remitente_dominio == "bancolombia-seguro.xyz"


def test_historial_expirado_recupera_los_ultimos(s):
    b = conectar(s)
    s.gmail.llega(correo(message_id="<1@x>"))
    s.gmail.historial_expirado = True
    assert s.revisar.ejecutar(b.id).nuevos == 1


def test_errores_pasajeros_llevan_a_estado_error(s):
    b = conectar(s)
    s.gmail.falla = "HTTP 503"
    for _ in range(5):
        r = s.revisar.ejecutar(b.id)
    assert r.estado == "error" and "503" in r.error
    s.gmail.falla = None
    s.actualizar.ejecutar(2, b.id, pausado=False)                               # el dueño lo reanuda
    assert s.revisar.ejecutar(b.id).estado == "activo"


def test_si_google_retira_el_permiso_el_buzon_queda_revocado(s):
    b = conectar(s)
    s.gmail.revocado = True
    r = s.revisar.ejecutar(b.id)
    assert r.estado == "revocado" and "Vuelve a conectar" in r.error
    assert s.uow.almacen.buzones[b.id].refresh_token_cifrado is None


def test_solo_el_dueno_administra_su_buzon(s):
    b = conectar(s)
    with pytest.raises(AccesoDenegado):
        s.actualizar.ejecutar(3, b.id, modo=ModoCuarentena.SOLO_AVISAR)
    with pytest.raises(AccesoDenegado):
        s.revisar.ejecutar(b.id, solicitado_por=3)
    assert s.actualizar.ejecutar(2, b.id, modo=ModoCuarentena.SOLO_AVISAR).modo is ModoCuarentena.SOLO_AVISAR


def test_desconectar_revoca_en_google(s):
    b = conectar(s)
    s.desconectar.ejecutar(2, b.id)
    assert s.auth.revocados == ["rt-c1"]
    assert s.uow.almacen.buzones[b.id].estado is EstadoBuzon.REVOCADO
    assert s.revisar.ejecutar(b.id).nuevos == 0


def test_worker_respeta_el_intervalo(s):
    b = conectar(s)
    s.gmail.llega(correo())
    assert [r.nuevos for r in s.pendientes.ejecutar()] == [1]
    s.gmail.llega(correo(message_id="<n@x>"))
    assert s.pendientes.ejecutar() == []                     # aún no pasan 30 s
    s.reloj.avanzar(seconds=31)
    assert [r.buzon_id for r in s.pendientes.ejecutar()] == [b.id]
