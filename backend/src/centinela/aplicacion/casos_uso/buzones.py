"""Casos de uso de buzones: conectar Gmail (OAuth2 + PKCE), administrarlo y revisarlo en busca de correos nuevos.

La revisión es idempotente: si algo falla a mitad de camino, el punto de avance (historyId) no se mueve y la
siguiente revisión vuelve a intentar los mismos correos; la restricción UNIQUE (buzon_id, gmail_id) evita duplicados.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from dataclasses import dataclass
from datetime import timedelta

from centinela.aplicacion.casos_uso.analisis import MotorAnalisis
from centinela.aplicacion.casos_uso.comun import SIN_CONTEXTO, CasoDeUso, Contexto, admin_activo, usuario_activo
from centinela.aplicacion.puertos import (
    AccesoCorreoRevocado,
    AutorizacionCorreo,
    Cifrador,
    ErrorProveedorCorreo,
    EventoAuditoria,
    FabricaUnidadDeTrabajo,
    HistorialExpirado,
    LectorCorreo,
    MensajeNoDisponible,
    PermisoInsuficiente,
    ProveedorCorreo,
    Reloj,
    ResultadoAnalisis,
    UnidadDeTrabajo,
)
from centinela.dominio.buzon import Buzon, EstadoBuzon, ModoCuarentena
from centinela.dominio.caso import Caso, EstadoCaso
from centinela.dominio.correo import Mensaje, ResumenMensaje
from centinela.dominio.errores import Conflicto, DatoInvalido, NoEncontrado, ServicioNoDisponible
from centinela.dominio.fraude import ContextoDestinatario
from centinela.dominio.politica import Acciones, decidir_acciones
from centinela.dominio.riesgo import NivelRiesgo

log = logging.getLogger(__name__)

MAX_RECUPERAR_TRAS_HUECO = 50     # si el historial expiró, se revisan los últimos N correos de la bandeja
MAX_MENSAJES_POR_REVISION = 100
HISTORIA_MINIMA = timedelta(days=14)
MSG_NO_CONFIGURADO = "La conexión con Gmail no está configurada en este servidor."


def nuevo_verificador_pkce() -> str:
    return secrets.token_urlsafe(64)


def reto_pkce(verificador: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verificador.encode()).digest()).rstrip(b"=").decode()


@dataclass(frozen=True)
class ResumenRevision:
    buzon_id: int
    nuevos: int = 0
    omitidos: int = 0
    estado: str = EstadoBuzon.ACTIVO.value
    error: str | None = None


def _auditar_buzon(uow: UnidadDeTrabajo, accion: str, buzon: Buzon, usuario_id: int | None,
                   ctx: Contexto = SIN_CONTEXTO, exito: bool = True, **detalle) -> None:
    uow.auditoria.registrar(EventoAuditoria(accion=accion, usuario_id=usuario_id, objeto_tipo="buzon",
                                            objeto_id=str(buzon.id), exito=exito, ip=ctx.ip,
                                            detalle={"correo": buzon.correo_gmail, **detalle}))


def _buzon_propio(uow: UnidadDeTrabajo, usuario_id: int, buzon_id: int) -> Buzon:
    usuario_activo(uow, usuario_id)
    buzon = uow.buzones.por_id(buzon_id)
    if buzon is None:
        raise NoEncontrado("El buzón no existe.")
    buzon.verificar_dueno(usuario_id)
    return buzon


# ---------------------------------------------------------------------- conexión
class IniciarConexionGmail(CasoDeUso):
    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, autorizacion: AutorizacionCorreo | None):
        super().__init__(uow, reloj)
        self._autorizacion = autorizacion

    def ejecutar(self, usuario_id: int, estado: str, verificador: str) -> str:
        """Devuelve la URL de Google a la que se envía al usuario para que dé el permiso."""
        if self._autorizacion is None:
            raise ServicioNoDisponible(MSG_NO_CONFIGURADO)
        with self._uow() as uow:
            usuario_activo(uow, usuario_id)
        return self._autorizacion.url_autorizacion(estado, reto_pkce(verificador))


class CompletarConexionGmail(CasoDeUso):
    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, autorizacion: AutorizacionCorreo | None,
                 proveedor: ProveedorCorreo | None, cifrador: Cifrador):
        super().__init__(uow, reloj)
        self._autorizacion = autorizacion
        self._proveedor = proveedor
        self._cifrador = cifrador

    def ejecutar(self, usuario_id: int, codigo: str, verificador: str, ctx: Contexto = SIN_CONTEXTO) -> Buzon:
        if self._autorizacion is None or self._proveedor is None:
            raise ServicioNoDisponible(MSG_NO_CONFIGURADO)
        with self._uow() as uow:
            usuario_activo(uow, usuario_id)
        try:
            cred = self._autorizacion.intercambiar_codigo(codigo, verificador)
        except PermisoInsuficiente:
            raise DatoInvalido("Para proteger tu correo, Centinela necesita el permiso para leer y organizar tus "
                               "mensajes. Vuelve a intentarlo y marca la casilla del permiso.") from None
        except ErrorProveedorCorreo:
            raise ServicioNoDisponible("Google no respondió. Intenta conectar el buzón de nuevo.") from None
        try:
            cliente = self._proveedor.abrir(cred.refresh_token)
            perfil = cliente.perfil()
            etiquetas = cliente.asegurar_etiquetas()
        except (ErrorProveedorCorreo, AccesoCorreoRevocado):
            raise ServicioNoDisponible("No pudimos leer tu buzón de Gmail. Intenta de nuevo en unos minutos.") from None

        ahora = self._reloj.ahora()
        cifrado = self._cifrador.cifrar(cred.refresh_token)
        with self._uow() as uow:
            existente = uow.buzones.por_correo(perfil.correo.lower())
            if existente is not None and existente.usuario_id != usuario_id:
                self._revocar_sin_error(cred.refresh_token)
                raise Conflicto("Este correo de Gmail ya está protegido desde otra cuenta de Centinela.")
            if existente is not None:
                existente.reconectar(cifrado, cred.alcances, perfil.history_id, etiquetas, ahora)
                uow.buzones.guardar(existente)
                buzon = existente
            else:
                buzon = uow.buzones.agregar(Buzon.conectar(usuario_id, perfil.correo, cifrado, cred.alcances,
                                                           perfil.history_id, etiquetas, ahora))
            _auditar_buzon(uow, "buzon.conectar", buzon, usuario_id, ctx)
            uow.confirmar()
        return buzon

    def _revocar_sin_error(self, token: str) -> None:
        try:
            self._autorizacion.revocar(token)
        except Exception:  # noqa: BLE001 - revocar es cortesía: el error no debe tapar el conflicto
            log.warning("No se pudo revocar un token sobrante en Google")


class DesconectarBuzon(CasoDeUso):
    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, autorizacion: AutorizacionCorreo | None,
                 cifrador: Cifrador):
        super().__init__(uow, reloj)
        self._autorizacion = autorizacion
        self._cifrador = cifrador

    def ejecutar(self, usuario_id: int, buzon_id: int, ctx: Contexto = SIN_CONTEXTO) -> Buzon:
        with self._uow() as uow:
            buzon = _buzon_propio(uow, usuario_id, buzon_id)
            token = self._cifrador.descifrar(buzon.refresh_token_cifrado) if buzon.refresh_token_cifrado else None
            buzon.desconectar(self._reloj.ahora())
            uow.buzones.guardar(buzon)
            _auditar_buzon(uow, "buzon.desconectar", buzon, usuario_id, ctx)
            uow.confirmar()
        if token and self._autorizacion is not None:
            try:
                self._autorizacion.revocar(token)        # el permiso también desaparece en la cuenta de Google
            except Exception:  # noqa: BLE001
                log.warning("No se pudo revocar el permiso en Google del buzón %s", buzon_id)
        return buzon


# ---------------------------------------------------------------------- consulta y ajustes
class ListarBuzones(CasoDeUso):
    def ejecutar(self, usuario_id: int) -> list[Buzon]:
        with self._uow() as uow:
            usuario_activo(uow, usuario_id)
            return uow.buzones.de_usuario(usuario_id)


class ListarTodosLosBuzones(CasoDeUso):
    """Para el administrador: estado de las conexiones, sin acceso a los correos."""

    def ejecutar(self, admin_id: int) -> list[Buzon]:
        with self._uow() as uow:
            admin_activo(uow, admin_id)
            return uow.buzones.todos()


class ActualizarBuzon(CasoDeUso):
    def ejecutar(self, usuario_id: int, buzon_id: int, modo: ModoCuarentena | None = None,
                 avisar_por_correo: bool | None = None, pausado: bool | None = None,
                 ctx: Contexto = SIN_CONTEXTO) -> Buzon:
        with self._uow() as uow:
            buzon = _buzon_propio(uow, usuario_id, buzon_id)
            if modo is not None:
                buzon.modo = modo
            if avisar_por_correo is not None:
                buzon.avisar_por_correo = avisar_por_correo
            if pausado is True and buzon.estado is not EstadoBuzon.PAUSADO:
                buzon.pausar()
            elif pausado is False and buzon.estado is not EstadoBuzon.ACTIVO:
                buzon.reanudar()
            uow.buzones.guardar(buzon)
            _auditar_buzon(uow, "buzon.actualizar", buzon, usuario_id, ctx, modo=buzon.modo.value,
                           avisar=buzon.avisar_por_correo, estado=buzon.estado.value)
            uow.confirmar()
            return buzon


class ListarMensajes(CasoDeUso):
    def ejecutar(self, usuario_id: int, buzon_id: int, limite: int = 50) -> list[ResumenMensaje]:
        with self._uow() as uow:
            _buzon_propio(uow, usuario_id, buzon_id)
            return uow.mensajes.recientes(buzon_id, max(1, min(limite, 200)))


# ---------------------------------------------------------------------- revisión (worker)
class RevisarBuzon(CasoDeUso):
    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, proveedor: ProveedorCorreo | None,
                 lector: LectorCorreo, cifrador: Cifrador, motor: MotorAnalisis | None = None):
        super().__init__(uow, reloj)
        self._proveedor = proveedor
        self._lector = lector
        self._cifrador = cifrador
        self._motor = motor

    def ejecutar(self, buzon_id: int, solicitado_por: int | None = None) -> ResumenRevision:
        if self._proveedor is None:
            raise ServicioNoDisponible(MSG_NO_CONFIGURADO)
        with self._uow() as uow:
            buzon = (_buzon_propio(uow, solicitado_por, buzon_id) if solicitado_por is not None
                     else uow.buzones.por_id(buzon_id))
        if buzon is None or not (buzon.revisable or buzon.reintentable):
            return ResumenRevision(buzon_id, estado=buzon.estado.value if buzon else "inexistente")

        try:
            cliente = self._proveedor.abrir(self._cifrador.descifrar(buzon.refresh_token_cifrado))
            ids, history_id = self._ids_nuevos(cliente, buzon)
            nuevos, omitidos = self._ingerir(cliente, buzon, ids)
        except AccesoCorreoRevocado:
            return self._cerrar(buzon, lambda b: b.marcar_acceso_revocado(self._reloj.ahora()), "buzon.acceso_revocado")
        except ErrorProveedorCorreo as error:
            mensaje = str(error) or "El proveedor de correo no respondió."
            return self._cerrar(buzon, lambda b: b.registrar_error(mensaje, self._reloj.ahora()), None)

        with self._uow() as uow:
            actual = uow.buzones.por_id(buzon.id)
            if actual is not None and (actual.revisable or actual.reintentable):   # pudo desconectarse entretanto
                actual.registrar_revision(history_id, self._reloj.ahora())
                uow.buzones.guardar(actual)
                uow.confirmar()
        return ResumenRevision(buzon.id, nuevos=nuevos, omitidos=omitidos)

    def _ids_nuevos(self, cliente, buzon: Buzon) -> tuple[list[str], int]:
        if buzon.ultimo_history_id is None:
            return [], cliente.perfil().history_id
        try:
            cambios = cliente.nuevos_desde(buzon.ultimo_history_id)
            return cambios.ids_nuevos[:MAX_MENSAJES_POR_REVISION], cambios.history_id
        except HistorialExpirado:
            log.warning("Historial expirado en el buzón %s: se revisan los últimos correos", buzon.id)
            history_id = cliente.perfil().history_id
            return cliente.recientes(MAX_RECUPERAR_TRAS_HUECO), history_id

    def _ingerir(self, cliente, buzon: Buzon, ids: list[str]) -> tuple[int, int]:
        nuevos = omitidos = 0
        catalogo = None
        for gmail_id in ids:
            with self._uow() as uow:
                if uow.mensajes.existe(buzon.id, gmail_id):
                    continue
                if catalogo is None and self._motor is not None:
                    catalogo = uow.entidades.catalogo()
            try:
                crudo = cliente.obtener(gmail_id)
            except MensajeNoDisponible:
                omitidos += 1
                continue
            if "SENT" in crudo.etiquetas or "DRAFT" in crudo.etiquetas:
                omitidos += 1
                continue
            correo = self._lector.leer(crudo.crudo) if crudo.crudo is not None else None
            if correo is not None and correo.es_aviso_centinela:
                omitidos += 1
                continue
            mensaje = Mensaje(buzon_id=buzon.id, gmail_id=gmail_id, gmail_hilo_id=crudo.hilo_id,
                              recibido_en=crudo.recibido_en, tamano_bytes=crudo.tamano_bytes, correo=correo)
            resultado = None
            if self._motor and correo:
                # «Primera vez que te escribe» solo vale cuando ya hay historia: en un buzón recién conectado todos
                # los remitentes serían nuevos.
                conocido = None
                if correo.remitente_correo and self._reloj.ahora() - buzon.conectado_en >= HISTORIA_MINIMA:
                    with self._uow() as uow:
                        conocido = uow.mensajes.remitente_conocido(buzon.id, correo.remitente_correo)
                contexto = ContextoDestinatario(correo=buzon.correo_gmail, remitente_conocido=conocido)
                resultado = self._motor.analizar(correo, catalogo, contexto)
            acciones = (decidir_acciones(resultado.veredicto.nivel, buzon.modo, buzon.avisar_por_correo)
                        if resultado else Acciones())
            # 1) Primero la acción en Gmail: si falla, no se guarda nada y la próxima revisión lo reintenta entero.
            try:
                self._aplicar_en_gmail(cliente, buzon, gmail_id, acciones)
            except MensajeNoDisponible:
                omitidos += 1
                continue
            # 2) Luego, el registro completo en UNA transacción (mensaje, veredicto, caso y aviso).
            if self._registrar(buzon, mensaje, resultado, acciones):
                nuevos += 1
        return nuevos, omitidos

    @staticmethod
    def _aplicar_en_gmail(cliente, buzon: Buzon, gmail_id: str, acciones: Acciones) -> None:
        if acciones.cuarentena:
            cliente.modificar_etiquetas(gmail_id, agregar=[buzon.etiqueta_cuarentena_id], quitar=["INBOX"])
        elif acciones.etiquetar_sospechoso:
            cliente.modificar_etiquetas(gmail_id, agregar=[buzon.etiqueta_sospechoso_id], quitar=[])

    def _registrar(self, buzon: Buzon, mensaje: Mensaje, resultado: ResultadoAnalisis | None, acciones: Acciones) -> bool:
        ahora = self._reloj.ahora()
        with self._uow() as uow:
            mensaje_id = uow.mensajes.agregar(mensaje, resultado.idioma if resultado else "otro")
            if mensaje_id is None:
                return False
            if resultado is not None:
                uow.analisis.guardar(mensaje_id, resultado)
                if resultado.veredicto.amerita_caso:
                    caso = Caso.abrir(mensaje_id, ahora)
                    if acciones.cuarentena:
                        caso.transicionar(EstadoCaso.EN_CUARENTENA, ahora,
                                          detalle="Centinela lo movió a cuarentena automáticamente.")
                    caso = uow.casos.agregar(caso)
                    if acciones.avisar:
                        uow.avisos.agregar(caso.id, "correo", buzon.correo_gmail)
                    # Push: solo riesgo alto y solo si la persona activó los avisos en algún dispositivo
                    if resultado.veredicto.nivel is NivelRiesgo.ALTO and uow.suscripciones_push.de_usuario(buzon.usuario_id):
                        uow.avisos.agregar(caso.id, "push", f"dispositivos del usuario {buzon.usuario_id}")
            uow.confirmar()
        return True

    def _cerrar(self, buzon: Buzon, cambio, accion: str | None) -> ResumenRevision:
        with self._uow() as uow:
            actual = uow.buzones.por_id(buzon.id)
            cambio(actual)
            uow.buzones.guardar(actual)
            if accion:
                _auditar_buzon(uow, accion, actual, None, exito=False)
            uow.confirmar()
        return ResumenRevision(buzon.id, estado=actual.estado.value, error=actual.ultimo_error)


class RevisarBuzonesPendientes(CasoDeUso):
    """Lo ejecuta el worker en cada ciclo: reclama los buzones que tocan y los revisa uno por uno.
    Con avisos de Gmail en tiempo real, un buzón vigilado se revisa al llegar el aviso y, de respaldo, cada 5 min."""

    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, revisar: RevisarBuzon, tiempo_real: bool = False):
        super().__init__(uow, reloj)
        self._revisar = revisar
        self._tiempo_real = tiempo_real

    def intervalo_segundos(self) -> int:
        with self._uow() as uow:
            return max(10, int(uow.configuracion.obtener("analisis.intervalo_sondeo_s", 30)))

    def intervalo_respaldo_segundos(self) -> int:
        with self._uow() as uow:
            return max(60, int(uow.configuracion.obtener("analisis.intervalo_respaldo_s", 300)))

    def intervalo_reintento_segundos(self) -> int:
        """Cada cuánto se reintenta un buzón en ERROR (falla pasajera): se recupera solo al volver la red."""
        with self._uow() as uow:
            return max(30, int(uow.configuracion.obtener("analisis.intervalo_reintento_error_s", 60)))

    def ejecutar(self, limite: int = 20) -> list[ResumenRevision]:
        ahora = self._reloj.ahora()
        intervalo = self.intervalo_segundos()
        respaldo = ahora - timedelta(seconds=self.intervalo_respaldo_segundos()) if self._tiempo_real else None
        with self._uow() as uow:
            ids = uow.buzones.reclamar_pendientes(ahora - timedelta(seconds=intervalo), ahora, limite, respaldo,
                                                  ahora - timedelta(seconds=self.intervalo_reintento_segundos()))
            uow.confirmar()
        resumenes = []
        for buzon_id in ids:
            try:
                resumenes.append(self._revisar.ejecutar(buzon_id))
            except Exception:  # un buzón con problemas no detiene a los demás
                log.exception("Error inesperado revisando el buzón %s", buzon_id)
                resumenes.append(ResumenRevision(buzon_id, estado="error", error="Error inesperado"))
        return resumenes
