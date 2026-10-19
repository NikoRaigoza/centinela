"""Casos de uso del dueño del buzón sobre los correos de riesgo: ver, liberar, clasificar y comentar.
También el envío de avisos pendientes (patrón outbox), que ejecuta el worker."""
from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import timedelta
from enum import StrEnum

from centinela.aplicacion.casos_uso.comun import SIN_CONTEXTO, CasoDeUso, Contexto, usuario_activo
from centinela.aplicacion.casos_uso.notificaciones import enviar_a_usuario
from centinela.aplicacion.puertos import (
    AccesoCorreoRevocado,
    AvisoPendiente,
    Cifrador,
    ContextoCaso,
    DatosAviso,
    DetalleCaso,
    EnviadorPush,
    ErrorProveedorCorreo,
    EventoAuditoria,
    FabricaUnidadDeTrabajo,
    MensajeNoDisponible,
    ProveedorCorreo,
    RedactorAvisos,
    Reloj,
    ResumenCaso,
    UnidadDeTrabajo,
)
from centinela.dominio.caso import EstadoCaso, EventoCaso, TipoEvento
from centinela.dominio.errores import NoEncontrado, ServicioNoDisponible, TransicionInvalida

log = logging.getLogger(__name__)

ESPERAS_REINTENTO_MIN = (1, 5, 15, 60)
MAX_INTENTOS_AVISO = 5


class Decision(StrEnum):
    CONFIRMAR = "confirmar"              # sí era phishing
    FALSO_POSITIVO = "falso_positivo"    # era legítimo
    REABRIR = "reabrir"


_DESTINO = {Decision.CONFIRMAR: EstadoCaso.CONFIRMADO, Decision.FALSO_POSITIVO: EstadoCaso.FALSO_POSITIVO,
            Decision.REABRIR: EstadoCaso.NUEVO}
_ETIQUETA = {Decision.CONFIRMAR: "phishing", Decision.FALSO_POSITIVO: "legitimo"}


def contexto_propio(uow: UnidadDeTrabajo, usuario_id: int, caso_id: int) -> ContextoCaso:
    usuario_activo(uow, usuario_id)
    ctx = uow.casos.contexto(caso_id)
    if ctx is None or ctx.usuario_id != usuario_id:     # no se revela si el caso existe en otro buzón
        raise NoEncontrado("El caso no existe.")
    return ctx


def _auditar_caso(uow: UnidadDeTrabajo, accion: str, usuario_id: int, caso_id: int, ctx: Contexto, **detalle) -> None:
    uow.auditoria.registrar(EventoAuditoria(accion=accion, usuario_id=usuario_id, objeto_tipo="caso",
                                            objeto_id=str(caso_id), ip=ctx.ip, detalle=detalle))


class ListarCasos(CasoDeUso):
    def ejecutar(self, usuario_id: int, estados: list[EstadoCaso] | None = None, limite: int = 50,
                 desde: int = 0) -> list[ResumenCaso]:
        with self._uow() as uow:
            usuario_activo(uow, usuario_id)
            return uow.casos.listar(usuario_id, [e.value for e in estados] if estados else None,
                                    max(1, min(limite, 200)), max(0, desde))


class VerCaso(CasoDeUso):
    def ejecutar(self, usuario_id: int, caso_id: int) -> DetalleCaso:
        with self._uow() as uow:
            contexto_propio(uow, usuario_id, caso_id)
            return uow.casos.detalle(caso_id)


class LiberarCorreo(CasoDeUso):
    """Devuelve a la bandeja de entrada un correo en cuarentena (el dueño decidió que es legítimo)."""

    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, proveedor: ProveedorCorreo | None, cifrador: Cifrador):
        super().__init__(uow, reloj)
        self._proveedor = proveedor
        self._cifrador = cifrador

    def ejecutar(self, usuario_id: int, caso_id: int, ctx: Contexto = SIN_CONTEXTO) -> None:
        if self._proveedor is None:
            raise ServicioNoDisponible("La conexión con Gmail no está configurada en este servidor.")
        with self._uow() as uow:
            cc = contexto_propio(uow, usuario_id, caso_id)
            caso = uow.casos.por_id(caso_id)
            buzon = uow.buzones.por_id(cc.buzon_id)
        if not caso.puede_liberarse:
            raise TransicionInvalida("Solo se pueden liberar correos que están en cuarentena.")
        if buzon.refresh_token_cifrado is None:
            raise TransicionInvalida("El buzón está desconectado. Vuelve a conectarlo para liberar el correo.")
        try:
            cliente = self._proveedor.abrir(self._cifrador.descifrar(buzon.refresh_token_cifrado))
            cliente.modificar_etiquetas(cc.gmail_id, agregar=["INBOX"], quitar=[buzon.etiqueta_cuarentena_id])
        except MensajeNoDisponible:
            raise NoEncontrado("Ese correo ya no existe en tu Gmail.") from None
        except (ErrorProveedorCorreo, AccesoCorreoRevocado):
            raise ServicioNoDisponible("Gmail no respondió. Intenta liberar el correo de nuevo.") from None
        with self._uow() as uow:
            caso = uow.casos.por_id(caso_id)
            caso.transicionar(EstadoCaso.LIBERADO, self._reloj.ahora(), autor_id=usuario_id,
                              detalle="El dueño devolvió el correo a la bandeja de entrada.")
            uow.casos.guardar(caso)
            uow.retroalimentacion.registrar(cc.mensaje_id, usuario_id, "legitimo")
            _auditar_caso(uow, "caso.liberar", usuario_id, caso_id, ctx)
            uow.confirmar()


class ClasificarCaso(CasoDeUso):
    def ejecutar(self, usuario_id: int, caso_id: int, decision: Decision, comentario: str | None = None,
                 ctx: Contexto = SIN_CONTEXTO) -> None:
        with self._uow() as uow:
            cc = contexto_propio(uow, usuario_id, caso_id)
            caso = uow.casos.por_id(caso_id)
            caso.transicionar(_DESTINO[decision], self._reloj.ahora(), autor_id=usuario_id, detalle=comentario)
            uow.casos.guardar(caso)
            if decision in _ETIQUETA:
                uow.retroalimentacion.registrar(cc.mensaje_id, usuario_id, _ETIQUETA[decision], comentario)
            _auditar_caso(uow, f"caso.{decision.value}", usuario_id, caso_id, ctx)
            uow.confirmar()


class AgregarNotaCaso(CasoDeUso):
    def ejecutar(self, usuario_id: int, caso_id: int, texto: str) -> None:
        with self._uow() as uow:
            contexto_propio(uow, usuario_id, caso_id)
            caso = uow.casos.por_id(caso_id)
            caso.agregar_nota(texto, usuario_id, self._reloj.ahora())
            uow.casos.guardar(caso)
            uow.confirmar()


class EnviarAvisosPendientes(CasoDeUso):
    """Entrega los avisos pendientes: por correo (se inserta en el buzón del dueño) y por push (a sus dispositivos).
    Reintenta con espera creciente."""

    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, proveedor: ProveedorCorreo | None,
                 cifrador: Cifrador, redactor: RedactorAvisos, enviador_push: EnviadorPush | None = None,
                 carga_push: Callable[[DatosAviso], dict] | None = None):
        super().__init__(uow, reloj)
        self._proveedor = proveedor
        self._cifrador = cifrador
        self._redactor = redactor
        self._push = enviador_push
        self._carga_push = carga_push

    def ejecutar(self, limite: int = 20) -> int:
        canales = [c for c, activo in (("correo", self._proveedor), ("push", self._push)) if activo is not None]
        if not canales:
            return 0
        with self._uow() as uow:
            pendientes = uow.avisos.reclamar_pendientes(self._reloj.ahora(), limite, canales)
            uow.confirmar()
        enviados = 0
        for aviso in pendientes:
            entregado = self._por_push(aviso) if aviso.canal == "push" else self._por_correo(aviso)
            if entregado is None:
                continue
            with self._uow() as uow:
                uow.avisos.marcar_enviado(aviso.id, self._reloj.ahora(), entregado)
                caso = uow.casos.por_id(aviso.caso_id)
                medio = "con una notificación push" if aviso.canal == "push" else "por correo"
                caso.eventos_nuevos.append(EventoCaso(TipoEvento.AVISO, self._reloj.ahora(),
                                                      detalle=f"Se avisó al dueño del buzón {medio}."))
                uow.casos.guardar(caso)
                uow.confirmar()
            enviados += 1
        return enviados

    def _por_correo(self, aviso: AvisoPendiente) -> str | None:
        """Devuelve la referencia del aviso en Gmail, o None si no se pudo entregar."""
        with self._uow() as uow:
            buzon = uow.buzones.por_id(aviso.buzon_id)
        if buzon is None or buzon.refresh_token_cifrado is None:
            self._fallo(aviso.id, aviso.intentos, "El buzón está desconectado.", definitivo=True)
            return None
        try:
            cliente = self._proveedor.abrir(self._cifrador.descifrar(buzon.refresh_token_cifrado))
            return cliente.insertar(self._redactor.redactar(aviso.datos), ["INBOX", "UNREAD", "IMPORTANT"])
        except AccesoCorreoRevocado:
            self._fallo(aviso.id, aviso.intentos, "Google retiró el permiso del buzón.", definitivo=True)
        except ErrorProveedorCorreo as e:
            self._fallo(aviso.id, aviso.intentos, str(e))
        return None

    def _por_push(self, aviso: AvisoPendiente) -> str | None:
        r = enviar_a_usuario(self._uow, self._reloj, self._push, aviso.usuario_id, self._carga_push(aviso.datos))
        if r.entregados:
            return f"{r.entregados} dispositivo(s)"
        if r.errores:
            self._fallo(aviso.id, aviso.intentos, "El servicio push del navegador no respondió.")
        else:
            self._fallo(aviso.id, aviso.intentos, "La persona ya no tiene dispositivos con avisos.", definitivo=True)
        return None

    def _fallo(self, aviso_id: int, intentos: int, error: str, definitivo: bool = False) -> None:
        proximo = None
        if not definitivo and intentos < MAX_INTENTOS_AVISO:
            espera = ESPERAS_REINTENTO_MIN[min(intentos - 1, len(ESPERAS_REINTENTO_MIN) - 1)]
            proximo = self._reloj.ahora() + timedelta(minutes=espera)
        with self._uow() as uow:
            uow.avisos.registrar_fallo(aviso_id, error[:500], proximo)
            uow.confirmar()
        log.warning("No se pudo enviar el aviso %s (%s)", aviso_id, "se reintentará" if proximo else "definitivo")
