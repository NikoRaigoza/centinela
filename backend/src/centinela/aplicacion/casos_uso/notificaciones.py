"""Casos de uso de las notificaciones push: activarlas en un dispositivo, verlas, quitarlas y probarlas."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta

from centinela.aplicacion.casos_uso.comun import SIN_CONTEXTO, CasoDeUso, Contexto, auditar, usuario_activo
from centinela.aplicacion.puertos import (
    EnviadorPush,
    FabricaUnidadDeTrabajo,
    Reloj,
    ResultadoPush,
    SuscripcionPush,
)
from centinela.dominio.errores import DatoInvalido, NoEncontrado, ServicioNoDisponible
from centinela.dominio.notificaciones import nombre_dispositivo, validar_endpoint

log = logging.getLogger(__name__)

MAX_DISPOSITIVOS = 10
# Recién creada, el servicio push a veces aún no la reconoce (se observó con FCM): en ese lapso un «no existe» se
# trata como falla pasajera y no se borra la suscripción.
GRACIA_SUSCRIPCION_NUEVA = timedelta(minutes=10)
MSG_SIN_PUSH = "Las notificaciones push no están configuradas en este servidor."
CARGA_PRUEBA = {"titulo": "Centinela", "cuerpo": "¡Listo! Así te avisaremos cuando detengamos un correo peligroso.",
                "url": "/cuenta", "etiqueta": "prueba"}


@dataclass(frozen=True)
class ResultadoEnvio:
    entregados: int = 0
    vencidas: int = 0
    errores: int = 0


def enviar_a_usuario(uow: FabricaUnidadDeTrabajo, reloj: Reloj, enviador: EnviadorPush, usuario_id: int,
                     carga: dict) -> ResultadoEnvio:
    """Envía a todos los dispositivos del usuario. Las suscripciones que el navegador ya no acepta se borran."""
    with uow() as u:
        suscripciones = u.suscripciones_push.de_usuario(usuario_id)
    entregados = vencidas = errores = 0
    for s in suscripciones:
        resultado = enviador.enviar(s, carga)
        if resultado is ResultadoPush.VENCIDA and s.creado_en and reloj.ahora() - s.creado_en < GRACIA_SUSCRIPCION_NUEVA:
            resultado = ResultadoPush.ERROR
        with uow() as u:
            if resultado is ResultadoPush.ENTREGADO:
                u.suscripciones_push.marcar_envio(s.id, reloj.ahora())
                entregados += 1
            elif resultado is ResultadoPush.VENCIDA:
                u.suscripciones_push.eliminar_vencida(s.id)
                vencidas += 1
            else:
                errores += 1
            u.confirmar()
    return ResultadoEnvio(entregados, vencidas, errores)


def _llave_valida(valor: str, minimo: int, maximo: int) -> bool:
    return minimo <= len(valor) <= maximo and all(c.isalnum() or c in "-_=" for c in valor)


class ActivarPush(CasoDeUso):
    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, enviador: EnviadorPush | None):
        super().__init__(uow, reloj)
        self._enviador = enviador

    def clave_publica(self) -> str | None:
        return self._enviador.clave_publica if self._enviador else None

    def ejecutar(self, usuario_id: int, endpoint: str, p256dh: str, auth: str, ctx: Contexto = SIN_CONTEXTO) -> None:
        if self._enviador is None:
            raise ServicioNoDisponible(MSG_SIN_PUSH)
        endpoint = validar_endpoint(endpoint)
        if not (_llave_valida(p256dh, 80, 100) and _llave_valida(auth, 16, 32)):
            raise DatoInvalido("El navegador entregó una suscripción inválida. Intenta de nuevo.")
        with self._uow() as uow:
            usuario_activo(uow, usuario_id)
            actuales = uow.suscripciones_push.de_usuario(usuario_id)
            if len(actuales) >= MAX_DISPOSITIVOS and all(s.endpoint != endpoint for s in actuales):
                raise DatoInvalido(f"Ya tienes {MAX_DISPOSITIVOS} dispositivos con avisos. Quita alguno primero.")
            uow.suscripciones_push.guardar(usuario_id, endpoint, p256dh, auth, nombre_dispositivo(ctx.agente))
            auditar(uow, "push.activar", ctx, usuario_id)
            uow.confirmar()


class ListarDispositivosPush(CasoDeUso):
    def ejecutar(self, usuario_id: int) -> list[SuscripcionPush]:
        with self._uow() as uow:
            usuario_activo(uow, usuario_id)
            return uow.suscripciones_push.de_usuario(usuario_id)


class QuitarPush(CasoDeUso):
    """Por id (desde la lista de dispositivos) o por la dirección del navegador actual (al desactivar o salir)."""

    def ejecutar(self, usuario_id: int, suscripcion_id: int | None = None, endpoint: str | None = None,
                 ctx: Contexto = SIN_CONTEXTO) -> None:
        if suscripcion_id is None and not endpoint:
            raise DatoInvalido("Indica qué dispositivo quieres quitar.")
        with self._uow() as uow:
            if not uow.suscripciones_push.eliminar(usuario_id, suscripcion_id, endpoint):
                if suscripcion_id is not None:
                    raise NoEncontrado("Ese dispositivo ya no recibe avisos.")
                return                  # el navegador ya no estaba registrado: no hay nada que hacer
            auditar(uow, "push.quitar", ctx, usuario_id)
            uow.confirmar()


class ProbarPush(CasoDeUso):
    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, enviador: EnviadorPush | None):
        super().__init__(uow, reloj)
        self._enviador = enviador

    def ejecutar(self, usuario_id: int) -> ResultadoEnvio:
        if self._enviador is None:
            raise ServicioNoDisponible(MSG_SIN_PUSH)
        with self._uow() as uow:
            usuario_activo(uow, usuario_id)
            if not uow.suscripciones_push.de_usuario(usuario_id):
                raise NoEncontrado("Aún no activas los avisos en ningún dispositivo.")
        return enviar_a_usuario(self._uow, self._reloj, self._enviador, usuario_id, CARGA_PRUEBA)
