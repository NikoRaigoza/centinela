"""Tareas de mantenimiento que corre el worker: retención de datos (Ley 1581, principio de temporalidad).

Plazos en la tabla `configuracion` (los puede ajustar el administrador de la BD):
  * retencion.dias_bajo_riesgo (30): correos que no abrieron caso (sin riesgo o sin analizar) y su análisis.
  * retencion.dias_casos (365): casos ya cerrados (liberados, confirmados o falsos positivos) con todo su análisis.
  * Las sesiones vencidas o cerradas se borran a los 30 días.
Los casos abiertos nunca se borran solos. La bitácora de auditoría no se toca (es inmutable).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from centinela.aplicacion.casos_uso.comun import CasoDeUso
from centinela.aplicacion.puertos import EventoAuditoria

DIAS_SESIONES = 30


@dataclass(frozen=True)
class ResultadoRetencion:
    mensajes_sin_riesgo: int
    casos_cerrados: int
    sesiones: int


class AplicarRetencion(CasoDeUso):
    def ejecutar(self) -> ResultadoRetencion:
        ahora = self._reloj.ahora()
        with self._uow() as uow:
            dias_bajo = max(1, int(uow.configuracion.obtener("retencion.dias_bajo_riesgo", 30)))
            dias_casos = max(1, int(uow.configuracion.obtener("retencion.dias_casos", 365)))
            n = uow.retencion.purgar(ahora - timedelta(days=dias_bajo), ahora - timedelta(days=dias_casos),
                                     ahora - timedelta(days=DIAS_SESIONES))
            uow.auditoria.registrar(EventoAuditoria(accion="retencion.aplicar", objeto_tipo="sistema",
                                                    detalle={**n, "dias_bajo_riesgo": dias_bajo, "dias_casos": dias_casos}))
            uow.confirmar()
        return ResultadoRetencion(**n)
