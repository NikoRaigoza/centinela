"""Casos de uso del panel: resumen de la pantalla de inicio y consulta de los modelos en uso."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

from centinela.aplicacion.casos_uso.comun import CasoDeUso, admin_activo, usuario_activo
from centinela.aplicacion.puertos import DiaPanel, EstadisticasPanel, ModeloRegistrado

ZONA = ZoneInfo("America/Bogota")      # los días del resumen son días de Colombia, no de UTC
MAX_DIAS = 90


class ObtenerResumenPanel(CasoDeUso):
    """Correos revisados, detecciones por día, casos por estado y entidades más suplantadas en los buzones propios."""

    def ejecutar(self, usuario_id: int, dias: int = 30) -> EstadisticasPanel:
        dias = max(1, min(dias, MAX_DIAS))
        inicio = self._reloj.ahora().astimezone(ZONA).date() - timedelta(days=dias - 1)
        with self._uow() as uow:
            usuario_activo(uow, usuario_id)
            e = uow.estadisticas.panel(usuario_id, datetime.combine(inicio, time.min, ZONA), ZONA.key)
        por_fecha = {d.fecha: d for d in e.serie}
        fechas = [inicio + timedelta(days=i) for i in range(dias)]
        return replace(e, serie=[por_fecha.get(f, DiaPanel(f, 0, 0, 0)) for f in fechas])


class ListarModelos(CasoDeUso):
    def ejecutar(self, admin_id: int) -> list[ModeloRegistrado]:
        with self._uow() as uow:
            admin_activo(uow, admin_id)
            return uow.modelos.listar()
