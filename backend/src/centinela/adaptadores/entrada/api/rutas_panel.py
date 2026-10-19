"""Ruta del resumen de la pantalla de inicio del panel."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from centinela.adaptadores.entrada.api.dependencias import Actual, Cont
from centinela.adaptadores.entrada.api.esquemas import ResumenPanelPublico
from centinela.aplicacion.casos_uso.panel import MAX_DIAS

panel = APIRouter(prefix="/api/panel", tags=["Panel"])


@panel.get("/resumen", response_model=ResumenPanelPublico)
def resumen(yo: Actual, c: Cont, dias: Annotated[int, Query(ge=1, le=MAX_DIAS)] = 30) -> ResumenPanelPublico:
    """Actividad de los buzones propios: correos revisados y detecciones por día (hora de Colombia)."""
    return ResumenPanelPublico.desde(c.resumen_panel.ejecutar(yo.usuario_id, dias))
