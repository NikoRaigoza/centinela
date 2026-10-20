"""Descarga de reportes en PDF o Excel."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, Response

from centinela.adaptadores.entrada.api.dependencias import Actual, Cont, Ctx
from centinela.aplicacion.casos_uso.reportes import MAX_DIAS_REPORTE, FormatoReporte

reportes = APIRouter(prefix="/api/reportes", tags=["Reportes"])


@reportes.get("", response_class=Response, responses={200: {"content": {
    "application/pdf": {}, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {}}}})
def descargar(yo: Actual, c: Cont, ctx: Ctx, formato: FormatoReporte = FormatoReporte.PDF,
              dias: Annotated[int, Query(ge=1, le=MAX_DIAS_REPORTE)] = 30, organizacion: bool = False) -> Response:
    """Reporte de los buzones propios, o de toda la organización (solo administradores, sin asuntos ni remitentes)."""
    archivo = c.generar_reporte.ejecutar(yo.usuario_id, formato, dias, organizacion, ctx)
    return Response(archivo.contenido, media_type=archivo.tipo_mime, headers={
        "Content-Disposition": f'attachment; filename="{archivo.nombre}"',
        "Access-Control-Expose-Headers": "Content-Disposition"})
