"""Reportes descargables en PDF y Excel.

* Reporte personal: actividad de los buzones propios en el periodo y el detalle de cada correo de riesgo.
* Reporte de la organización (solo administradores): las mismas cifras sumando todos los buzones, el desglose por
  buzón y los modelos en uso. No incluye asuntos ni remitentes: el administrador no lee los correos de nadie.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, time, timedelta
from enum import StrEnum

from centinela.aplicacion.casos_uso.comun import SIN_CONTEXTO, CasoDeUso, Contexto, admin_activo, usuario_activo
from centinela.aplicacion.casos_uso.panel import ZONA
from centinela.aplicacion.puertos import (
    DatosReporte,
    DiaPanel,
    EventoAuditoria,
    FabricaUnidadDeTrabajo,
    GeneradorReportes,
    Reloj,
)

MAX_DIAS_REPORTE = 365
MAX_CASOS_REPORTE = 2000


class FormatoReporte(StrEnum):
    PDF = "pdf"
    EXCEL = "xlsx"

    @property
    def tipo_mime(self) -> str:
        return ("application/pdf" if self is FormatoReporte.PDF
                else "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@dataclass(frozen=True)
class ArchivoReporte:
    nombre: str
    tipo_mime: str
    contenido: bytes


class GenerarReporte(CasoDeUso):
    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, generador: GeneradorReportes):
        super().__init__(uow, reloj)
        self._generador = generador

    def datos(self, usuario_id: int, dias: int, organizacion: bool = False) -> DatosReporte:
        dias = max(1, min(dias, MAX_DIAS_REPORTE))
        ahora = self._reloj.ahora().astimezone(ZONA)
        hasta = ahora.date()
        inicio = hasta - timedelta(days=dias - 1)
        desde_dt = datetime.combine(inicio, time.min, ZONA)
        hasta_dt = datetime.combine(hasta + timedelta(days=1), time.min, ZONA)
        with self._uow() as uow:
            persona = admin_activo(uow, usuario_id) if organizacion else usuario_activo(uow, usuario_id)
            filtro = None if organizacion else usuario_id
            e = uow.estadisticas.panel(filtro, desde_dt, ZONA.key)
            indicadores = uow.estadisticas.indicadores(filtro, desde_dt)
            casos = [] if organizacion else uow.casos.del_periodo(usuario_id, desde_dt, hasta_dt, MAX_CASOS_REPORTE + 1)
            buzones = uow.estadisticas.por_buzon(desde_dt) if organizacion else []
            modelos = [m for m in uow.modelos.listar() if m.activo] if organizacion else []
        por_fecha = {d.fecha: d for d in e.serie}
        serie = [por_fecha.get(inicio + timedelta(days=i), DiaPanel(inicio + timedelta(days=i), 0, 0, 0))
                 for i in range(dias)]
        return DatosReporte(
            titulo="Reporte de seguridad del correo",
            alcance="Toda la organización" if organizacion else "Mis buzones",
            persona=persona.nombre, generado_en=ahora, desde=inicio, hasta=hasta,
            estadisticas=replace(e, serie=serie), indicadores=indicadores, organizacion=organizacion,
            casos=casos[:MAX_CASOS_REPORTE], casos_truncados=len(casos) > MAX_CASOS_REPORTE,
            buzones=buzones, modelos=modelos)

    def ejecutar(self, usuario_id: int, formato: FormatoReporte, dias: int = 30, organizacion: bool = False,
                 ctx: Contexto = SIN_CONTEXTO) -> ArchivoReporte:
        d = self.datos(usuario_id, dias, organizacion)
        contenido = self._generador.pdf(d) if formato is FormatoReporte.PDF else self._generador.excel(d)
        with self._uow() as uow:
            uow.auditoria.registrar(EventoAuditoria(
                accion="reporte.descargar", usuario_id=usuario_id, ip=ctx.ip,
                detalle={"formato": formato.value, "dias": (d.hasta - d.desde).days + 1,
                         "alcance": "organizacion" if organizacion else "propio", "casos": len(d.casos)}))
            uow.confirmar()
        sufijo = "organizacion" if organizacion else "personal"
        nombre = f"centinela-reporte-{sufijo}-{d.desde.isoformat()}-a-{d.hasta.isoformat()}.{formato.value}"
        return ArchivoReporte(nombre=nombre, tipo_mime=formato.tipo_mime, contenido=contenido)
