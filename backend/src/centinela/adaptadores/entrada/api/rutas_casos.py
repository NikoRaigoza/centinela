"""Rutas de casos (correos de riesgo del usuario) y de análisis manual de un correo."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, Request, Response, status

from centinela.adaptadores.entrada.api.dependencias import Actual, Cont, Ctx
from centinela.adaptadores.entrada.api.esquemas import (
    AdjuntoPublico,
    AnalisisPublico,
    CasoPublico,
    ComponentesRiesgo,
    DetalleCasoPublico,
    EnlacePublico,
    EventoPublico,
    RazonPublica,
    SolicitudClasificacion,
    SolicitudNota,
)
from centinela.aplicacion.casos_uso.casos import Decision
from centinela.aplicacion.puertos import ResumenCaso
from centinela.dominio.caso import EstadoCaso
from centinela.dominio.errores import DatoInvalido
from centinela.dominio.reglas import riesgo_adjunto

MAX_BYTES_EML = 10_000_000

casos = APIRouter(prefix="/api/casos", tags=["Casos"])
analisis = APIRouter(prefix="/api/analisis", tags=["Análisis"])


def _razon(r) -> RazonPublica:
    return RazonPublica(area=r.area.value, gravedad=r.gravedad.value, texto=r.texto)


def _caso(r: ResumenCaso) -> dict:
    return dict(id=r.id, estado=r.estado, nivel=r.nivel, probabilidad=r.p_final, resumen=r.resumen, razones=r.razones,
                buzon=r.buzon_correo, remitente_nombre=r.remitente_nombre, remitente_correo=r.remitente_correo,
                asunto=r.asunto, recibido_en=r.recibido_en, puede_liberarse=r.estado == EstadoCaso.EN_CUARENTENA.value)


def _adjunto(nombre: str, tipo_mime: str, tamano: int, riesgo) -> AdjuntoPublico:
    return AdjuntoPublico(nombre=nombre, tipo_mime=tipo_mime, tamano_bytes=tamano, peligroso=riesgo is not None,
                          motivo=riesgo[1] if riesgo else None)


@analisis.post("", response_model=AnalisisPublico, openapi_extra={
    "requestBody": {"content": {"message/rfc822": {"schema": {"type": "string", "format": "binary"}}}}})
async def analizar_correo(request: Request, yo: Actual, c: Cont, ctx: Ctx) -> AnalisisPublico:
    """Analiza un correo .eml enviado como cuerpo de la petición. No se guarda (privacidad)."""
    crudo = await request.body()
    if not crudo:
        raise DatoInvalido("Envía el archivo .eml del correo en el cuerpo de la petición.")
    if len(crudo) > MAX_BYTES_EML:
        raise DatoInvalido("El correo es demasiado grande (máximo 10 MB).")
    correo, r = c.analizar_manual.ejecutar(yo.usuario_id, crudo, ctx)
    v = r.veredicto
    return AnalisisPublico(
        remitente=f"{correo.remitente_nombre} <{correo.remitente_correo}>".strip(), asunto=correo.asunto,
        idioma=r.idioma, nivel=v.nivel.value, probabilidad=v.p_final, resumen=v.resumen,
        razones=[_razon(x) for x in v.razones_visibles], todas_las_razones=[_razon(x) for x in v.razones],
        senales_positivas=r.positivas,
        componentes=ComponentesRiesgo(contenido=v.p_contenido, enlaces=v.p_enlaces, tecnico=v.p_tecnico),
        enlaces=[EnlacePublico(dominio=e.dominio, probabilidad=e.probabilidad, enganoso=e.enganoso, origen=e.origen)
                 for e in r.enlaces],
        adjuntos=[_adjunto(a.nombre, a.tipo_mime, a.tamano_bytes, riesgo_adjunto(a)) for a in correo.adjuntos],
        tiempo_ms=v.tiempo_ms, modelo_contenido_id=r.modelo_contenido_id, modelo_enlaces_id=r.modelo_enlaces_id)


@casos.get("", response_model=list[CasoPublico])
def listar(yo: Actual, c: Cont, estado: Annotated[list[EstadoCaso] | None, Query()] = None,
           limite: Annotated[int, Query(ge=1, le=200)] = 50, desde: Annotated[int, Query(ge=0)] = 0) -> list[CasoPublico]:
    return [CasoPublico(**_caso(r)) for r in c.listar_casos.ejecutar(yo.usuario_id, estado, limite, desde)]


@casos.get("/{caso_id}", response_model=DetalleCasoPublico)
def ver(caso_id: int, yo: Actual, c: Cont) -> DetalleCasoPublico:
    d = c.ver_caso.ejecutar(yo.usuario_id, caso_id)
    return DetalleCasoPublico(
        **_caso(d.resumen), spf=d.spf, dkim=d.dkim, dmarc=d.dmarc,
        todas_las_razones=[_razon(x) for x in d.todas_las_razones],
        enlaces=[EnlacePublico(dominio=e.dominio, probabilidad=e.probabilidad, enganoso=e.enganoso, origen=e.origen)
                 for e in d.enlaces],
        adjuntos=[AdjuntoPublico(nombre=a.nombre, tipo_mime=a.tipo_mime, tamano_bytes=a.tamano_bytes, peligroso=a.peligroso,
                                 motivo=a.motivo) for a in d.adjuntos],
        historial=[EventoPublico(tipo=e.tipo, fecha=e.creado_en, autor=e.autor, detalle=e.detalle) for e in d.eventos])


@casos.post("/{caso_id}/liberacion", status_code=status.HTTP_204_NO_CONTENT)
def liberar(caso_id: int, yo: Actual, c: Cont, ctx: Ctx) -> Response:
    c.liberar_correo.ejecutar(yo.usuario_id, caso_id, ctx)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@casos.post("/{caso_id}/clasificacion", status_code=status.HTTP_204_NO_CONTENT)
def clasificar(caso_id: int, datos: SolicitudClasificacion, yo: Actual, c: Cont, ctx: Ctx) -> Response:
    c.clasificar_caso.ejecutar(yo.usuario_id, caso_id, Decision(datos.decision), datos.comentario, ctx)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@casos.post("/{caso_id}/notas", status_code=status.HTTP_204_NO_CONTENT)
def nota(caso_id: int, datos: SolicitudNota, yo: Actual, c: Cont) -> Response:
    c.nota_caso.ejecutar(yo.usuario_id, caso_id, datos.texto)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
