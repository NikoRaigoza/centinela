"""Rutas del asistente de IA y de las notificaciones push del usuario."""
from __future__ import annotations

from fastapi import APIRouter, Response, status

from centinela.adaptadores.entrada.api.dependencias import Actual, Cont, Ctx
from centinela.adaptadores.entrada.api.esquemas import (
    ConfiguracionPush,
    ConversacionDetalle,
    ConversacionPublica,
    DispositivoPush,
    EstadoAsistentePublico,
    RespuestaPublica,
    ResultadoPrueba,
    SolicitudPregunta,
    SolicitudQuitarSuscripcion,
    SolicitudSuscripcion,
    TurnoPublico,
)
from centinela.aplicacion.guia_asistente import SUGERENCIAS_CASO, SUGERENCIAS_GENERALES

asistente = APIRouter(prefix="/api/asistente", tags=["Asistente"])
push = APIRouter(prefix="/api/push", tags=["Notificaciones push"])


@asistente.get("/estado", response_model=EstadoAsistentePublico)
def estado_asistente(yo: Actual, c: Cont) -> EstadoAsistentePublico:
    e = c.consultar_asistente.estado(yo.usuario_id)
    return EstadoAsistentePublico(ia_disponible=e.ia_disponible, proveedor=e.proveedor, limite_ia=e.limite_ia,
                                  restantes_ia=e.restantes_ia, sugerencias_generales=SUGERENCIAS_GENERALES,
                                  sugerencias_caso=SUGERENCIAS_CASO)


@asistente.post("/preguntas", response_model=RespuestaPublica)
def preguntar(datos: SolicitudPregunta, yo: Actual, c: Cont) -> RespuestaPublica:
    """Sin `conversacion_id` empieza una conversación nueva (sobre un caso si se envía `caso_id`)."""
    return RespuestaPublica.desde(c.preguntar_asistente.ejecutar(yo.usuario_id, datos.pregunta, datos.conversacion_id,
                                                                 datos.caso_id))


@asistente.get("/conversaciones", response_model=list[ConversacionPublica])
def conversaciones(yo: Actual, c: Cont) -> list[ConversacionPublica]:
    return [ConversacionPublica.desde(x) for x in c.consultar_asistente.conversaciones(yo.usuario_id)]


@asistente.get("/conversaciones/{conversacion_id}", response_model=ConversacionDetalle)
def conversacion(conversacion_id: int, yo: Actual, c: Cont) -> ConversacionDetalle:
    conv, turnos = c.consultar_asistente.conversacion(yo.usuario_id, conversacion_id)
    return ConversacionDetalle(**ConversacionPublica.desde(conv).model_dump(),
                               turnos=[TurnoPublico(rol=t.rol, contenido=t.contenido, proveedor=t.proveedor,
                                                    creado_en=t.creado_en) for t in turnos])


@asistente.delete("/conversaciones/{conversacion_id}", status_code=status.HTTP_204_NO_CONTENT)
def eliminar_conversacion(conversacion_id: int, yo: Actual, c: Cont) -> Response:
    c.consultar_asistente.eliminar(yo.usuario_id, conversacion_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@push.get("/configuracion", response_model=ConfiguracionPush)
def configuracion_push(_: Actual, c: Cont) -> ConfiguracionPush:
    """La llave pública VAPID que el navegador necesita para suscribirse."""
    clave = c.activar_push.clave_publica()
    return ConfiguracionPush(disponible=clave is not None, clave_publica=clave)


@push.get("/dispositivos", response_model=list[DispositivoPush])
def dispositivos(yo: Actual, c: Cont) -> list[DispositivoPush]:
    return [DispositivoPush.desde(s) for s in c.listar_dispositivos_push.ejecutar(yo.usuario_id)]


@push.post("/dispositivos", status_code=status.HTTP_204_NO_CONTENT)
def activar(datos: SolicitudSuscripcion, yo: Actual, c: Cont, ctx: Ctx) -> Response:
    c.activar_push.ejecutar(yo.usuario_id, datos.endpoint, datos.keys.p256dh, datos.keys.auth, ctx)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@push.post("/dispositivos/quitar", status_code=status.HTTP_204_NO_CONTENT)
def quitar_este(datos: SolicitudQuitarSuscripcion, yo: Actual, c: Cont, ctx: Ctx) -> Response:
    """Quita la suscripción del navegador actual (al desactivar los avisos o al cerrar sesión)."""
    c.quitar_push.ejecutar(yo.usuario_id, endpoint=datos.endpoint, ctx=ctx)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@push.delete("/dispositivos/{suscripcion_id}", status_code=status.HTTP_204_NO_CONTENT)
def quitar(suscripcion_id: int, yo: Actual, c: Cont, ctx: Ctx) -> Response:
    c.quitar_push.ejecutar(yo.usuario_id, suscripcion_id=suscripcion_id, ctx=ctx)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@push.post("/prueba", response_model=ResultadoPrueba)
def probar(yo: Actual, c: Cont) -> ResultadoPrueba:
    r = c.probar_push.ejecutar(yo.usuario_id)
    return ResultadoPrueba(entregados=r.entregados, vencidas=r.vencidas, errores=r.errores)
