"""Rutas de autenticación y de la cuenta propia."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Response, status

from centinela.adaptadores.entrada.api import tokens as t
from centinela.adaptadores.entrada.api.dependencias import (
    Actual,
    Cont,
    Ctx,
    desafio_cambiar_clave,
    desafio_o_acceso_configurar,
    desafio_verificar,
)
from centinela.adaptadores.entrada.api.esquemas import (
    Activacion2FA,
    Configuracion2FA,
    InfoLegal,
    Mensaje,
    RespuestaInicio,
    SolicitudCambioClave,
    SolicitudClaveNueva,
    SolicitudCodigo,
    SolicitudEliminarCuenta,
    SolicitudInicio,
    SolicitudRegistro,
    TokenAcceso,
    UsuarioPublico,
)
from centinela.aplicacion.casos_uso.acceso import Paso, ResultadoInicio, SesionCreada
from centinela.contenedor import Contenedor
from centinela.dominio.errores import CredencialesInvalidas
from centinela.dominio.usuario import VERSION_POLITICA

COOKIE = "centinela_renovacion"
RUTA_COOKIE = "/api/auth"

auth = APIRouter(prefix="/api/auth", tags=["Autenticación"])
publico = APIRouter(prefix="/api/publico", tags=["Público"])
cuenta = APIRouter(prefix="/api/usuarios/yo", tags=["Mi cuenta"])


def _abrir_sesion(respuesta: Response, c: Contenedor, sesion: SesionCreada) -> TokenAcceso:
    """Entrega el token de acceso en el cuerpo y el de renovación en una cookie httpOnly."""
    respuesta.set_cookie(COOKIE, sesion.token_renovacion, expires=sesion.expira_en, path=RUTA_COOKIE,
                         httponly=True, secure=c.config.cookies_seguras, samesite="strict")
    return TokenAcceso(token_acceso=c.tokens.acceso(sesion.usuario), expira_en_s=c.tokens.segundos_acceso,
                       usuario=UsuarioPublico.desde(sesion.usuario))


def _borrar_cookie(respuesta: Response, c: Contenedor) -> None:
    respuesta.delete_cookie(COOKIE, path=RUTA_COOKIE, httponly=True, secure=c.config.cookies_seguras,
                            samesite="strict")


@auth.post("/registro", status_code=status.HTTP_202_ACCEPTED, response_model=Mensaje)
def registrarse(datos: SolicitudRegistro, c: Cont, ctx: Ctx) -> Mensaje:
    c.solicitar_registro.ejecutar(datos.correo, datos.nombre, datos.clave, datos.acepta_politica, ctx)
    return Mensaje(mensaje="Recibimos tu solicitud. Un administrador la revisará y podrás ingresar cuando la apruebe.")


@auth.post("/inicio", response_model=RespuestaInicio)
def iniciar_sesion(datos: SolicitudInicio, respuesta: Response, c: Cont, ctx: Ctx) -> RespuestaInicio:
    return _respuesta_inicio(c.iniciar_sesion.ejecutar(datos.correo, datos.clave, ctx), respuesta, c)


_DESAFIO = {Paso.CONFIGURAR_2FA: t.CONFIGURAR_2FA, Paso.VERIFICAR_2FA: t.VERIFICAR_2FA, Paso.CAMBIAR_CLAVE: t.CAMBIAR_CLAVE}


def _respuesta_inicio(r: ResultadoInicio, respuesta: Response, c: Contenedor) -> RespuestaInicio:
    if r.paso is Paso.COMPLETO:
        return RespuestaInicio(paso=r.paso.value, acceso=_abrir_sesion(respuesta, c, r.sesion))
    return RespuestaInicio(paso=r.paso.value, token_desafio=c.tokens.desafio(r.usuario, _DESAFIO[r.paso]))


@auth.post("/clave-temporal", response_model=RespuestaInicio)
def cambiar_clave_temporal(datos: SolicitudClaveNueva, respuesta: Response, c: Cont, ctx: Ctx,
                           desafio: Annotated[t.Reclamos, Depends(desafio_cambiar_clave)]) -> RespuestaInicio:
    """Primer ingreso con la contraseña temporal del administrador: se elige la definitiva y sigue el ingreso."""
    return _respuesta_inicio(c.cambiar_clave_temporal.ejecutar(desafio.usuario_id, datos.nueva, ctx), respuesta, c)


@auth.post("/2fa/verificacion", response_model=TokenAcceso)
def verificar_2fa(datos: SolicitudCodigo, respuesta: Response, c: Cont, ctx: Ctx,
                  desafio: Annotated[t.Reclamos, Depends(desafio_verificar)]) -> TokenAcceso:
    sesion = c.verificar_2fa.ejecutar(desafio.usuario_id, datos.codigo, ctx)
    return _abrir_sesion(respuesta, c, sesion)


@auth.post("/2fa/configuracion", response_model=Configuracion2FA)
def iniciar_configuracion_2fa(c: Cont, quien: Annotated[t.Reclamos, Depends(desafio_o_acceso_configurar)]):
    d = c.iniciar_config_2fa.ejecutar(quien.usuario_id)
    return Configuracion2FA(secreto=d.secreto, uri=d.uri)


@auth.post("/2fa/confirmacion", response_model=Activacion2FA)
def confirmar_configuracion_2fa(datos: SolicitudCodigo, respuesta: Response, c: Cont, ctx: Ctx,
                                quien: Annotated[t.Reclamos, Depends(desafio_o_acceso_configurar)]) -> Activacion2FA:
    durante_inicio = quien.tipo == t.CONFIGURAR_2FA
    r = c.confirmar_config_2fa.ejecutar(quien.usuario_id, datos.codigo, ctx, iniciar_sesion=durante_inicio)
    acceso = _abrir_sesion(respuesta, c, r.sesion) if r.sesion else None
    return Activacion2FA(codigos_recuperacion=r.codigos_recuperacion, acceso=acceso)


@auth.post("/renovacion", response_model=TokenAcceso)
def renovar(respuesta: Response, c: Cont, ctx: Ctx,
            centinela_renovacion: Annotated[str | None, Cookie()] = None) -> TokenAcceso:
    if not centinela_renovacion:
        raise CredencialesInvalidas("Tu sesión expiró. Inicia sesión de nuevo.")
    try:
        sesion = c.renovar_sesion.ejecutar(centinela_renovacion, ctx)
    except CredencialesInvalidas:
        _borrar_cookie(respuesta, c)
        raise
    return _abrir_sesion(respuesta, c, sesion)


@auth.post("/cierre", status_code=status.HTTP_204_NO_CONTENT)
def cerrar_sesion(respuesta: Response, c: Cont, ctx: Ctx,
                  centinela_renovacion: Annotated[str | None, Cookie()] = None) -> Response:
    if centinela_renovacion:
        c.cerrar_sesion.ejecutar(centinela_renovacion, ctx)
    respuesta.status_code = status.HTTP_204_NO_CONTENT
    _borrar_cookie(respuesta, c)
    return respuesta


@cuenta.get("", response_model=UsuarioPublico)
def mi_cuenta(yo: Actual, c: Cont) -> UsuarioPublico:
    return UsuarioPublico.desde(c.obtener_usuario.ejecutar(yo.usuario_id))


@cuenta.put("/clave", response_model=TokenAcceso)
def cambiar_clave(datos: SolicitudCambioClave, respuesta: Response, yo: Actual, c: Cont, ctx: Ctx) -> TokenAcceso:
    sesion = c.cambiar_clave.ejecutar(yo.usuario_id, datos.actual, datos.nueva, ctx)
    return _abrir_sesion(respuesta, c, sesion)


@cuenta.post("/eliminacion", status_code=status.HTTP_204_NO_CONTENT)
def eliminar_mi_cuenta(datos: SolicitudEliminarCuenta, respuesta: Response, yo: Actual, c: Cont, ctx: Ctx) -> Response:
    """Borra la cuenta y todos sus datos (derecho de supresión). Pide la contraseña para confirmar."""
    c.eliminar_mi_cuenta.ejecutar(yo.usuario_id, datos.clave, ctx)
    respuesta.status_code = status.HTTP_204_NO_CONTENT
    _borrar_cookie(respuesta, c)
    return respuesta


@publico.get("/legal", response_model=InfoLegal)
def info_legal(c: Cont) -> InfoLegal:
    """Datos de la Política de tratamiento de datos (pública: Google la exige en la pantalla de permisos)."""
    with c.uow() as uow:
        dias_bajo = int(uow.configuracion.obtener("retencion.dias_bajo_riesgo", 30))
        dias_casos = int(uow.configuracion.obtener("retencion.dias_casos", 365))
    return InfoLegal(version_politica=VERSION_POLITICA, responsable=c.config.responsable_nombre,
                     correo_contacto=c.config.responsable_correo, dias_sin_riesgo=dias_bajo, dias_casos=dias_casos)
