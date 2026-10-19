"""Rutas de buzones de Gmail: conexión OAuth2, ajustes, revisión manual y mensajes recibidos.

Protección del flujo OAuth contra CSRF: además del `state` firmado, el navegador que inició la conexión recibe una
cookie con un valor aleatorio (nonce) que debe coincidir con el del `state` cuando Google lo devuelve.
"""
from __future__ import annotations

import hmac
import html
import secrets
from typing import Annotated

from fastapi import APIRouter, Cookie, Query, Response
from fastapi.responses import HTMLResponse

from centinela.adaptadores.entrada.api.dependencias import Actual, Admin, Cont, Ctx
from centinela.adaptadores.entrada.api.esquemas import (
    BuzonPublico,
    CambiosBuzon,
    MensajePublico,
    ResumenRevisionPublico,
    UrlAutorizacion,
)
from centinela.adaptadores.entrada.api.tokens import MINUTOS_OAUTH
from centinela.aplicacion.casos_uso.buzones import nuevo_verificador_pkce
from centinela.dominio.errores import AccesoDenegado, DatoInvalido, ErrorCentinela

COOKIE_OAUTH = "centinela_oauth"
RUTA_OAUTH = "/api/gmail"

buzones = APIRouter(prefix="/api/buzones", tags=["Buzones"])
gmail = APIRouter(prefix=RUTA_OAUTH, tags=["Buzones"])
admin_buzones = APIRouter(prefix="/api/admin/buzones", tags=["Administración"])


@buzones.post("/conexion", response_model=UrlAutorizacion)
def iniciar_conexion(respuesta: Response, yo: Actual, c: Cont) -> UrlAutorizacion:
    """Devuelve la URL de Google. El panel debe navegar a ella (no abrirla con fetch)."""
    nonce, verificador = secrets.token_urlsafe(24), nuevo_verificador_pkce()
    estado = c.tokens.estado_oauth(yo.usuario_id, nonce, c.cifrador.cifrar(verificador).decode())
    url = c.iniciar_conexion_gmail.ejecutar(yo.usuario_id, estado, verificador)
    respuesta.set_cookie(COOKIE_OAUTH, nonce, max_age=MINUTOS_OAUTH * 60, path=RUTA_OAUTH, httponly=True,
                         secure=c.config.cookies_seguras, samesite="lax")
    return UrlAutorizacion(url=url)


def _pagina(exito: bool, mensaje: str, url_panel: str) -> str:
    titulo = "Buzón conectado" if exito else "No se pudo conectar el buzón"
    color = "#2E7D32" if exito else "#C62828"
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Centinela · {titulo}</title>
<style>body{{font-family:system-ui,sans-serif;background:#F4F7FA;color:#16202B;display:grid;place-items:center;
min-height:100vh;margin:0;padding:16px}}main{{background:#fff;border-radius:12px;padding:32px;max-width:440px;
box-shadow:0 2px 12px rgba(0,0,0,.08)}}h1{{color:{color};font-size:1.3rem}}a{{color:#2E7CE4}}</style></head>
<body><main><h1>{html.escape(titulo)}</h1><p>{html.escape(mensaje)}</p>
<p><a href="{html.escape(url_panel.rstrip("/") + "/buzones")}">Volver al panel de Centinela</a></p></main></body></html>"""


@gmail.get("/callback", response_class=HTMLResponse, include_in_schema=False)
def callback(c: Cont, ctx: Ctx, state: str | None = None, code: str | None = None, error: str | None = None,
             centinela_oauth: Annotated[str | None, Cookie()] = None) -> HTMLResponse:
    try:
        if error:
            raise DatoInvalido("Cancelaste la conexión con Gmail." if error == "access_denied"
                               else "Google no autorizó la conexión.")
        if not state or not code:
            raise DatoInvalido("La respuesta de Google llegó incompleta. Intenta conectar el buzón de nuevo.")
        estado = c.tokens.leer_estado_oauth(state)
        if not centinela_oauth or not hmac.compare_digest(centinela_oauth, estado.nonce):
            raise AccesoDenegado("La conexión debe completarse en el mismo navegador donde la iniciaste.")
        verificador = c.cifrador.descifrar(estado.verificador_cifrado.encode())
        buzon = c.completar_conexion_gmail.ejecutar(estado.usuario_id, code, verificador, ctx)
        respuesta = HTMLResponse(_pagina(True, f"Centinela ya está protegiendo {buzon.correo_gmail}. "
                                               "Revisará cada correo nuevo que llegue.", c.config.url_panel))
    except ErrorCentinela as e:
        respuesta = HTMLResponse(_pagina(False, e.mensaje, c.config.url_panel), status_code=400)
    respuesta.delete_cookie(COOKIE_OAUTH, path=RUTA_OAUTH, httponly=True, secure=c.config.cookies_seguras, samesite="lax")
    respuesta.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
    return respuesta


@buzones.get("", response_model=list[BuzonPublico])
def mis_buzones(yo: Actual, c: Cont) -> list[BuzonPublico]:
    return [BuzonPublico.desde(b) for b in c.listar_buzones.ejecutar(yo.usuario_id)]


@buzones.patch("/{buzon_id}", response_model=BuzonPublico)
def actualizar(buzon_id: int, datos: CambiosBuzon, yo: Actual, c: Cont, ctx: Ctx) -> BuzonPublico:
    b = c.actualizar_buzon.ejecutar(yo.usuario_id, buzon_id, modo=datos.modo,
                                    avisar_por_correo=datos.avisar_por_correo, pausado=datos.pausado, ctx=ctx)
    return BuzonPublico.desde(b)


@buzones.delete("/{buzon_id}", response_model=BuzonPublico)
def desconectar(buzon_id: int, yo: Actual, c: Cont, ctx: Ctx) -> BuzonPublico:
    return BuzonPublico.desde(c.desconectar_buzon.ejecutar(yo.usuario_id, buzon_id, ctx))


@buzones.post("/{buzon_id}/revision", response_model=ResumenRevisionPublico)
def revisar_ahora(buzon_id: int, yo: Actual, c: Cont) -> ResumenRevisionPublico:
    return ResumenRevisionPublico.desde(c.revisar_buzon.ejecutar(buzon_id, solicitado_por=yo.usuario_id))


@buzones.get("/{buzon_id}/mensajes", response_model=list[MensajePublico])
def mensajes(buzon_id: int, yo: Actual, c: Cont,
             limite: Annotated[int, Query(ge=1, le=200)] = 50) -> list[MensajePublico]:
    return [MensajePublico.desde(m) for m in c.listar_mensajes.ejecutar(yo.usuario_id, buzon_id, limite)]


@admin_buzones.get("", response_model=list[BuzonPublico])
def todos_los_buzones(yo: Admin, c: Cont) -> list[BuzonPublico]:
    return [BuzonPublico.desde(b) for b in c.listar_todos_los_buzones.ejecutar(yo.usuario_id)]
