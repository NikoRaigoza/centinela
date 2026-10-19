"""Aplicación FastAPI: arma rutas, traduce errores del dominio a HTTP y agrega cabeceras de seguridad.
Si el panel React está compilado, también lo sirve (rutas que no empiezan por /api)."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import text

from centinela.adaptadores.entrada.api.rutas_acceso import auth, cuenta
from centinela.adaptadores.entrada.api.rutas_admin import admin
from centinela.adaptadores.entrada.api.rutas_buzones import admin_buzones, buzones, gmail
from centinela.adaptadores.entrada.api.rutas_casos import analisis, casos
from centinela.adaptadores.entrada.api.rutas_panel import panel
from centinela.contenedor import Contenedor, construir
from centinela.dominio import errores as e

ESTADO_HTTP = {
    e.DatoInvalido: 422,
    e.CredencialesInvalidas: 401,
    e.CuentaBloqueada: 423,
    e.AccesoDenegado: 403,
    e.NoEncontrado: 404,
    e.Conflicto: 409,
    e.TransicionInvalida: 409,
    e.ServicioNoDisponible: 503,
}

CABECERAS_SEGURIDAD = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

# El panel no carga nada de terceros: ni fuentes, ni scripts, ni analítica (los correos no salen de la empresa).
CSP_PANEL = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
             "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
             "frame-ancestors 'none'")
CACHE_INMUTABLE = "public, max-age=31536000, immutable"      # archivos de /assets: llevan hash en el nombre


def crear_app(contenedor: Contenedor | None = None) -> FastAPI:
    contenedor = contenedor or construir()
    produccion = contenedor.config.entorno == "produccion"
    app = FastAPI(title="Centinela API", version="0.1.0",
                  description="Detección de phishing en correos de Gmail para usuarios en Colombia.",
                  docs_url=None if produccion else "/api/docs", openapi_url=None if produccion else "/api/openapi.json")
    app.state.contenedor = contenedor

    app.add_middleware(CORSMiddleware, allow_origins=contenedor.config.origenes_cors, allow_credentials=True,
                       allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type"])

    @app.middleware("http")
    async def cabeceras_seguridad(request: Request, call_next):
        respuesta = await call_next(request)
        if request.url.path.startswith("/assets/") and respuesta.status_code == 200:
            respuesta.headers["Cache-Control"] = CACHE_INMUTABLE
        for k, v in CABECERAS_SEGURIDAD.items():
            respuesta.headers.setdefault(k, v)
        if produccion:
            respuesta.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return respuesta

    @app.exception_handler(e.ErrorCentinela)
    async def error_centinela(_: Request, err: e.ErrorCentinela) -> JSONResponse:
        estado = next((s for tipo, s in ESTADO_HTTP.items() if isinstance(err, tipo)), 400)
        cabeceras = {"WWW-Authenticate": "Bearer"} if estado == 401 else None
        return JSONResponse({"codigo": err.codigo, "mensaje": err.mensaje}, status_code=estado, headers=cabeceras)

    @app.exception_handler(RequestValidationError)
    async def error_validacion(_: Request, err: RequestValidationError) -> JSONResponse:
        campos = sorted({str(x["loc"][-1]) for x in err.errors()})
        return JSONResponse({"codigo": "dato_invalido", "mensaje": "Revisa los datos enviados: " + ", ".join(campos)},
                            status_code=422)

    @app.get("/api/salud", tags=["Sistema"])
    def salud() -> dict:
        with contenedor.motor.connect() as conexion:
            conexion.execute(text("SELECT 1"))
        return {"estado": "ok", "base_de_datos": "ok"}

    app.include_router(auth)
    app.include_router(cuenta)
    app.include_router(admin)
    app.include_router(buzones)
    app.include_router(gmail)
    app.include_router(admin_buzones)
    app.include_router(casos)
    app.include_router(analisis)
    app.include_router(panel)
    if contenedor.config.dir_panel and (contenedor.config.dir_panel / "index.html").is_file():
        _servir_panel(app, contenedor.config.dir_panel.resolve())
    return app


def _servir_panel(app: FastAPI, carpeta: Path) -> None:
    """Archivos del panel compilado; cualquier otra ruta devuelve index.html (React Router decide qué mostrar)."""
    indice = carpeta / "index.html"

    @app.get("/{ruta:path}", include_in_schema=False)
    def panel_web(ruta: str):
        if ruta == "api" or ruta.startswith("api/"):
            return JSONResponse({"codigo": "no_encontrado", "mensaje": "La ruta no existe."}, status_code=404)
        archivo = (carpeta / ruta).resolve()
        if ruta and archivo.is_file() and archivo.is_relative_to(carpeta):      # sin salir de la carpeta
            return FileResponse(archivo)
        return FileResponse(indice, headers={"Content-Security-Policy": CSP_PANEL})
