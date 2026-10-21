"""Rutas de administración: cuentas de usuario y modelos de ML en uso (solo rol administrador)."""
from __future__ import annotations

from fastapi import APIRouter

from centinela.adaptadores.entrada.api.dependencias import Admin, Cont, Ctx
from centinela.adaptadores.entrada.api.esquemas import ClaveTemporal, ModeloPublico, UsuarioPublico
from centinela.aplicacion.casos_uso.acceso import AccionCuenta
from centinela.dominio.usuario import EstadoCuenta

admin = APIRouter(prefix="/api/admin", tags=["Administración"])


@admin.get("/usuarios", response_model=list[UsuarioPublico])
def listar_usuarios(yo: Admin, c: Cont, estado: EstadoCuenta | None = None) -> list[UsuarioPublico]:
    return [UsuarioPublico.desde(u) for u in c.listar_usuarios.ejecutar(yo.usuario_id, estado)]


@admin.post("/usuarios/{usuario_id}/clave-temporal", response_model=ClaveTemporal)
def restablecer_clave(usuario_id: int, yo: Admin, c: Cont, ctx: Ctx) -> ClaveTemporal:
    """Genera una contraseña temporal (se muestra una sola vez). La persona debe cambiarla al entrar."""
    return ClaveTemporal(clave_temporal=c.restablecer_clave.ejecutar(yo.usuario_id, usuario_id, ctx))


@admin.post("/usuarios/{usuario_id}/{accion}", response_model=UsuarioPublico)
def cambiar_estado(usuario_id: int, accion: AccionCuenta, yo: Admin, c: Cont, ctx: Ctx) -> UsuarioPublico:
    return UsuarioPublico.desde(c.cambiar_estado_cuenta.ejecutar(yo.usuario_id, usuario_id, accion, ctx))


@admin.get("/modelos", response_model=list[ModeloPublico])
def listar_modelos(yo: Admin, c: Cont) -> list[ModeloPublico]:
    """Modelos registrados, con su huella SHA-256, umbrales y métricas de validación (solo lectura)."""
    return [ModeloPublico.desde(m) for m in c.listar_modelos.ejecutar(yo.usuario_id)]
