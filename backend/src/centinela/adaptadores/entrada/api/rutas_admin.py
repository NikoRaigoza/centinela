"""Rutas de administración de cuentas (solo rol administrador)."""
from __future__ import annotations

from fastapi import APIRouter

from centinela.adaptadores.entrada.api.dependencias import Admin, Cont, Ctx
from centinela.adaptadores.entrada.api.esquemas import UsuarioPublico
from centinela.aplicacion.casos_uso.acceso import AccionCuenta
from centinela.dominio.usuario import EstadoCuenta

admin = APIRouter(prefix="/api/admin", tags=["Administración"])


@admin.get("/usuarios", response_model=list[UsuarioPublico])
def listar_usuarios(yo: Admin, c: Cont, estado: EstadoCuenta | None = None) -> list[UsuarioPublico]:
    return [UsuarioPublico.desde(u) for u in c.listar_usuarios.ejecutar(yo.usuario_id, estado)]


@admin.post("/usuarios/{usuario_id}/{accion}", response_model=UsuarioPublico)
def cambiar_estado(usuario_id: int, accion: AccionCuenta, yo: Admin, c: Cont, ctx: Ctx) -> UsuarioPublico:
    return UsuarioPublico.desde(c.cambiar_estado_cuenta.ejecutar(yo.usuario_id, usuario_id, accion, ctx))
