"""Piezas compartidas por los casos de uso: contexto de la petición, auditoría y verificación de cuentas."""
from __future__ import annotations

from dataclasses import dataclass

from centinela.aplicacion.puertos import EventoAuditoria, FabricaUnidadDeTrabajo, Reloj, UnidadDeTrabajo
from centinela.dominio.errores import AccesoDenegado, CredencialesInvalidas
from centinela.dominio.usuario import Usuario

MSG_SESION = "Tu sesión expiró. Inicia sesión de nuevo."


@dataclass(frozen=True)
class Contexto:
    """Datos de la petición que sirven para auditar."""
    ip: str | None = None
    agente: str | None = None


SIN_CONTEXTO = Contexto()


class CasoDeUso:
    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj):
        self._uow = uow
        self._reloj = reloj


def auditar(uow: UnidadDeTrabajo, accion: str, ctx: Contexto, usuario_id: int | None = None,
            exito: bool = True, **detalle) -> None:
    uow.auditoria.registrar(EventoAuditoria(accion=accion, usuario_id=usuario_id, objeto_tipo="usuario",
                                            objeto_id=str(usuario_id) if usuario_id else None,
                                            exito=exito, ip=ctx.ip, detalle=detalle))


def usuario_activo(uow: UnidadDeTrabajo, usuario_id: int) -> Usuario:
    usuario = uow.usuarios.por_id(usuario_id)
    if usuario is None:
        raise CredencialesInvalidas(MSG_SESION)
    usuario.verificar_puede_ingresar()
    return usuario


def admin_activo(uow: UnidadDeTrabajo, admin_id: int) -> Usuario:
    admin = usuario_activo(uow, admin_id)
    if not admin.es_admin:
        raise AccesoDenegado("Esta acción es solo para administradores.")
    return admin
