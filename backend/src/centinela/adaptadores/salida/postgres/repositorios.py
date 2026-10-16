"""Repositorios PostgreSQL: traducen entre las filas (SQLAlchemy) y las entidades del dominio."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from centinela.adaptadores.salida.postgres.tablas import (
    AuditoriaFila,
    CodigoRecuperacionFila,
    ConfiguracionFila,
    SesionFila,
    UsuarioFila,
)
from centinela.aplicacion.puertos import EventoAuditoria
from centinela.dominio.sesion import Sesion
from centinela.dominio.usuario import EstadoCuenta, Rol, Usuario

_CAMPOS_USUARIO = ("correo", "nombre", "clave_hash", "totp_secreto_cifrado", "totp_activo", "totp_ultimo_paso",
                   "intentos_fallidos", "bloqueado_hasta", "aprobado_por", "aprobado_en", "ultimo_acceso")


def _a_usuario(f: UsuarioFila) -> Usuario:
    return Usuario(id=f.id, rol=Rol(f.rol), estado=EstadoCuenta(f.estado), creado_en=f.creado_en,
                   **{c: getattr(f, c) for c in _CAMPOS_USUARIO})


def _volcar_usuario(u: Usuario, f: UsuarioFila) -> None:
    for c in _CAMPOS_USUARIO:
        setattr(f, c, getattr(u, c))
    f.rol, f.estado = u.rol.value, u.estado.value


class RepoUsuariosSql:
    def __init__(self, s: Session):
        self._s = s

    def por_id(self, usuario_id: int) -> Usuario | None:
        f = self._s.get(UsuarioFila, usuario_id)
        return _a_usuario(f) if f else None

    def por_correo(self, correo: str) -> Usuario | None:
        f = self._s.scalar(select(UsuarioFila).where(UsuarioFila.correo == correo))
        return _a_usuario(f) if f else None

    def agregar(self, usuario: Usuario) -> Usuario:
        f = UsuarioFila()
        _volcar_usuario(usuario, f)
        self._s.add(f)
        self._s.flush()
        usuario.id, usuario.creado_en = f.id, f.creado_en
        return usuario

    def guardar(self, usuario: Usuario) -> None:
        f = self._s.get(UsuarioFila, usuario.id)
        _volcar_usuario(usuario, f)
        self._s.flush()

    def listar(self, estado: EstadoCuenta | None = None) -> list[Usuario]:
        q = select(UsuarioFila).order_by(UsuarioFila.creado_en.desc())
        if estado is not None:
            q = q.where(UsuarioFila.estado == estado.value)
        return [_a_usuario(f) for f in self._s.scalars(q)]


def _a_sesion(f: SesionFila) -> Sesion:
    return Sesion(id=f.id, usuario_id=f.usuario_id, token_hash=bytes(f.token_hash), creada_en=f.creada_en,
                  expira_en=f.expira_en, ip=str(f.ip) if f.ip else None, agente=f.agente, revocada_en=f.revocada_en)


class RepoSesionesSql:
    def __init__(self, s: Session):
        self._s = s

    def agregar(self, sesion: Sesion) -> Sesion:
        f = SesionFila(usuario_id=sesion.usuario_id, token_hash=sesion.token_hash, ip=sesion.ip, agente=sesion.agente,
                       creada_en=sesion.creada_en, expira_en=sesion.expira_en)
        self._s.add(f)
        self._s.flush()
        sesion.id = f.id
        return sesion

    def por_hash(self, token_hash: bytes) -> Sesion | None:
        f = self._s.scalar(select(SesionFila).where(SesionFila.token_hash == token_hash))
        return _a_sesion(f) if f else None

    def guardar(self, sesion: Sesion) -> None:
        f = self._s.get(SesionFila, sesion.id)
        f.revocada_en = sesion.revocada_en
        self._s.flush()

    def revocar_de_usuario(self, usuario_id: int, ahora: datetime) -> int:
        r = self._s.execute(update(SesionFila)
                            .where(SesionFila.usuario_id == usuario_id, SesionFila.revocada_en.is_(None))
                            .values(revocada_en=ahora))
        return r.rowcount


class RepoCodigosRecuperacionSql:
    def __init__(self, s: Session):
        self._s = s

    def reemplazar(self, usuario_id: int, hashes: list[str]) -> None:
        self._s.query(CodigoRecuperacionFila).filter_by(usuario_id=usuario_id).delete()
        self._s.add_all(CodigoRecuperacionFila(usuario_id=usuario_id, codigo_hash=h) for h in hashes)
        self._s.flush()

    def consumir(self, usuario_id: int, codigo_hash: str, ahora: datetime) -> bool:
        r = self._s.execute(update(CodigoRecuperacionFila)
                            .where(CodigoRecuperacionFila.usuario_id == usuario_id,
                                   CodigoRecuperacionFila.codigo_hash == codigo_hash,
                                   CodigoRecuperacionFila.usado_en.is_(None))
                            .values(usado_en=ahora))
        return r.rowcount == 1


class RepoConfiguracionSql:
    def __init__(self, s: Session):
        self._s = s

    def obtener(self, clave: str, defecto: Any) -> Any:
        valor = self._s.scalar(select(ConfiguracionFila.valor).where(ConfiguracionFila.clave == clave))
        return defecto if valor is None else valor


class RegistroAuditoriaSql:
    def __init__(self, s: Session):
        self._s = s

    def registrar(self, evento: EventoAuditoria) -> None:
        self._s.add(AuditoriaFila(usuario_id=evento.usuario_id, accion=evento.accion, objeto_tipo=evento.objeto_tipo,
                                  objeto_id=evento.objeto_id, exito=evento.exito, ip=evento.ip,
                                  detalle=evento.detalle or {}))
        self._s.flush()
