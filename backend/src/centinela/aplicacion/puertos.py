"""Puertos de salida: lo que la aplicación necesita del mundo exterior, sin saber cómo se implementa.

Los adaptadores (PostgreSQL, argon2, pyotp, Fernet, ...) implementan estas interfaces.
En las pruebas se reemplazan por versiones en memoria.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, Self

from centinela.dominio.sesion import Sesion
from centinela.dominio.usuario import EstadoCuenta, Usuario


# ---------------------------------------------------------------------- servicios técnicos
class Reloj(Protocol):
    def ahora(self) -> datetime: ...


class HasherClaves(Protocol):
    def hashear(self, clave: str) -> str: ...
    def verificar(self, clave: str, hash_guardado: str) -> bool: ...
    def necesita_rehash(self, hash_guardado: str) -> bool: ...


class Cifrador(Protocol):
    def cifrar(self, texto: str) -> bytes: ...
    def descifrar(self, datos: bytes) -> str: ...


class ServicioTotp(Protocol):
    def generar_secreto(self) -> str: ...
    def uri_aprovisionamiento(self, secreto: str, cuenta: str) -> str: ...
    def verificar(self, secreto: str, codigo: str, ahora: datetime) -> int | None:
        """Devuelve el paso de tiempo del código si es válido; None si no lo es."""
        ...


# ---------------------------------------------------------------------- persistencia
class RepoUsuarios(Protocol):
    def por_id(self, usuario_id: int) -> Usuario | None: ...
    def por_correo(self, correo: str) -> Usuario | None: ...
    def agregar(self, usuario: Usuario) -> Usuario: ...
    def guardar(self, usuario: Usuario) -> None: ...
    def listar(self, estado: EstadoCuenta | None = None) -> list[Usuario]: ...


class RepoSesiones(Protocol):
    def agregar(self, sesion: Sesion) -> Sesion: ...
    def por_hash(self, token_hash: bytes) -> Sesion | None: ...
    def guardar(self, sesion: Sesion) -> None: ...
    def revocar_de_usuario(self, usuario_id: int, ahora: datetime) -> int: ...


class RepoCodigosRecuperacion(Protocol):
    def reemplazar(self, usuario_id: int, hashes: list[str]) -> None: ...
    def consumir(self, usuario_id: int, codigo_hash: str, ahora: datetime) -> bool: ...


class RepoConfiguracion(Protocol):
    def obtener(self, clave: str, defecto: Any) -> Any: ...


@dataclass(frozen=True)
class EventoAuditoria:
    accion: str
    usuario_id: int | None = None
    objeto_tipo: str | None = None
    objeto_id: str | None = None
    exito: bool = True
    ip: str | None = None
    detalle: dict[str, Any] = field(default_factory=dict)


class RegistroAuditoria(Protocol):
    def registrar(self, evento: EventoAuditoria) -> None: ...


class UnidadDeTrabajo(Protocol):
    """Una transacción: o se guardan todos los cambios de un caso de uso, o ninguno."""
    usuarios: RepoUsuarios
    sesiones: RepoSesiones
    codigos_recuperacion: RepoCodigosRecuperacion
    configuracion: RepoConfiguracion
    auditoria: RegistroAuditoria

    def __enter__(self) -> Self: ...
    def __exit__(self, *exc: object) -> None: ...
    def confirmar(self) -> None: ...
    def revertir(self) -> None: ...


class FabricaUnidadDeTrabajo(Protocol):
    def __call__(self) -> UnidadDeTrabajo: ...
