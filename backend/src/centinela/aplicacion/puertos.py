"""Puertos de salida: lo que la aplicación necesita del mundo exterior, sin saber cómo se implementa.

Los adaptadores (PostgreSQL, argon2, pyotp, Fernet, ...) implementan estas interfaces.
En las pruebas se reemplazan por versiones en memoria.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, Self

from centinela.dominio.buzon import Buzon, EtiquetasCentinela
from centinela.dominio.correo import CorreoParseado, Mensaje, ResumenMensaje
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


# ---------------------------------------------------------------------- correo (Gmail)
class ErrorProveedorCorreo(Exception):
    """Falla pasajera del proveedor (red, cuota, error 5xx). Se reintenta en la siguiente revisión."""


class AccesoCorreoRevocado(Exception):
    """El proveedor ya no acepta el permiso: hay que volver a conectar el buzón."""


class HistorialExpirado(Exception):
    """El punto de avance guardado es demasiado antiguo para el proveedor."""


class MensajeNoDisponible(Exception):
    """El mensaje ya no existe (lo borraron antes de poder leerlo)."""


class PermisoInsuficiente(Exception):
    """La persona no aceptó todos los permisos que Centinela necesita."""


@dataclass(frozen=True)
class CredencialCorreo:
    refresh_token: str
    alcances: list[str]


@dataclass(frozen=True)
class PerfilBuzon:
    correo: str
    history_id: int


@dataclass(frozen=True)
class CambiosBuzon:
    ids_nuevos: list[str]
    history_id: int


@dataclass(frozen=True)
class MensajeCrudo:
    gmail_id: str
    hilo_id: str | None
    recibido_en: datetime
    tamano_bytes: int
    etiquetas: list[str]
    crudo: bytes | None           # None si supera el tamaño máximo que se descarga


class AutorizacionCorreo(Protocol):
    def url_autorizacion(self, estado: str, reto_pkce: str) -> str: ...
    def intercambiar_codigo(self, codigo: str, verificador_pkce: str) -> CredencialCorreo: ...
    def revocar(self, refresh_token: str) -> None: ...


class ClienteCorreo(Protocol):
    def perfil(self) -> PerfilBuzon: ...
    def asegurar_etiquetas(self) -> EtiquetasCentinela: ...
    def nuevos_desde(self, history_id: int) -> CambiosBuzon: ...
    def recientes(self, maximo: int) -> list[str]: ...
    def obtener(self, gmail_id: str) -> MensajeCrudo: ...
    def modificar_etiquetas(self, gmail_id: str, agregar: list[str], quitar: list[str]) -> None: ...
    def insertar(self, crudo: bytes, etiquetas: list[str]) -> str: ...


class ProveedorCorreo(Protocol):
    def abrir(self, refresh_token: str) -> ClienteCorreo: ...


class LectorCorreo(Protocol):
    def leer(self, crudo: bytes) -> CorreoParseado: ...


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


class RepoBuzones(Protocol):
    def por_id(self, buzon_id: int) -> Buzon | None: ...
    def por_correo(self, correo_gmail: str) -> Buzon | None: ...
    def de_usuario(self, usuario_id: int) -> list[Buzon]: ...
    def todos(self) -> list[Buzon]: ...
    def agregar(self, buzon: Buzon) -> Buzon: ...
    def guardar(self, buzon: Buzon) -> None: ...
    def reclamar_pendientes(self, revisados_antes_de: datetime, ahora: datetime, limite: int) -> list[int]:
        """Marca y devuelve buzones activos que tocan revisar. Seguro con varios workers a la vez."""
        ...


class RepoMensajes(Protocol):
    def existe(self, buzon_id: int, gmail_id: str) -> bool: ...
    def agregar(self, mensaje: Mensaje) -> int | None:
        """Guarda el mensaje; devuelve None si ya estaba (idempotente)."""
        ...
    def recientes(self, buzon_id: int, limite: int) -> list[ResumenMensaje]: ...


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
    buzones: RepoBuzones
    mensajes: RepoMensajes
    configuracion: RepoConfiguracion
    auditoria: RegistroAuditoria

    def __enter__(self) -> Self: ...
    def __exit__(self, *exc: object) -> None: ...
    def confirmar(self) -> None: ...
    def revertir(self) -> None: ...


class FabricaUnidadDeTrabajo(Protocol):
    def __call__(self) -> UnidadDeTrabajo: ...
