"""Correo leído y listo para analizar. Solo datos: no conoce Gmail ni el formato MIME."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class ResultadoAuth(StrEnum):
    PASS = "pass"  # noqa: S105 - resultado de SPF/DKIM/DMARC, no es una contraseña
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"

    @classmethod
    def interpretar(cls, valor: str | None) -> ResultadoAuth | None:
        try:
            return cls((valor or "").strip().lower())
        except ValueError:
            return None


@dataclass(frozen=True)
class Autenticacion:
    spf: ResultadoAuth | None = None
    dkim: ResultadoAuth | None = None
    dmarc: ResultadoAuth | None = None
    dkim_dominio: str | None = None
    confiable: bool = False      # True si la puso el servidor de Google y no el remitente


@dataclass(frozen=True)
class Enlace:
    url: str
    texto_visible: str = ""


@dataclass(frozen=True)
class Adjunto:
    nombre: str
    tipo_mime: str
    tamano_bytes: int
    sha256: str | None = None

    @property
    def extension(self) -> str | None:
        partes = self.nombre.rsplit(".", 1)
        return partes[1].lower()[:20] if len(partes) == 2 and partes[1] else None


@dataclass(frozen=True)
class CorreoParseado:
    asunto: str
    remitente_nombre: str
    remitente_correo: str
    remitente_dominio: str
    cuerpo: str
    message_id: str | None = None
    fecha: datetime | None = None
    responder_a_dominio: str | None = None
    ruta_retorno_dominio: str | None = None
    autenticacion: Autenticacion = field(default_factory=Autenticacion)
    saltos: int = 0
    enlaces: tuple[Enlace, ...] = ()
    adjuntos: tuple[Adjunto, ...] = ()
    es_aviso_centinela: bool = False


@dataclass
class Mensaje:
    """Un correo recibido en un buzón vigilado. Nunca guarda el cuerpo."""
    buzon_id: int
    gmail_id: str
    recibido_en: datetime
    gmail_hilo_id: str | None = None
    tamano_bytes: int | None = None
    correo: CorreoParseado | None = None      # None si era demasiado grande para leerlo
    id: int | None = None


@dataclass(frozen=True)
class ResumenMensaje:
    """Lo que se muestra de un mensaje en el panel (lo guardado en la BD, sin cuerpo)."""
    id: int
    gmail_id: str
    recibido_en: datetime
    remitente_nombre: str | None
    remitente_correo: str | None
    asunto: str | None
    n_enlaces: int
    n_adjuntos: int
    spf: ResultadoAuth | None
    dkim: ResultadoAuth | None
    dmarc: ResultadoAuth | None
