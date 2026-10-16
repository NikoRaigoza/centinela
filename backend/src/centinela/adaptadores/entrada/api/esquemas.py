"""Contratos JSON de la API (lo que ve React). Separados de las entidades del dominio a propósito."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from centinela.dominio.usuario import Usuario


class UsuarioPublico(BaseModel):
    id: int
    correo: str
    nombre: str
    rol: str
    estado: str
    totp_activo: bool
    ultimo_acceso: datetime | None
    creado_en: datetime | None

    @classmethod
    def desde(cls, u: Usuario) -> UsuarioPublico:
        return cls(id=u.id, correo=u.correo, nombre=u.nombre, rol=u.rol.value, estado=u.estado.value,
                   totp_activo=u.totp_activo, ultimo_acceso=u.ultimo_acceso, creado_en=u.creado_en)


class SolicitudRegistro(BaseModel):
    correo: str = Field(max_length=254)
    nombre: str = Field(max_length=120)
    clave: str = Field(max_length=128)


class SolicitudInicio(BaseModel):
    correo: str = Field(max_length=254)
    clave: str = Field(max_length=128)


class SolicitudCodigo(BaseModel):
    codigo: str = Field(min_length=6, max_length=20)


class SolicitudCambioClave(BaseModel):
    actual: str = Field(max_length=128)
    nueva: str = Field(max_length=128)


class Mensaje(BaseModel):
    mensaje: str


class TokenAcceso(BaseModel):
    token_acceso: str
    tipo: str = "bearer"
    expira_en_s: int
    usuario: UsuarioPublico


class RespuestaInicio(BaseModel):
    paso: str                                   # completo | verificar_2fa | configurar_2fa
    acceso: TokenAcceso | None = None
    token_desafio: str | None = None


class Configuracion2FA(BaseModel):
    secreto: str
    uri: str                                    # se muestra como código QR en el panel


class Activacion2FA(BaseModel):
    codigos_recuperacion: list[str]
    acceso: TokenAcceso | None = None


class Error(BaseModel):
    codigo: str
    mensaje: str
