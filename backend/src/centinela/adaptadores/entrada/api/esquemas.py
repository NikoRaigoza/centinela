"""Contratos JSON de la API (lo que ve React). Separados de las entidades del dominio a propósito."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from centinela.aplicacion.casos_uso.buzones import ResumenRevision
from centinela.dominio.buzon import Buzon, ModoCuarentena
from centinela.dominio.correo import ResumenMensaje
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


# ---------------------------------------------------------------------- buzones
class UrlAutorizacion(BaseModel):
    url: str


class BuzonPublico(BaseModel):
    id: int
    usuario_id: int
    correo_gmail: str
    estado: str
    modo: str
    avisar_por_correo: bool
    ultima_revision_en: datetime | None
    ultimo_error: str | None
    conectado_en: datetime

    @classmethod
    def desde(cls, b: Buzon) -> BuzonPublico:
        return cls(id=b.id, usuario_id=b.usuario_id, correo_gmail=b.correo_gmail, estado=b.estado.value,
                   modo=b.modo.value, avisar_por_correo=b.avisar_por_correo, ultima_revision_en=b.ultima_revision_en,
                   ultimo_error=b.ultimo_error, conectado_en=b.conectado_en)


class CambiosBuzon(BaseModel):
    modo: ModoCuarentena | None = None
    avisar_por_correo: bool | None = None
    pausado: bool | None = None


class ResumenRevisionPublico(BaseModel):
    buzon_id: int
    nuevos: int
    omitidos: int
    estado: str
    error: str | None

    @classmethod
    def desde(cls, r: ResumenRevision) -> ResumenRevisionPublico:
        return cls(buzon_id=r.buzon_id, nuevos=r.nuevos, omitidos=r.omitidos, estado=r.estado, error=r.error)


class MensajePublico(BaseModel):
    id: int
    recibido_en: datetime
    remitente_nombre: str | None
    remitente_correo: str | None
    asunto: str | None
    n_enlaces: int
    n_adjuntos: int
    spf: str | None
    dkim: str | None
    dmarc: str | None

    @classmethod
    def desde(cls, m: ResumenMensaje) -> MensajePublico:
        valor = lambda r: r.value if r else None  # noqa: E731
        return cls(id=m.id, recibido_en=m.recibido_en, remitente_nombre=m.remitente_nombre,
                   remitente_correo=m.remitente_correo, asunto=m.asunto, n_enlaces=m.n_enlaces, n_adjuntos=m.n_adjuntos,
                   spf=valor(m.spf), dkim=valor(m.dkim), dmarc=valor(m.dmarc))


# ---------------------------------------------------------------------- análisis y casos
class RazonPublica(BaseModel):
    area: str
    gravedad: str
    texto: str


class EnlacePublico(BaseModel):
    dominio: str
    probabilidad: float | None


class ComponentesRiesgo(BaseModel):
    contenido: float | None
    enlaces: float | None
    tecnico: float | None


class AnalisisPublico(BaseModel):
    remitente: str
    asunto: str
    idioma: str
    nivel: str
    probabilidad: float
    resumen: str
    razones: list[RazonPublica]                 # máximo 3: lo que vería el usuario
    todas_las_razones: list[RazonPublica]
    senales_positivas: list[str]
    componentes: ComponentesRiesgo
    enlaces: list[EnlacePublico]
    tiempo_ms: int | None
    modelo_contenido_id: int | None
    modelo_enlaces_id: int | None


class CasoPublico(BaseModel):
    id: int
    estado: str
    nivel: str
    probabilidad: float
    resumen: str
    razones: list[str]
    buzon: str
    remitente_nombre: str | None
    remitente_correo: str | None
    asunto: str | None
    recibido_en: datetime
    puede_liberarse: bool


class EventoPublico(BaseModel):
    tipo: str
    fecha: datetime
    autor: str | None
    detalle: str | None


class DetalleCasoPublico(CasoPublico):
    spf: str | None
    dkim: str | None
    dmarc: str | None
    todas_las_razones: list[RazonPublica]
    enlaces: list[EnlacePublico]
    adjuntos: list[str]
    historial: list[EventoPublico]


class SolicitudClasificacion(BaseModel):
    decision: str = Field(pattern="^(confirmar|falso_positivo|reabrir)$")
    comentario: str | None = Field(default=None, max_length=1000)


class SolicitudNota(BaseModel):
    texto: str = Field(min_length=1, max_length=2000)
