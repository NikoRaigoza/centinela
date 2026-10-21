"""Contratos JSON de la API (lo que ve React). Separados de las entidades del dominio a propósito."""
from __future__ import annotations

import hashlib
from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, Field

from centinela.aplicacion.casos_uso.asistente import RespuestaAsistente
from centinela.aplicacion.casos_uso.buzones import ResumenRevision
from centinela.aplicacion.puertos import Conversacion, EstadisticasPanel, ModeloRegistrado, SuscripcionPush
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
    consentimiento_version: str | None = None
    consentimiento_en: datetime | None = None
    debe_cambiar_clave: bool = False

    @classmethod
    def desde(cls, u: Usuario) -> UsuarioPublico:
        return cls(id=u.id, correo=u.correo, nombre=u.nombre, rol=u.rol.value, estado=u.estado.value,
                   totp_activo=u.totp_activo, ultimo_acceso=u.ultimo_acceso, creado_en=u.creado_en,
                   consentimiento_version=u.consentimiento_version, consentimiento_en=u.consentimiento_en,
                   debe_cambiar_clave=u.debe_cambiar_clave)


class SolicitudRegistro(BaseModel):
    correo: str = Field(max_length=254)
    nombre: str = Field(max_length=120)
    clave: str = Field(max_length=128)
    acepta_politica: bool = False      # autorización del tratamiento de datos (Ley 1581): obligatoria


class SolicitudClaveNueva(BaseModel):
    nueva: str = Field(max_length=128)


class SolicitudEliminarCuenta(BaseModel):
    clave: str = Field(max_length=128)


class ClaveTemporal(BaseModel):
    clave_temporal: str


class InfoLegal(BaseModel):
    version_politica: str
    responsable: str
    correo_contacto: str | None
    dias_sin_riesgo: int
    dias_casos: int


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
    paso: str                                   # completo | verificar_2fa | configurar_2fa | cambiar_clave
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
    tiempo_real: bool = False         # Gmail avisa al instante de los correos nuevos (Pub/Sub)

    @classmethod
    def desde(cls, b: Buzon, ahora: datetime | None = None) -> BuzonPublico:
        return cls(id=b.id, usuario_id=b.usuario_id, correo_gmail=b.correo_gmail, estado=b.estado.value,
                   modo=b.modo.value, avisar_por_correo=b.avisar_por_correo, ultima_revision_en=b.ultima_revision_en,
                   ultimo_error=b.ultimo_error, conectado_en=b.conectado_en,
                   tiempo_real=ahora is not None and b.en_tiempo_real(ahora))


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
    enganoso: bool = False          # el texto visible muestra otro dominio
    origen: str = "cuerpo"          # cuerpo | qr (leído de un código QR) | adjunto (dentro de un PDF o página adjunta)


class AdjuntoPublico(BaseModel):
    nombre: str
    tipo_mime: str | None = None
    tamano_bytes: int | None = None
    peligroso: bool = False
    motivo: str | None = None


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
    adjuntos: list[AdjuntoPublico] = []
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
    adjuntos: list[AdjuntoPublico]
    historial: list[EventoPublico]


class SolicitudClasificacion(BaseModel):
    decision: str = Field(pattern="^(confirmar|falso_positivo|reabrir)$")
    comentario: str | None = Field(default=None, max_length=1000)


class SolicitudNota(BaseModel):
    texto: str = Field(min_length=1, max_length=2000)


# ---------------------------------------------------------------------- panel y modelos
class DiaPublico(BaseModel):
    fecha: date
    revisados: int
    sospechosos: int
    peligrosos: int


class EntidadFrecuente(BaseModel):
    nombre: str
    correos: int


class ResumenPanelPublico(BaseModel):
    dias: int
    revisados: int
    sospechosos: int
    peligrosos: int
    casos_por_estado: dict[str, int]
    entidades_suplantadas: list[EntidadFrecuente]
    serie: list[DiaPublico]

    @classmethod
    def desde(cls, e: EstadisticasPanel) -> ResumenPanelPublico:
        return cls(dias=len(e.serie), revisados=e.revisados, sospechosos=e.por_nivel.get("medio", 0),
                   peligrosos=e.por_nivel.get("alto", 0), casos_por_estado=e.casos_por_estado,
                   entidades_suplantadas=[EntidadFrecuente(nombre=n, correos=c) for n, c in e.entidades_suplantadas],
                   serie=[DiaPublico(fecha=d.fecha, revisados=d.revisados, sospechosos=d.sospechosos,
                                     peligrosos=d.peligrosos) for d in e.serie])


class ModeloPublico(BaseModel):
    id: int
    tipo: str
    nombre: str
    version: str
    dataset: str
    sha256: str
    umbral_medio: float
    umbral_alto: float
    activo: bool
    metricas: dict[str, Any]
    creado_en: datetime | None

    @classmethod
    def desde(cls, m: ModeloRegistrado) -> ModeloPublico:
        return cls(id=m.id, tipo=m.tipo, nombre=m.nombre, version=m.version, dataset=m.dataset, sha256=m.sha256,
                   umbral_medio=m.umbral_medio, umbral_alto=m.umbral_alto, activo=m.activo, metricas=m.metricas,
                   creado_en=m.creado_en)


# ---------------------------------------------------------------------- notificaciones push
class LlavesSuscripcion(BaseModel):
    p256dh: str = Field(max_length=120)
    auth: str = Field(max_length=40)


class SolicitudSuscripcion(BaseModel):
    """Lo que entrega `PushSubscription.toJSON()` en el navegador."""
    endpoint: str = Field(max_length=1024)
    keys: LlavesSuscripcion


class SolicitudQuitarSuscripcion(BaseModel):
    endpoint: str = Field(max_length=1024)


class ConfiguracionPush(BaseModel):
    disponible: bool
    clave_publica: str | None


class DispositivoPush(BaseModel):
    id: int
    dispositivo: str
    creado_en: datetime | None
    ultimo_envio_en: datetime | None
    endpoint_hash: str           # para que el navegador reconozca su propia suscripción sin exponer la dirección

    @classmethod
    def desde(cls, s: SuscripcionPush) -> DispositivoPush:
        return cls(id=s.id, dispositivo=s.dispositivo or "Navegador", creado_en=s.creado_en,
                   ultimo_envio_en=s.ultimo_envio_en, endpoint_hash=hashlib.sha256(s.endpoint.encode()).hexdigest()[:16])


class ResultadoPrueba(BaseModel):
    entregados: int
    vencidas: int
    errores: int


# ---------------------------------------------------------------------- asistente de IA
class SolicitudPregunta(BaseModel):
    pregunta: str = Field(min_length=1, max_length=1000)
    conversacion_id: int | None = None
    caso_id: int | None = None


class TurnoPublico(BaseModel):
    rol: str
    contenido: str
    proveedor: str | None
    creado_en: datetime


class RespuestaPublica(BaseModel):
    conversacion_id: int
    turno: TurnoPublico
    aviso: str | None
    restantes_ia: int

    @classmethod
    def desde(cls, r: RespuestaAsistente) -> RespuestaPublica:
        return cls(conversacion_id=r.conversacion_id, aviso=r.aviso, restantes_ia=r.restantes_ia,
                   turno=TurnoPublico(rol="asistente", contenido=r.contenido, proveedor=r.proveedor, creado_en=r.creado_en))


class ConversacionPublica(BaseModel):
    id: int
    titulo: str
    caso_id: int | None
    creado_en: datetime
    actualizado_en: datetime

    @classmethod
    def desde(cls, c: Conversacion) -> ConversacionPublica:
        return cls(id=c.id, titulo=c.titulo or "Conversación", caso_id=c.caso_id, creado_en=c.creado_en,
                   actualizado_en=c.actualizado_en)


class ConversacionDetalle(ConversacionPublica):
    turnos: list[TurnoPublico]


class EstadoAsistentePublico(BaseModel):
    ia_disponible: bool
    proveedor: str
    limite_ia: int
    restantes_ia: int
    sugerencias_generales: list[str]
    sugerencias_caso: list[str]
