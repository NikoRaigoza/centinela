"""Mapeo SQLAlchemy de las 20 tablas del esquema `centinela`.

El esquema lo crea la migración de Alembic (fuente de verdad). Estas clases deben coincidir con ella;
la prueba `test_esquema_sincronizado` lo verifica contra la base de datos real.
Son modelos de PERSISTENCIA: los repositorios los traducen a entidades del dominio.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    ARRAY,
    CHAR,
    BigInteger,
    Boolean,
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    Numeric,
    SmallInteger,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ENUM, INET, JSONB, TIMESTAMP, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

ESQUEMA = "centinela"
TS = TIMESTAMP(timezone=True)
AHORA = text("now()")


def _enum(nombre: str, *valores: str) -> ENUM:
    return ENUM(*valores, name=nombre, schema=ESQUEMA, create_type=False)


ROL_USUARIO = _enum("rol_usuario", "administrador", "usuario")
ESTADO_CUENTA = _enum("estado_cuenta", "pendiente", "activo", "rechazado", "desactivado")
ESTADO_BUZON = _enum("estado_buzon", "activo", "pausado", "revocado", "error")
MODO_CUARENTENA = _enum("modo_cuarentena", "solo_avisar", "cuarentena_automatica")
RESULTADO_AUTH = _enum("resultado_auth", "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror")
NIVEL_RIESGO = _enum("nivel_riesgo", "bajo", "medio", "alto")
AREA_RAZON = _enum("area_razon", "remitente", "autenticacion", "suplantacion", "contenido", "enlace", "adjunto")
GRAVEDAD = _enum("gravedad", "baja", "media", "alta")
TIPO_MODELO = _enum("tipo_modelo", "contenido", "enlaces")
CATEGORIA_ENTIDAD = _enum("categoria_entidad", "banco", "billetera_digital", "gobierno", "logistica", "comercio",
                          "telecomunicaciones", "servicios_publicos", "educacion", "otro")
ESTADO_CASO = _enum("estado_caso", "nuevo", "en_cuarentena", "liberado", "confirmado", "falso_positivo")
TIPO_EVENTO_CASO = _enum("tipo_evento_caso", "creado", "cuarentena", "aviso", "liberado", "confirmado",
                         "falso_positivo", "reabierto", "nota")
ETIQUETA_USUARIO = _enum("etiqueta_usuario", "phishing", "legitimo")
CANAL_AVISO = _enum("canal_aviso", "correo", "push")
ESTADO_AVISO = _enum("estado_aviso", "pendiente", "enviado", "fallido")
ROL_CHAT = _enum("rol_chat", "usuario", "asistente")
PROVEEDOR_IA = _enum("proveedor_ia", "gemini", "local")


class Base(DeclarativeBase):
    metadata = MetaData(schema=ESQUEMA)


def _id() -> Mapped[int]:
    return mapped_column(BigInteger, Identity(always=True), primary_key=True)


def _fk(destino: str, ondelete: str, nullable: bool = False) -> Mapped[Any]:
    return mapped_column(BigInteger, ForeignKey(f"{ESQUEMA}.{destino}", ondelete=ondelete), nullable=nullable)


# =====================================================================
# 1. Identidad y acceso
# =====================================================================
class UsuarioFila(Base):
    __tablename__ = "usuario"
    id: Mapped[int] = _id()
    correo: Mapped[str] = mapped_column(Text, unique=True)
    nombre: Mapped[str] = mapped_column(Text)
    clave_hash: Mapped[str] = mapped_column(Text)
    rol: Mapped[str] = mapped_column(ROL_USUARIO, server_default=text("'usuario'"))
    estado: Mapped[str] = mapped_column(ESTADO_CUENTA, server_default=text("'pendiente'"))
    totp_secreto_cifrado: Mapped[bytes | None] = mapped_column(LargeBinary)
    totp_activo: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    totp_ultimo_paso: Mapped[int | None] = mapped_column(BigInteger)
    intentos_fallidos: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"))
    bloqueado_hasta: Mapped[datetime | None] = mapped_column(TS)
    aprobado_por: Mapped[int | None] = _fk("usuario.id", "SET NULL", nullable=True)
    aprobado_en: Mapped[datetime | None] = mapped_column(TS)
    ultimo_acceso: Mapped[datetime | None] = mapped_column(TS)
    creado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)
    actualizado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)


class CodigoRecuperacionFila(Base):
    __tablename__ = "codigo_recuperacion"
    __table_args__ = (Index("codigo_recuperacion_usuario_idx", "usuario_id", postgresql_where=text("usado_en IS NULL")),)
    id: Mapped[int] = _id()
    usuario_id: Mapped[int] = _fk("usuario.id", "CASCADE")
    codigo_hash: Mapped[str] = mapped_column(Text)
    usado_en: Mapped[datetime | None] = mapped_column(TS)
    creado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)


class SesionFila(Base):
    __tablename__ = "sesion"
    __table_args__ = (Index("sesion_usuario_activa_idx", "usuario_id", postgresql_where=text("revocada_en IS NULL")),)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    usuario_id: Mapped[int] = _fk("usuario.id", "CASCADE")
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    ip: Mapped[str | None] = mapped_column(INET)
    agente: Mapped[str | None] = mapped_column(Text)
    creada_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)
    expira_en: Mapped[datetime] = mapped_column(TS)
    revocada_en: Mapped[datetime | None] = mapped_column(TS)


# =====================================================================
# 2. Buzones de Gmail
# =====================================================================
class BuzonFila(Base):
    __tablename__ = "buzon"
    __table_args__ = (
        Index("buzon_usuario_idx", "usuario_id"),
        Index("buzon_activos_idx", text("ultima_revision_en NULLS FIRST"), postgresql_where=text("estado = 'activo'")),
    )
    id: Mapped[int] = _id()
    usuario_id: Mapped[int] = _fk("usuario.id", "RESTRICT")
    correo_gmail: Mapped[str] = mapped_column(Text, unique=True)
    refresh_token_cifrado: Mapped[bytes | None] = mapped_column(LargeBinary)
    alcances: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    estado: Mapped[str] = mapped_column(ESTADO_BUZON, server_default=text("'activo'"))
    modo: Mapped[str] = mapped_column(MODO_CUARENTENA, server_default=text("'cuarentena_automatica'"))
    avisar_por_correo: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    ultimo_history_id: Mapped[Decimal | None] = mapped_column(Numeric(20, 0))
    etiqueta_cuarentena_id: Mapped[str | None] = mapped_column(Text)
    etiqueta_sospechoso_id: Mapped[str | None] = mapped_column(Text)
    ultima_revision_en: Mapped[datetime | None] = mapped_column(TS)
    errores_consecutivos: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"))
    ultimo_error: Mapped[str | None] = mapped_column(Text)
    conectado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)
    desconectado_en: Mapped[datetime | None] = mapped_column(TS)
    creado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)
    actualizado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)


# =====================================================================
# 3. Conocimiento: modelos de ML y entidades colombianas
# =====================================================================
class ModeloMlFila(Base):
    __tablename__ = "modelo_ml"
    __table_args__ = (
        UniqueConstraint("tipo", "version", name="modelo_version_unica"),
        Index("modelo_un_activo_por_tipo", "tipo", unique=True, postgresql_where=text("activo")),
    )
    id: Mapped[int] = _id()
    tipo: Mapped[str] = mapped_column(TIPO_MODELO)
    nombre: Mapped[str] = mapped_column(Text)
    version: Mapped[str] = mapped_column(Text)
    ruta_artefacto: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(CHAR(64))
    dataset: Mapped[str] = mapped_column(Text)
    metricas: Mapped[dict] = mapped_column(JSONB, server_default=text("'{}'"))
    umbral_medio: Mapped[Decimal] = mapped_column(Numeric(4, 3))
    umbral_alto: Mapped[Decimal] = mapped_column(Numeric(4, 3))
    activo: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    creado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)


class EntidadSuplantadaFila(Base):
    __tablename__ = "entidad_suplantada"
    id: Mapped[int] = _id()
    nombre: Mapped[str] = mapped_column(Text, unique=True)
    categoria: Mapped[str] = mapped_column(CATEGORIA_ENTIDAD)
    alias: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'"))
    activa: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    creado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)
    actualizado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)


class DominioOficialFila(Base):
    __tablename__ = "dominio_oficial"
    __table_args__ = (Index("dominio_oficial_entidad_idx", "entidad_id"),)
    id: Mapped[int] = _id()
    entidad_id: Mapped[int] = _fk("entidad_suplantada.id", "CASCADE")
    dominio: Mapped[str] = mapped_column(Text, unique=True)


# =====================================================================
# 4. Análisis de correos
# =====================================================================
class MensajeAnalizadoFila(Base):
    __tablename__ = "mensaje_analizado"
    __table_args__ = (
        UniqueConstraint("buzon_id", "gmail_id", name="mensaje_unico_por_buzon"),
        Index("mensaje_buzon_fecha_idx", "buzon_id", text("recibido_en DESC")),
        Index("mensaje_remitente_dominio_idx", "remitente_dominio"),
    )
    id: Mapped[int] = _id()
    buzon_id: Mapped[int] = _fk("buzon.id", "CASCADE")
    gmail_id: Mapped[str] = mapped_column(Text)
    gmail_hilo_id: Mapped[str | None] = mapped_column(Text)
    message_id_rfc: Mapped[str | None] = mapped_column(Text)
    remitente_correo: Mapped[str | None] = mapped_column(Text)
    remitente_nombre: Mapped[str | None] = mapped_column(Text)
    remitente_dominio: Mapped[str | None] = mapped_column(Text)
    responder_a_dominio: Mapped[str | None] = mapped_column(Text)
    asunto: Mapped[str | None] = mapped_column(Text)
    recibido_en: Mapped[datetime] = mapped_column(TS)
    analizado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)
    idioma: Mapped[str] = mapped_column(Text, server_default=text("'es'"))
    tamano_bytes: Mapped[int | None] = mapped_column(Integer)
    n_enlaces: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"))
    n_adjuntos: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"))
    spf: Mapped[str | None] = mapped_column(RESULTADO_AUTH)
    dkim: Mapped[str | None] = mapped_column(RESULTADO_AUTH)
    dmarc: Mapped[str | None] = mapped_column(RESULTADO_AUTH)


class AdjuntoAnalizadoFila(Base):
    __tablename__ = "adjunto_analizado"
    __table_args__ = (Index("adjunto_mensaje_idx", "mensaje_id"),)
    id: Mapped[int] = _id()
    mensaje_id: Mapped[int] = _fk("mensaje_analizado.id", "CASCADE")
    nombre: Mapped[str] = mapped_column(Text)
    extension: Mapped[str | None] = mapped_column(Text)
    tipo_mime: Mapped[str | None] = mapped_column(Text)
    tamano_bytes: Mapped[int | None] = mapped_column(Integer)
    sha256: Mapped[str | None] = mapped_column(CHAR(64))
    peligroso: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    motivo: Mapped[str | None] = mapped_column(Text)


class VeredictoFila(Base):
    __tablename__ = "veredicto"
    __table_args__ = (
        Index("veredicto_un_vigente", "mensaje_id", unique=True, postgresql_where=text("vigente")),
        Index("veredicto_nivel_idx", "nivel", postgresql_where=text("vigente")),
        Index("veredicto_modelo_contenido_idx", "modelo_contenido_id"),
        Index("veredicto_modelo_enlaces_idx", "modelo_enlaces_id"),
    )
    id: Mapped[int] = _id()
    mensaje_id: Mapped[int] = _fk("mensaje_analizado.id", "CASCADE")
    modelo_contenido_id: Mapped[int | None] = _fk("modelo_ml.id", "RESTRICT", nullable=True)
    modelo_enlaces_id: Mapped[int | None] = _fk("modelo_ml.id", "RESTRICT", nullable=True)
    p_contenido: Mapped[Decimal | None] = mapped_column(Numeric(5, 4))
    p_enlaces: Mapped[Decimal | None] = mapped_column(Numeric(5, 4))
    p_tecnico: Mapped[Decimal | None] = mapped_column(Numeric(5, 4))
    p_final: Mapped[Decimal] = mapped_column(Numeric(5, 4))
    nivel: Mapped[str] = mapped_column(NIVEL_RIESGO)
    resumen: Mapped[str] = mapped_column(Text)
    tiempo_ms: Mapped[int | None] = mapped_column(Integer)
    vigente: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    creado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)


class RazonFila(Base):
    __tablename__ = "razon"
    __table_args__ = (
        UniqueConstraint("veredicto_id", "orden", name="razon_orden_unico"),
        Index("razon_entidad_idx", "entidad_id", postgresql_where=text("entidad_id IS NOT NULL")),
    )
    id: Mapped[int] = _id()
    veredicto_id: Mapped[int] = _fk("veredicto.id", "CASCADE")
    orden: Mapped[int] = mapped_column(SmallInteger)
    area: Mapped[str] = mapped_column(AREA_RAZON)
    gravedad: Mapped[str] = mapped_column(GRAVEDAD)
    aporte: Mapped[Decimal | None] = mapped_column(Numeric(6, 4))
    texto: Mapped[str] = mapped_column(Text)
    mostrada: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    entidad_id: Mapped[int | None] = _fk("entidad_suplantada.id", "SET NULL", nullable=True)


class EnlaceAnalizadoFila(Base):
    __tablename__ = "enlace_analizado"
    __table_args__ = (Index("enlace_veredicto_idx", "veredicto_id"), Index("enlace_dominio_idx", "dominio"))
    id: Mapped[int] = _id()
    veredicto_id: Mapped[int] = _fk("veredicto.id", "CASCADE")
    dominio: Mapped[str] = mapped_column(Text)
    url_sha256: Mapped[str] = mapped_column(CHAR(64))
    dominio_texto_visible: Mapped[str | None] = mapped_column(Text)
    probabilidad: Mapped[Decimal | None] = mapped_column(Numeric(5, 4))
    nivel: Mapped[str | None] = mapped_column(NIVEL_RIESGO)
    es_acortador: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    enganoso: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))


# =====================================================================
# 5. Gestión: casos, avisos y retroalimentación
# =====================================================================
class CasoFila(Base):
    __tablename__ = "caso"
    __table_args__ = (
        Index("caso_abiertos_idx", "estado", text("creado_en DESC"),
              postgresql_where=text("estado = ANY (ARRAY['nuevo'::centinela.estado_caso, "
                                    "'en_cuarentena'::centinela.estado_caso])")),
    )
    id: Mapped[int] = _id()
    mensaje_id: Mapped[int] = mapped_column(BigInteger, ForeignKey(f"{ESQUEMA}.mensaje_analizado.id", ondelete="CASCADE"),
                                            unique=True)
    estado: Mapped[str] = mapped_column(ESTADO_CASO, server_default=text("'nuevo'"))
    creado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)
    actualizado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)
    cerrado_en: Mapped[datetime | None] = mapped_column(TS)


class EventoCasoFila(Base):
    __tablename__ = "evento_caso"
    __table_args__ = (
        Index("evento_caso_idx", "caso_id", "creado_en"),
        Index("evento_autor_idx", "autor_id", postgresql_where=text("autor_id IS NOT NULL")),
    )
    id: Mapped[int] = _id()
    caso_id: Mapped[int] = _fk("caso.id", "CASCADE")
    tipo: Mapped[str] = mapped_column(TIPO_EVENTO_CASO)
    estado_anterior: Mapped[str | None] = mapped_column(ESTADO_CASO)
    estado_nuevo: Mapped[str | None] = mapped_column(ESTADO_CASO)
    autor_id: Mapped[int | None] = _fk("usuario.id", "SET NULL", nullable=True)
    detalle: Mapped[str | None] = mapped_column(Text)
    creado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)


class AvisoFila(Base):
    __tablename__ = "aviso"
    __table_args__ = (
        UniqueConstraint("caso_id", "canal", name="aviso_unico_por_canal"),
        Index("aviso_pendientes_idx", "proximo_intento_en", postgresql_where=text("estado = 'pendiente'")),
    )
    id: Mapped[int] = _id()
    caso_id: Mapped[int] = _fk("caso.id", "CASCADE")
    canal: Mapped[str] = mapped_column(CANAL_AVISO)
    destino: Mapped[str] = mapped_column(Text)
    estado: Mapped[str] = mapped_column(ESTADO_AVISO, server_default=text("'pendiente'"))
    intentos: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"))
    proximo_intento_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)
    enviado_en: Mapped[datetime | None] = mapped_column(TS)
    referencia_externa: Mapped[str | None] = mapped_column(Text)
    ultimo_error: Mapped[str | None] = mapped_column(Text)
    creado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)


class RetroalimentacionFila(Base):
    __tablename__ = "retroalimentacion"
    __table_args__ = (
        UniqueConstraint("mensaje_id", "usuario_id", name="retro_una_por_usuario"),
        Index("retro_usuario_idx", "usuario_id"),
        Index("retro_por_validar_idx", "creado_en", postgresql_where=text("validada_en IS NULL")),
    )
    id: Mapped[int] = _id()
    mensaje_id: Mapped[int] = _fk("mensaje_analizado.id", "CASCADE")
    usuario_id: Mapped[int] = _fk("usuario.id", "CASCADE")
    etiqueta: Mapped[str] = mapped_column(ETIQUETA_USUARIO)
    comentario: Mapped[str | None] = mapped_column(Text)
    validada_por: Mapped[int | None] = _fk("usuario.id", "RESTRICT", nullable=True)
    validada_en: Mapped[datetime | None] = mapped_column(TS)
    creado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)


# =====================================================================
# 6. Asistente de IA
# =====================================================================
class ConversacionFila(Base):
    __tablename__ = "conversacion"
    __table_args__ = (
        Index("conversacion_usuario_idx", "usuario_id", text("actualizado_en DESC")),
        Index("conversacion_mensaje_idx", "mensaje_id", postgresql_where=text("mensaje_id IS NOT NULL")),
    )
    id: Mapped[int] = _id()
    usuario_id: Mapped[int] = _fk("usuario.id", "CASCADE")
    mensaje_id: Mapped[int | None] = _fk("mensaje_analizado.id", "SET NULL", nullable=True)
    titulo: Mapped[str | None] = mapped_column(Text)
    creado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)
    actualizado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)


class TurnoChatFila(Base):
    __tablename__ = "turno_chat"
    __table_args__ = (Index("turno_conversacion_idx", "conversacion_id", "creado_en"),)
    id: Mapped[int] = _id()
    conversacion_id: Mapped[int] = _fk("conversacion.id", "CASCADE")
    rol: Mapped[str] = mapped_column(ROL_CHAT)
    contenido: Mapped[str] = mapped_column(Text)
    proveedor: Mapped[str | None] = mapped_column(PROVEEDOR_IA)
    creado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)


# =====================================================================
# 7. Configuración y auditoría
# =====================================================================
class ConfiguracionFila(Base):
    __tablename__ = "configuracion"
    clave: Mapped[str] = mapped_column(Text, primary_key=True)
    valor: Mapped[Any] = mapped_column(JSONB)
    descripcion: Mapped[str] = mapped_column(Text)
    actualizado_por: Mapped[int | None] = _fk("usuario.id", "SET NULL", nullable=True)
    actualizado_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)


class AuditoriaFila(Base):
    __tablename__ = "auditoria"
    __table_args__ = (
        Index("auditoria_fecha_idx", text("ocurrido_en DESC")),
        Index("auditoria_usuario_idx", "usuario_id", text("ocurrido_en DESC")),
    )
    id: Mapped[int] = _id()
    ocurrido_en: Mapped[datetime] = mapped_column(TS, server_default=AHORA)
    usuario_id: Mapped[int | None] = mapped_column(BigInteger)      # sin FK a propósito
    accion: Mapped[str] = mapped_column(Text)
    objeto_tipo: Mapped[str | None] = mapped_column(Text)
    objeto_id: Mapped[str | None] = mapped_column(Text)
    exito: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    ip: Mapped[str | None] = mapped_column(INET)
    detalle: Mapped[dict] = mapped_column(JSONB, server_default=text("'{}'"))
