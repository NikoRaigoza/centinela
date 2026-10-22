"""Puertos de salida: lo que la aplicación necesita del mundo exterior, sin saber cómo se implementa.

Los adaptadores (PostgreSQL, argon2, pyotp, Fernet, ...) implementan estas interfaces.
En las pruebas se reemplazan por versiones en memoria.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from enum import StrEnum
from typing import Any, Protocol, Self

from centinela.dominio.buzon import Buzon, EtiquetasCentinela
from centinela.dominio.caso import Caso
from centinela.dominio.correo import CorreoParseado, Mensaje, ResumenMensaje
from centinela.dominio.entidades import CatalogoEntidades
from centinela.dominio.riesgo import Razon, Veredicto
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
class Vigilancia:
    """Respuesta de Gmail al pedir avisos en tiempo real (users.watch)."""
    history_id: int
    expira_en: datetime


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
    def vigilar(self, tema: str) -> Vigilancia:
        """Pide a Gmail que publique en el tema de Pub/Sub cada vez que llegue algo a la bandeja de entrada."""
        ...


class ProveedorCorreo(Protocol):
    def abrir(self, refresh_token: str) -> ClienteCorreo: ...


class LectorCorreo(Protocol):
    def leer(self, crudo: bytes) -> CorreoParseado: ...


class AvisoNoAutentico(Exception):
    """La notificación no la firmó Google con la cuenta de servicio configurada."""


class VerificadorAvisosGmail(Protocol):
    def verificar(self, token: str) -> None:
        """Valida el token OIDC que Pub/Sub adjunta a cada notificación. Lanza AvisoNoAutentico si no es válido."""
        ...


# ---------------------------------------------------------------------- modelos de machine learning
@dataclass(frozen=True)
class EvaluacionContenido:
    probabilidad: float           # calibrada
    razones: list[Razon]
    idioma: str
    umbral_medio: float = 0.3     # puntos de operación del modelo (FP ≤ 5 % y ≤ 1 % en legítimos), de su manifiesto
    umbral_alto: float = 0.7


@dataclass(frozen=True)
class EvaluacionEnlace:
    url: str
    dominio: str
    probabilidad: float | None        # None si el modelo no aplica (p. ej. enlace acortado)
    dominio_visible: str | None = None   # el dominio que muestra el texto del enlace, si es distinto del real
    enganoso: bool = False
    origen: str = "cuerpo"               # cuerpo | qr | adjunto


class ClasificadorContenido(Protocol):
    modelo_id: int | None
    def evaluar(self, asunto: str, cuerpo: str) -> EvaluacionContenido | None:
        """None si no hay un modelo para el idioma del correo o el texto es muy corto."""
        ...


class ClasificadorEnlaces(Protocol):
    modelo_id: int | None
    def evaluar(self, urls: list[str]) -> list[EvaluacionEnlace]: ...


class ProveedorModelos(Protocol):
    """Entrega los modelos ACTIVOS del registro (tabla modelo_ml), verificando la integridad de sus archivos."""
    def contenido(self) -> ClasificadorContenido | None: ...
    def enlaces(self) -> ClasificadorEnlaces | None: ...


# ---------------------------------------------------------------------- avisos
@dataclass(frozen=True)
class DatosAviso:
    destinatario: str
    nivel: str
    remitente: str
    asunto: str
    resumen: str
    razones: list[str]
    accion: str               # lo que hizo Centinela (cuarentena, etiqueta, nada)
    caso_id: int | None = None   # para enlazar directo al caso en el panel
    en_cuarentena: bool = False


class RedactorAvisos(Protocol):
    def redactar(self, datos: DatosAviso) -> bytes:
        """Mensaje MIME listo para insertar en el buzón, firmado para que Centinela no se analice a sí mismo."""
        ...


@dataclass(frozen=True)
class SuscripcionPush:
    """Un navegador donde la persona activó las notificaciones (estándar Web Push)."""
    id: int
    usuario_id: int
    endpoint: str
    p256dh: str
    auth: str
    dispositivo: str | None = None
    creado_en: datetime | None = None
    ultimo_envio_en: datetime | None = None


class ResultadoPush(StrEnum):
    ENTREGADO = "entregado"
    VENCIDA = "vencida"      # el navegador ya no acepta la suscripción: se borra
    ERROR = "error"          # falla pasajera: se reintenta


class EnviadorPush(Protocol):
    clave_publica: str       # llave VAPID que el navegador necesita para suscribirse
    def enviar(self, suscripcion: SuscripcionPush, carga: dict) -> ResultadoPush: ...


# ---------------------------------------------------------------------- asistente de IA
class IANoDisponible(Exception):
    """El proveedor de IA no respondió (sin clave, sin red, cuota agotada). Se responde en modo local."""


@dataclass(frozen=True)
class TurnoIA:
    rol: str                 # "usuario" | "asistente"
    texto: str


class ModeloLenguaje(Protocol):
    proveedor: str           # valor del enum proveedor_ia de la BD
    def responder(self, instrucciones: str, contexto: str, historial: list[TurnoIA], pregunta: str) -> str: ...


# ---------------------------------------------------------------------- persistencia
class RepoUsuarios(Protocol):
    def por_id(self, usuario_id: int) -> Usuario | None: ...
    def por_correo(self, correo: str) -> Usuario | None: ...
    def agregar(self, usuario: Usuario) -> Usuario: ...
    def guardar(self, usuario: Usuario) -> None: ...
    def listar(self, estado: EstadoCuenta | None = None) -> list[Usuario]: ...
    def administradores_activos(self) -> int: ...
    def eliminar(self, usuario_id: int) -> None:
        """Borra a la persona con todos sus datos (buzones, casos, sesiones...). La auditoría se conserva."""
        ...


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
    def reclamar_pendientes(self, revisados_antes_de: datetime, ahora: datetime, limite: int,
                            respaldo_antes_de: datetime | None = None,
                            reintento_antes_de: datetime | None = None) -> list[int]:
        """Marca y devuelve buzones activos que tocan revisar, y los que están en ERROR con el permiso intacto
        cuya última revisión es anterior a reintento_antes_de. Seguro con varios workers a la vez."""
        ...
    def solicitar_revision(self, buzon_id: int, ahora: datetime) -> None:
        """Gmail avisó de un correo nuevo: el buzón se revisa en el siguiente ciclo y se despierta al worker."""
        ...
    def por_vigilar(self, renovar_antes_de: datetime, limite: int) -> list[Buzon]:
        """Buzones activos sin avisos en tiempo real o cuyo permiso de avisos vence pronto."""
        ...


class RepoMensajes(Protocol):
    def existe(self, buzon_id: int, gmail_id: str) -> bool: ...
    def agregar(self, mensaje: Mensaje, idioma: str = "es") -> int | None:
        """Guarda el mensaje; devuelve None si ya estaba (idempotente)."""
        ...
    def recientes(self, buzon_id: int, limite: int) -> list[ResumenMensaje]: ...
    def remitente_conocido(self, buzon_id: int, remitente_correo: str) -> bool:
        """¿Ese remitente ya había escrito antes a este buzón? (para detectar fraudes de suplantación)."""
        ...


@dataclass(frozen=True)
class ModeloRegistrado:
    id: int
    tipo: str
    nombre: str
    version: str
    ruta: str
    sha256: str
    dataset: str
    umbral_medio: float
    umbral_alto: float
    activo: bool
    metricas: dict[str, Any]
    creado_en: datetime | None = None


class RepoModelos(Protocol):
    def activo(self, tipo: str) -> ModeloRegistrado | None: ...
    def listar(self) -> list[ModeloRegistrado]: ...
    def registrar(self, modelo: ModeloRegistrado, activar: bool) -> ModeloRegistrado: ...


class RepoEntidades(Protocol):
    def catalogo(self) -> CatalogoEntidades: ...


@dataclass(frozen=True)
class ResultadoAnalisis:
    veredicto: Veredicto
    enlaces: list[EvaluacionEnlace]
    positivas: list[str]
    idioma: str
    modelo_contenido_id: int | None = None
    modelo_enlaces_id: int | None = None


class RepoAnalisis(Protocol):
    def guardar(self, mensaje_id: int, resultado: ResultadoAnalisis) -> int: ...


@dataclass(frozen=True)
class ContextoCaso:
    """Lo necesario para autorizar y actuar sobre un caso en Gmail."""
    caso_id: int
    usuario_id: int
    buzon_id: int
    gmail_id: str
    mensaje_id: int


@dataclass(frozen=True)
class ResumenCaso:
    id: int
    estado: str
    creado_en: datetime
    buzon_correo: str
    remitente_nombre: str | None
    remitente_correo: str | None
    asunto: str | None
    recibido_en: datetime
    nivel: str
    p_final: float
    resumen: str
    razones: list[str]


@dataclass(frozen=True)
class EnlaceGuardado:
    dominio: str
    probabilidad: float | None
    enganoso: bool
    origen: str = "cuerpo"


@dataclass(frozen=True)
class AdjuntoGuardado:
    nombre: str
    tipo_mime: str | None
    tamano_bytes: int | None
    peligroso: bool = False
    motivo: str | None = None


@dataclass(frozen=True)
class EventoGuardado:
    tipo: str
    creado_en: datetime
    autor: str | None
    detalle: str | None


@dataclass(frozen=True)
class DetalleCaso:
    resumen: ResumenCaso
    spf: str | None
    dkim: str | None
    dmarc: str | None
    todas_las_razones: list[Razon]
    enlaces: list[EnlaceGuardado]
    adjuntos: list[AdjuntoGuardado]
    eventos: list[EventoGuardado]


class RepoCasos(Protocol):
    def agregar(self, caso: Caso) -> Caso: ...
    def por_id(self, caso_id: int) -> Caso | None: ...
    def guardar(self, caso: Caso) -> None: ...
    def contexto(self, caso_id: int) -> ContextoCaso | None: ...
    def listar(self, usuario_id: int, estados: list[str] | None, limite: int, desde: int) -> list[ResumenCaso]: ...
    def del_periodo(self, usuario_id: int, desde: datetime, hasta: datetime, limite: int) -> list[ResumenCaso]:
        """Casos de los correos recibidos en el periodo, del más reciente al más antiguo."""
        ...
    def detalle(self, caso_id: int) -> DetalleCaso | None: ...



# ---------------------------------------------------------------------- panel
@dataclass(frozen=True)
class DiaPanel:
    fecha: date
    revisados: int
    sospechosos: int            # nivel medio
    peligrosos: int             # nivel alto


@dataclass(frozen=True)
class EstadisticasPanel:
    revisados: int
    por_nivel: dict[str, int]
    casos_por_estado: dict[str, int]                # estado actual de TODOS los casos (no solo del periodo)
    entidades_suplantadas: list[tuple[str, int]]    # (entidad, correos de riesgo que la suplantaron)
    serie: list[DiaPanel]                           # puede venir con huecos: el caso de uso los rellena


class RepoEstadisticas(Protocol):
    def panel(self, usuario_id: int | None, desde: datetime, zona: str) -> EstadisticasPanel:
        """usuario_id None: todos los buzones (reporte de la organización, solo cifras)."""
        ...
    def indicadores(self, usuario_id: int | None, desde: datetime) -> dict[str, int]:
        """Correos de riesgo por área de la razón principal, más enlaces de QR y adjuntos peligrosos."""
        ...
    def por_buzon(self, desde: datetime) -> list[FilaBuzonReporte]: ...


# ---------------------------------------------------------------------- reportes
@dataclass(frozen=True)
class FilaBuzonReporte:
    correo: str
    estado: str
    revisados: int
    sospechosos: int
    peligrosos: int


@dataclass(frozen=True)
class DatosReporte:
    """Todo lo que lleva un reporte. El de la organización (admin) no incluye asuntos ni remitentes: solo cifras."""
    titulo: str
    alcance: str
    persona: str
    generado_en: datetime
    desde: date
    hasta: date
    estadisticas: EstadisticasPanel
    indicadores: dict[str, int]
    organizacion: bool = False
    casos: list[ResumenCaso] = field(default_factory=list)
    casos_truncados: bool = False
    buzones: list[FilaBuzonReporte] = field(default_factory=list)
    modelos: list[ModeloRegistrado] = field(default_factory=list)


class GeneradorReportes(Protocol):
    def pdf(self, datos: DatosReporte) -> bytes: ...
    def excel(self, datos: DatosReporte) -> bytes: ...


@dataclass(frozen=True)
class AvisoPendiente:
    id: int
    caso_id: int
    buzon_id: int
    intentos: int
    datos: DatosAviso
    canal: str = "correo"
    usuario_id: int | None = None


class RepoAvisos(Protocol):
    def agregar(self, caso_id: int, canal: str, destino: str) -> None: ...
    def reclamar_pendientes(self, ahora: datetime, limite: int, canales: list[str]) -> list[AvisoPendiente]: ...
    def marcar_enviado(self, aviso_id: int, ahora: datetime, referencia: str) -> None: ...
    def registrar_fallo(self, aviso_id: int, error: str, proximo_intento: datetime | None) -> None: ...


class RepoSuscripcionesPush(Protocol):
    def guardar(self, usuario_id: int, endpoint: str, p256dh: str, auth: str, dispositivo: str | None) -> None:
        """Crea o actualiza (si el mismo navegador ya estaba suscrito, pasa a ser de este usuario)."""
        ...
    def de_usuario(self, usuario_id: int) -> list[SuscripcionPush]: ...
    def eliminar(self, usuario_id: int, suscripcion_id: int | None = None, endpoint: str | None = None) -> bool: ...
    def eliminar_vencida(self, suscripcion_id: int) -> None: ...
    def marcar_envio(self, suscripcion_id: int, ahora: datetime) -> None: ...


@dataclass(frozen=True)
class Conversacion:
    id: int
    usuario_id: int
    titulo: str | None
    mensaje_id: int | None
    caso_id: int | None          # caso del correo, si la conversación se abrió desde uno
    creado_en: datetime
    actualizado_en: datetime


@dataclass(frozen=True)
class TurnoChat:
    rol: str
    contenido: str
    proveedor: str | None
    creado_en: datetime


class RepoConversaciones(Protocol):
    def crear(self, usuario_id: int, mensaje_id: int | None, titulo: str) -> int: ...
    def por_id(self, conversacion_id: int) -> Conversacion | None: ...
    def de_usuario(self, usuario_id: int, limite: int) -> list[Conversacion]: ...
    def turnos(self, conversacion_id: int, ultimos: int | None = None) -> list[TurnoChat]: ...
    def agregar_turno(self, conversacion_id: int, rol: str, contenido: str, proveedor: str | None) -> None: ...
    def eliminar(self, conversacion_id: int) -> None: ...
    def respuestas_ia_desde(self, usuario_id: int, desde: datetime) -> int:
        """Respuestas del proveedor de IA externo que recibió el usuario desde esa fecha (para el límite diario)."""
        ...
    def preguntas_desde(self, usuario_id: int, desde: datetime) -> int: ...


class RepoRetroalimentacion(Protocol):
    def registrar(self, mensaje_id: int, usuario_id: int, etiqueta: str, comentario: str | None = None) -> None: ...


class RepoRetencion(Protocol):
    def purgar(self, sin_caso_antes_de: datetime, cerrados_antes_de: datetime, sesiones_antes_de: datetime) -> dict[str, int]:
        """Borra correos sin riesgo y casos cerrados antiguos (con todo su análisis) y sesiones vencidas."""
        ...


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
    modelos: RepoModelos
    entidades: RepoEntidades
    analisis: RepoAnalisis
    casos: RepoCasos
    avisos: RepoAvisos
    retroalimentacion: RepoRetroalimentacion
    configuracion: RepoConfiguracion
    estadisticas: RepoEstadisticas
    suscripciones_push: RepoSuscripcionesPush
    conversaciones: RepoConversaciones
    retencion: RepoRetencion
    auditoria: RegistroAuditoria

    def __enter__(self) -> Self: ...
    def __exit__(self, *exc: object) -> None: ...
    def confirmar(self) -> None: ...
    def revertir(self) -> None: ...


class FabricaUnidadDeTrabajo(Protocol):
    def __call__(self) -> UnidadDeTrabajo: ...
