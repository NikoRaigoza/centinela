// Contratos de la API (espejo de backend/src/centinela/adaptadores/entrada/api/esquemas.py).

export type Rol = "administrador" | "usuario";
export type EstadoCuenta = "pendiente" | "activo" | "rechazado" | "desactivado";
export type Nivel = "bajo" | "medio" | "alto";
export type EstadoCaso = "nuevo" | "en_cuarentena" | "liberado" | "confirmado" | "falso_positivo";
export type EstadoBuzon = "activo" | "pausado" | "revocado" | "error";
export type ModoCuarentena = "solo_avisar" | "cuarentena_automatica";
export type Area = "remitente" | "autenticacion" | "suplantacion" | "contenido" | "enlace" | "adjunto";
export type Gravedad = "baja" | "media" | "alta";
export type AccionCuenta = "aprobar" | "rechazar" | "desactivar" | "reactivar";
export type Decision = "confirmar" | "falso_positivo" | "reabrir";

export interface Usuario {
  id: number;
  correo: string;
  nombre: string;
  rol: Rol;
  estado: EstadoCuenta;
  totp_activo: boolean;
  ultimo_acceso: string | null;
  creado_en: string | null;
}

export interface TokenAcceso {
  token_acceso: string;
  tipo: string;
  expira_en_s: number;
  usuario: Usuario;
}

export interface RespuestaInicio {
  paso: "completo" | "verificar_2fa" | "configurar_2fa";
  acceso: TokenAcceso | null;
  token_desafio: string | null;
}

export interface Configuracion2FA {
  secreto: string;
  uri: string;
}

export interface Activacion2FA {
  codigos_recuperacion: string[];
  acceso: TokenAcceso | null;
}

export interface Buzon {
  id: number;
  usuario_id: number;
  correo_gmail: string;
  estado: EstadoBuzon;
  modo: ModoCuarentena;
  avisar_por_correo: boolean;
  ultima_revision_en: string | null;
  ultimo_error: string | null;
  conectado_en: string;
}

export interface ResumenRevision {
  buzon_id: number;
  nuevos: number;
  omitidos: number;
  estado: string;
  error: string | null;
}

export type ResultadoAuth = "pass" | "fail" | "softfail" | "neutral" | "none" | "temperror" | "permerror";

export interface MensajeRecibido {
  id: number;
  recibido_en: string;
  remitente_nombre: string | null;
  remitente_correo: string | null;
  asunto: string | null;
  n_enlaces: number;
  n_adjuntos: number;
  spf: ResultadoAuth | null;
  dkim: ResultadoAuth | null;
  dmarc: ResultadoAuth | null;
}

export interface Razon {
  area: Area;
  gravedad: Gravedad;
  texto: string;
}

export interface Enlace {
  dominio: string;
  probabilidad: number | null;
  enganoso?: boolean;
}

export interface Analisis {
  remitente: string;
  asunto: string;
  idioma: string;
  nivel: Nivel;
  probabilidad: number;
  resumen: string;
  razones: Razon[];
  todas_las_razones: Razon[];
  senales_positivas: string[];
  componentes: { contenido: number | null; enlaces: number | null; tecnico: number | null };
  enlaces: Enlace[];
  tiempo_ms: number | null;
  modelo_contenido_id: number | null;
  modelo_enlaces_id: number | null;
}

export interface Caso {
  id: number;
  estado: EstadoCaso;
  nivel: Nivel;
  probabilidad: number;
  resumen: string;
  razones: string[];
  buzon: string;
  remitente_nombre: string | null;
  remitente_correo: string | null;
  asunto: string | null;
  recibido_en: string;
  puede_liberarse: boolean;
}

export type TipoEvento =
  | "creado" | "cuarentena" | "aviso" | "liberado" | "confirmado" | "falso_positivo" | "reabierto" | "nota";

export interface Evento {
  tipo: TipoEvento;
  fecha: string;
  autor: string | null;
  detalle: string | null;
}

export interface DetalleCaso extends Caso {
  spf: ResultadoAuth | null;
  dkim: ResultadoAuth | null;
  dmarc: ResultadoAuth | null;
  todas_las_razones: Razon[];
  enlaces: Enlace[];
  adjuntos: string[];
  historial: Evento[];
}

export interface DiaResumen {
  fecha: string;
  revisados: number;
  sospechosos: number;
  peligrosos: number;
}

export interface ResumenPanel {
  dias: number;
  revisados: number;
  sospechosos: number;
  peligrosos: number;
  casos_por_estado: Record<EstadoCaso, number>;
  entidades_suplantadas: { nombre: string; correos: number }[];
  serie: DiaResumen[];
}

export interface Modelo {
  id: number;
  tipo: "contenido" | "enlaces";
  nombre: string;
  version: string;
  dataset: string;
  sha256: string;
  umbral_medio: number;
  umbral_alto: number;
  activo: boolean;
  metricas: Record<string, unknown>;
  creado_en: string | null;
}
