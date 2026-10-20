// Textos y formatos para mostrar los datos de la API en español de Colombia.

import type {
  Area,
  EstadoBuzon,
  EstadoCaso,
  EstadoCuenta,
  ModoCuarentena,
  Nivel,
  OrigenEnlace,
  ResultadoAuth,
  TipoEvento,
} from "../api/tipos";

const ZONA = "America/Bogota";

const fechaHora = new Intl.DateTimeFormat("es-CO", { dateStyle: "medium", timeStyle: "short", timeZone: ZONA });
const soloFecha = new Intl.DateTimeFormat("es-CO", { dateStyle: "medium", timeZone: ZONA });
const diaCorto = new Intl.DateTimeFormat("es-CO", { day: "numeric", month: "short", timeZone: "UTC" });
const relativo = new Intl.RelativeTimeFormat("es-CO", { numeric: "auto" });
const entero = new Intl.NumberFormat("es-CO");

export const formatoFechaHora = (iso: string | null | undefined) => (iso ? fechaHora.format(new Date(iso)) : "—");
export const formatoFecha = (iso: string | null | undefined) => (iso ? soloFecha.format(new Date(iso)) : "—");
/** Fechas "AAAA-MM-DD" (sin hora) del resumen: ya están en hora de Colombia. */
export const formatoDia = (dia: string) => diaCorto.format(new Date(`${dia}T00:00:00Z`));
export const formatoEntero = (n: number) => entero.format(n);
export const formatoPorcentaje = (p: number | null | undefined, decimales = 0) =>
  p == null ? "—" : `${(p * 100).toFixed(decimales).replace(".", ",")} %`;

export function haceCuanto(iso: string | null | undefined, ahora = Date.now()): string {
  if (!iso) return "nunca";
  const seg = Math.round((new Date(iso).getTime() - ahora) / 1000);
  const abs = Math.abs(seg);
  if (abs < 60) return relativo.format(seg, "second");
  if (abs < 3600) return relativo.format(Math.round(seg / 60), "minute");
  if (abs < 86400) return relativo.format(Math.round(seg / 3600), "hour");
  return relativo.format(Math.round(seg / 86400), "day");
}

export const NIVEL: Record<Nivel, string> = { bajo: "Riesgo bajo", medio: "Sospechoso", alto: "Peligroso" };

export const ESTADO_CASO: Record<EstadoCaso, string> = {
  nuevo: "Por revisar",
  en_cuarentena: "En cuarentena",
  liberado: "Liberado",
  confirmado: "Phishing confirmado",
  falso_positivo: "Era legítimo",
};

export const ESTADO_CUENTA: Record<EstadoCuenta, string> = {
  pendiente: "Pendiente",
  activo: "Activa",
  rechazado: "Rechazada",
  desactivado: "Desactivada",
};

export const ESTADO_BUZON: Record<EstadoBuzon, string> = {
  activo: "Protegido",
  pausado: "En pausa",
  revocado: "Desconectado",
  error: "Con problemas",
};

export const MODO: Record<ModoCuarentena, { titulo: string; detalle: string }> = {
  cuarentena_automatica: {
    titulo: "Cuarentena automática",
    detalle: "Los correos peligrosos salen de la bandeja de entrada y quedan en la etiqueta Centinela/Cuarentena.",
  },
  solo_avisar: {
    titulo: "Solo avisar",
    detalle: "Centinela no mueve nada: marca los correos de riesgo con una etiqueta y te avisa.",
  },
};

export const AREA: Record<Area, string> = {
  remitente: "Remitente",
  autenticacion: "Autenticación",
  suplantacion: "Suplantación",
  contenido: "Contenido",
  enlace: "Enlaces",
  adjunto: "Adjuntos",
  fraude: "Fraude sin enlaces",
};

export const ORIGEN_ENLACE: Record<OrigenEnlace, string> = {
  cuerpo: "En el texto",
  qr: "Código QR",
  adjunto: "Dentro de un adjunto",
};

export function formatoTamano(bytes: number | null | undefined): string {
  if (bytes == null) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1).replace(".", ",")} MB`;
}

export const EVENTO: Record<TipoEvento, string> = {
  creado: "Centinela detectó el correo",
  cuarentena: "Movido a cuarentena",
  aviso: "Aviso enviado al dueño del buzón",
  liberado: "Devuelto a la bandeja de entrada",
  confirmado: "Confirmado como phishing",
  falso_positivo: "Marcado como legítimo",
  reabierto: "Caso reabierto",
  nota: "Nota",
};

export const AUTENTICACION: Record<ResultadoAuth, { texto: string; tono: "bien" | "mal" | "neutro" }> = {
  pass: { texto: "aprobó", tono: "bien" },
  fail: { texto: "falló", tono: "mal" },
  softfail: { texto: "falló (leve)", tono: "mal" },
  neutral: { texto: "neutral", tono: "neutro" },
  none: { texto: "sin registro", tono: "neutro" },
  temperror: { texto: "error temporal", tono: "neutro" },
  permerror: { texto: "mal configurado", tono: "mal" },
};

export function remitente(nombre: string | null, correo: string | null): string {
  if (nombre && correo) return `${nombre} <${correo}>`;
  return nombre ?? correo ?? "Remitente desconocido";
}
