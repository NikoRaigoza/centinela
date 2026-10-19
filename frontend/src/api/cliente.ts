// Cliente HTTP del panel.
//
// Seguridad de la sesión:
//  * El token de acceso (15 min) vive SOLO en memoria: nunca en localStorage, donde un script inyectado lo leería.
//  * El token de renovación viaja en una cookie httpOnly que JavaScript no puede leer.
//  * Se renueva un poco antes de que venza. Si aun así la API responde 401, se renueva una vez y se repite la
//    petición (salvo en operaciones que no deben repetirse, como cambiar la clave). Las renovaciones se serializan
//    entre pestañas (Web Locks): el backend rota el token en cada uso y detecta reúsos como posible robo.

import type { TokenAcceso } from "./tipos";

export class ErrorApi extends Error {
  readonly estado: number;
  readonly codigo: string;

  constructor(estado: number, codigo: string, mensaje: string) {
    super(mensaje);
    this.name = "ErrorApi";
    this.estado = estado;
    this.codigo = codigo;
  }
}

type Oyente = (acceso: TokenAcceso | null) => void;

const MARGEN_MS = 30_000;

let tokenAcceso: string | null = null;
let venceEn = 0;
let renovando: Promise<TokenAcceso | null> | null = null;
const oyentes = new Set<Oyente>();

/** La sesión (React) se suscribe para enterarse de renovaciones y de cierres forzados. */
export function suscribirSesion(oyente: Oyente): () => void {
  oyentes.add(oyente);
  return () => oyentes.delete(oyente);
}

export function fijarAcceso(acceso: TokenAcceso | null): void {
  tokenAcceso = acceso?.token_acceso ?? null;
  venceEn = acceso ? Date.now() + acceso.expira_en_s * 1000 : 0;
  oyentes.forEach((o) => o(acceso));
}

async function leerError(r: Response): Promise<ErrorApi> {
  try {
    const cuerpo = (await r.json()) as { codigo?: string; mensaje?: string };
    return new ErrorApi(r.status, cuerpo.codigo ?? "error", cuerpo.mensaje ?? "Ocurrió un error inesperado.");
  } catch {
    return new ErrorApi(r.status, "error", `El servidor respondió con un error (${r.status}).`);
  }
}

async function fetchSeguro(ruta: string, init: RequestInit): Promise<Response> {
  try {
    return await fetch(ruta, { credentials: "same-origin", ...init });
  } catch {
    throw new ErrorApi(0, "sin_conexion", "No hay conexión con el servidor de Centinela. Revisa tu red e intenta de nuevo.");
  }
}

async function pedirRenovacion(): Promise<TokenAcceso | null> {
  const r = await fetchSeguro("/api/auth/renovacion", { method: "POST" });
  if (!r.ok) return null;
  return (await r.json()) as TokenAcceso;
}

/** Renueva el token de acceso con la cookie. Devuelve null si la sesión ya no es válida. */
export function renovarSesion(): Promise<TokenAcceso | null> {
  if (!renovando) {
    const tarea = async () => {
      const acceso = await pedirRenovacion().catch(() => null);
      fijarAcceso(acceso);
      return acceso;
    };
    const bloqueos = typeof navigator !== "undefined" ? navigator.locks : undefined;
    renovando = (bloqueos ? bloqueos.request("centinela-renovacion", tarea) : tarea()).finally(() => {
      renovando = null;
    });
  }
  return renovando;
}

export interface OpcionesPeticion {
  metodo?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  json?: unknown;
  cuerpo?: Blob;
  tipoCuerpo?: string;
  /** Token distinto al de acceso (el de desafío del doble factor). No se renueva. */
  token?: string;
  /** false si la operación no debe repetirse tras un 401 (p. ej. una clave incorrecta también da 401). */
  reintentar?: boolean;
  señal?: AbortSignal;
}

export async function pedir<T>(ruta: string, op: OpcionesPeticion = {}): Promise<T> {
  const enviar = () => {
    const cabeceras: Record<string, string> = { Accept: "application/json" };
    const token = op.token ?? tokenAcceso;
    if (token) cabeceras.Authorization = `Bearer ${token}`;
    let body: BodyInit | undefined;
    if (op.json !== undefined) {
      cabeceras["Content-Type"] = "application/json";
      body = JSON.stringify(op.json);
    } else if (op.cuerpo) {
      cabeceras["Content-Type"] = op.tipoCuerpo ?? "application/octet-stream";
      body = op.cuerpo;
    }
    return fetchSeguro(ruta, { method: op.metodo ?? "GET", headers: cabeceras, body, signal: op.señal });
  };

  if (!op.token && tokenAcceso && Date.now() > venceEn - MARGEN_MS) await renovarSesion();
  let r = await enviar();
  if (r.status === 401 && !op.token && tokenAcceso && op.reintentar !== false) {
    const acceso = await renovarSesion();
    if (!acceso) throw new ErrorApi(401, "sesion_expirada", "Tu sesión expiró. Inicia sesión de nuevo.");
    r = await enviar();
  }
  if (!r.ok) throw await leerError(r);
  if (r.status === 204) return undefined as T;
  return (await r.json()) as T;
}

export function mensajeDeError(error: unknown): string {
  if (error instanceof ErrorApi) return error.message;
  return "Ocurrió un error inesperado. Intenta de nuevo.";
}
