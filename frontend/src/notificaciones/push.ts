// Notificaciones push en este navegador (estándar Web Push). La suscripción queda ligada a la llave VAPID del
// servidor y el aviso viaja cifrado: el servicio push del navegador no puede leerlo.

import { push } from "../api/servicios";

export type EstadoPush =
  | { tipo: "no_soportado"; motivo: string }
  | { tipo: "bloqueado" }
  | { tipo: "inactivo" }
  | { tipo: "activo"; endpoint: string };

const RUTA_SW = "/sw.js";

export function pushSoportado(): string | null {
  if (typeof window === "undefined" || !("serviceWorker" in navigator) || !("PushManager" in window) ||
      !("Notification" in window)) {
    return /iPhone|iPad/.test(navigator.userAgent)
      ? "En iPhone, primero agrega Centinela a tu pantalla de inicio (Compartir → Agregar a inicio) y ábrelo desde ahí."
      : "Este navegador no permite notificaciones push.";
  }
  if (!window.isSecureContext) return "Las notificaciones necesitan una conexión segura (https).";
  return null;
}

async function registro(): Promise<ServiceWorkerRegistration> {
  const actual = await navigator.serviceWorker.getRegistration("/");
  return actual ?? navigator.serviceWorker.register(RUTA_SW, { scope: "/" });
}

function bytesDeClave(base64url: string): Uint8Array<ArrayBuffer> {
  const relleno = "=".repeat((4 - (base64url.length % 4)) % 4);
  const binario = atob((base64url + relleno).replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(binario, (c) => c.charCodeAt(0));
}

function mismaClave(s: PushSubscription, clave: string): boolean {
  const actual = s.options.applicationServerKey;
  if (!actual) return true;
  const a = new Uint8Array(actual);
  const b = bytesDeClave(clave);
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

export async function estadoPush(clavePublica: string | null): Promise<EstadoPush> {
  const motivo = pushSoportado();
  if (motivo) return { tipo: "no_soportado", motivo };
  if (Notification.permission === "denied") return { tipo: "bloqueado" };
  const r = await navigator.serviceWorker.getRegistration("/");
  const s = await r?.pushManager.getSubscription();
  if (!s) return { tipo: "inactivo" };
  if (clavePublica && !mismaClave(s, clavePublica)) {          // el servidor cambió sus llaves: hay que reactivar
    await s.unsubscribe();
    return { tipo: "inactivo" };
  }
  return { tipo: "activo", endpoint: s.endpoint };
}

/** Pide permiso, suscribe este navegador y lo registra en Centinela. */
export async function activarPush(clavePublica: string): Promise<EstadoPush> {
  const permiso = await Notification.requestPermission();
  if (permiso !== "granted") return permiso === "denied" ? { tipo: "bloqueado" } : { tipo: "inactivo" };
  const r = await registro();
  await navigator.serviceWorker.ready;
  let s = await r.pushManager.getSubscription();
  if (s && !mismaClave(s, clavePublica)) {
    await s.unsubscribe();
    s = null;
  }
  s ??= await r.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: bytesDeClave(clavePublica) });
  await push.activar(s.toJSON());
  return { tipo: "activo", endpoint: s.endpoint };
}

/** Quita la suscripción de este navegador (en Centinela y en el navegador). No falla si ya no existía. */
export async function desactivarPush(): Promise<void> {
  if (pushSoportado()) return;
  const r = await navigator.serviceWorker.getRegistration("/");
  const s = await r?.pushManager.getSubscription();
  if (!s) return;
  try {
    await push.quitarEste(s.endpoint);
  } finally {
    await s.unsubscribe();
  }
}

/** SHA-256 del endpoint (16 primeros hex), igual que el que devuelve la API: así se marca «este dispositivo». */
export async function huellaEndpoint(endpoint: string): Promise<string> {
  const datos = new TextEncoder().encode(endpoint);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", datos));
  return Array.from(hash, (b) => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
}
