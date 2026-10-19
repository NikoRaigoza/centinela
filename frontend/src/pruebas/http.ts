// Servidor falso para las pruebas: responde según el método y la ruta, y registra cada petición.
import { vi } from "vitest";

export type Respuesta = { estado?: number; cuerpo?: unknown };
export type Manejador = (req: { metodo: string; ruta: string; cabeceras: Record<string, string>; cuerpo?: unknown }) => Respuesta;

export function servidorFalso(manejar: Manejador) {
  const peticiones: { metodo: string; ruta: string; autorizacion?: string }[] = [];
  vi.stubGlobal("fetch", vi.fn(async (ruta: string, init: RequestInit = {}) => {
    const cabeceras = (init.headers ?? {}) as Record<string, string>;
    const metodo = init.method ?? "GET";
    peticiones.push({ metodo, ruta, autorizacion: cabeceras.Authorization });
    const cuerpo = typeof init.body === "string" ? JSON.parse(init.body) : undefined;
    const r = manejar({ metodo, ruta, cabeceras, cuerpo });
    const estado = r.estado ?? 200;
    return new Response(estado === 204 ? null : JSON.stringify(r.cuerpo ?? {}), { status: estado, headers: { "Content-Type": "application/json" } });
  }));
  return peticiones;
}

export const usuarioDemo = {
  id: 2, correo: "ana@gmail.com", nombre: "Ana Martínez", rol: "usuario" as const, estado: "activo" as const,
  totp_activo: false, ultimo_acceso: null, creado_en: null,
};
export const acceso = (token: string, usuario = usuarioDemo) => ({ token_acceso: token, tipo: "bearer", expira_en_s: 900, usuario });
