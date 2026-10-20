// Una función por operación de la API. Las pantallas usan estas funciones, nunca `fetch` directamente.

import { descargar, pedir } from "./cliente";
import type {
  AccionCuenta,
  Activacion2FA,
  Analisis,
  Buzon,
  Caso,
  Configuracion2FA,
  ConfiguracionPush,
  Conversacion,
  ConversacionDetalle,
  Decision,
  DetalleCaso,
  DispositivoPush,
  EstadoAsistente,
  EstadoCaso,
  EstadoCuenta,
  FormatoReporte,
  MensajeRecibido,
  ModoCuarentena,
  Modelo,
  RespuestaInicio,
  RespuestaAsistente,
  ResultadoPrueba,
  ResumenPanel,
  ResumenRevision,
  TokenAcceso,
  Usuario,
} from "./tipos";

export const auth = {
  iniciar: (correo: string, clave: string) =>
    pedir<RespuestaInicio>("/api/auth/inicio", { metodo: "POST", json: { correo, clave } }),
  registrar: (correo: string, nombre: string, clave: string) =>
    pedir<{ mensaje: string }>("/api/auth/registro", { metodo: "POST", json: { correo, nombre, clave } }),
  verificar2fa: (codigo: string, tokenDesafio: string) =>
    pedir<TokenAcceso>("/api/auth/2fa/verificacion", { metodo: "POST", json: { codigo }, token: tokenDesafio }),
  /** Sin tokenDesafio usa la sesión actual (activar el doble factor desde "Mi cuenta"). */
  iniciarConfig2fa: (tokenDesafio?: string) =>
    pedir<Configuracion2FA>("/api/auth/2fa/configuracion", { metodo: "POST", token: tokenDesafio }),
  confirmarConfig2fa: (codigo: string, tokenDesafio?: string) =>
    pedir<Activacion2FA>("/api/auth/2fa/confirmacion", { metodo: "POST", json: { codigo }, token: tokenDesafio }),
  cerrar: () => pedir<void>("/api/auth/cierre", { metodo: "POST" }),
};

export const cuenta = {
  yo: () => pedir<Usuario>("/api/usuarios/yo"),
  cambiarClave: (actual: string, nueva: string) =>
    pedir<TokenAcceso>("/api/usuarios/yo/clave", { metodo: "PUT", json: { actual, nueva }, reintentar: false }),
};

export const panel = {
  resumen: (dias: number) => pedir<ResumenPanel>(`/api/panel/resumen?dias=${dias}`),
};

export const reportes = {
  descargar: (formato: FormatoReporte, dias: number, organizacion = false) => {
    const q = new URLSearchParams({ formato, dias: String(dias), organizacion: String(organizacion) });
    return descargar(`/api/reportes?${q}`, `centinela-reporte.${formato}`);
  },
};

export const buzones = {
  listar: () => pedir<Buzon[]>("/api/buzones"),
  urlConexion: () => pedir<{ url: string }>("/api/buzones/conexion", { metodo: "POST" }),
  actualizar: (id: number, cambios: { modo?: ModoCuarentena; avisar_por_correo?: boolean; pausado?: boolean }) =>
    pedir<Buzon>(`/api/buzones/${id}`, { metodo: "PATCH", json: cambios }),
  desconectar: (id: number) => pedir<Buzon>(`/api/buzones/${id}`, { metodo: "DELETE" }),
  revisar: (id: number) => pedir<ResumenRevision>(`/api/buzones/${id}/revision`, { metodo: "POST" }),
  mensajes: (id: number, limite = 50) => pedir<MensajeRecibido[]>(`/api/buzones/${id}/mensajes?limite=${limite}`),
};

export const casos = {
  listar: (estados: EstadoCaso[], limite: number, desde: number) => {
    const q = new URLSearchParams({ limite: String(limite), desde: String(desde) });
    estados.forEach((e) => q.append("estado", e));
    return pedir<Caso[]>(`/api/casos?${q}`);
  },
  ver: (id: number) => pedir<DetalleCaso>(`/api/casos/${id}`),
  liberar: (id: number) => pedir<void>(`/api/casos/${id}/liberacion`, { metodo: "POST" }),
  clasificar: (id: number, decision: Decision, comentario?: string) =>
    pedir<void>(`/api/casos/${id}/clasificacion`, { metodo: "POST", json: { decision, comentario: comentario || null } }),
  anotar: (id: number, texto: string) => pedir<void>(`/api/casos/${id}/notas`, { metodo: "POST", json: { texto } }),
};

export const analisis = {
  analizar: (archivo: Blob) =>
    pedir<Analisis>("/api/analisis", { metodo: "POST", cuerpo: archivo, tipoCuerpo: "message/rfc822" }),
};

export const admin = {
  usuarios: (estado?: EstadoCuenta) => pedir<Usuario[]>(`/api/admin/usuarios${estado ? `?estado=${estado}` : ""}`),
  cambiarEstado: (id: number, accion: AccionCuenta) =>
    pedir<Usuario>(`/api/admin/usuarios/${id}/${accion}`, { metodo: "POST" }),
  buzones: () => pedir<Buzon[]>("/api/admin/buzones"),
  modelos: () => pedir<Modelo[]>("/api/admin/modelos"),
};

export const asistente = {
  estado: () => pedir<EstadoAsistente>("/api/asistente/estado"),
  preguntar: (pregunta: string, destino: { conversacion_id?: number; caso_id?: number }) =>
    pedir<RespuestaAsistente>("/api/asistente/preguntas", { metodo: "POST", json: { pregunta, ...destino } }),
  conversaciones: () => pedir<Conversacion[]>("/api/asistente/conversaciones"),
  conversacion: (id: number) => pedir<ConversacionDetalle>(`/api/asistente/conversaciones/${id}`),
  eliminar: (id: number) => pedir<void>(`/api/asistente/conversaciones/${id}`, { metodo: "DELETE" }),
};

export const push = {
  configuracion: () => pedir<ConfiguracionPush>("/api/push/configuracion"),
  dispositivos: () => pedir<DispositivoPush[]>("/api/push/dispositivos"),
  activar: (suscripcion: PushSubscriptionJSON) => pedir<void>("/api/push/dispositivos", { metodo: "POST", json: suscripcion }),
  quitarEste: (endpoint: string) => pedir<void>("/api/push/dispositivos/quitar", { metodo: "POST", json: { endpoint } }),
  quitar: (id: number) => pedir<void>(`/api/push/dispositivos/${id}`, { metodo: "DELETE" }),
  probar: () => pedir<ResultadoPrueba>("/api/push/prueba", { metodo: "POST" }),
};
