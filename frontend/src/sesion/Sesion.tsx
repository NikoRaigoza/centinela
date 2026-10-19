// Estado de la sesión del panel: quién está conectado. Al abrir el panel se intenta recuperar la sesión con la
// cookie de renovación; si otra pestaña cierra sesión, esta también lo hace (BroadcastChannel).

import { useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { fijarAcceso, renovarSesion, suscribirSesion } from "../api/cliente";
import { auth } from "../api/servicios";
import type { TokenAcceso, Usuario } from "../api/tipos";
import { desactivarPush } from "../notificaciones/push";

type Estado = { tipo: "cargando" } | { tipo: "anonimo"; voluntario?: boolean } | { tipo: "autenticado"; usuario: Usuario };

interface ValorSesion {
  estado: Estado;
  usuario: Usuario | null;
  esAdmin: boolean;
  entrar: (acceso: TokenAcceso) => void;
  /** Refleja cambios del propio usuario (p. ej. activó el 2FA) sin tocar los tokens. */
  actualizarUsuario: (usuario: Usuario) => void;
  salir: () => Promise<void>;
}

const Contexto = createContext<ValorSesion | null>(null);
const CANAL = "centinela-sesion";

export function ProveedorSesion({ children }: { children: ReactNode }) {
  const [estado, setEstado] = useState<Estado>({ tipo: "cargando" });
  const consultas = useQueryClient();

  useEffect(() => {
    const quitar = suscribirSesion((acceso) => {
      setEstado((previo) =>
        acceso ? { tipo: "autenticado", usuario: acceso.usuario } : previo.tipo === "anonimo" ? previo : { tipo: "anonimo" });
      if (!acceso) consultas.clear();          // no dejar datos de la cuenta anterior en memoria
    });
    void renovarSesion();
    return quitar;
  }, [consultas]);

  useEffect(() => {
    if (typeof BroadcastChannel === "undefined") return;
    const canal = new BroadcastChannel(CANAL);
    canal.onmessage = (e) => {
      if (e.data === "salir") fijarAcceso(null);
    };
    return () => canal.close();
  }, []);

  const entrar = useCallback((acceso: TokenAcceso) => fijarAcceso(acceso), []);
  const actualizarUsuario = useCallback((usuario: Usuario) => setEstado({ tipo: "autenticado", usuario }), []);

  const salir = useCallback(async () => {
    try {
      // Este navegador deja de recibir avisos de la cuenta (importante en un computador compartido).
      // Con tope de tiempo: un servicio push lento no debe impedir cerrar la sesión.
      await Promise.race([desactivarPush().catch(() => undefined), new Promise((listo) => setTimeout(listo, 3000))]);
      await auth.cerrar();
    } finally {
      setEstado({ tipo: "anonimo", voluntario: true });      // antes de limpiar: así no se recuerda la página actual
      fijarAcceso(null);
      if (typeof BroadcastChannel !== "undefined") {
        const canal = new BroadcastChannel(CANAL);
        canal.postMessage("salir");
        canal.close();
      }
    }
  }, []);

  const valor = useMemo<ValorSesion>(() => {
    const usuario = estado.tipo === "autenticado" ? estado.usuario : null;
    return { estado, usuario, esAdmin: usuario?.rol === "administrador", entrar, actualizarUsuario, salir };
  }, [estado, entrar, actualizarUsuario, salir]);

  return <Contexto.Provider value={valor}>{children}</Contexto.Provider>;
}

export function useSesion(): ValorSesion {
  const v = useContext(Contexto);
  if (!v) throw new Error("useSesion debe usarse dentro de <ProveedorSesion>");
  return v;
}

/** Para pantallas que solo existen con sesión iniciada. */
export function useUsuario(): Usuario {
  const { usuario } = useSesion();
  if (!usuario) throw new Error("No hay sesión iniciada");
  return usuario;
}
