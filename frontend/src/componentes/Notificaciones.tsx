// Notificaciones push: activarlas en este dispositivo, ver los demás dispositivos, quitarlos y enviar una prueba.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BellOff, BellRing, Send, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { ErrorApi, mensajeDeError } from "../api/cliente";
import { push } from "../api/servicios";
import { activarPush, desactivarPush, estadoPush, huellaEndpoint, type EstadoPush } from "../notificaciones/push";
import { haceCuanto } from "../utilidades/textos";
import { useTostadas } from "./Tostadas";
import { Alerta, ErrorCarga, Esqueleto, Girando } from "./ui";

function EsteDispositivo({ estado, ocupado, activar, desactivar }: {
  estado: EstadoPush | null; ocupado: boolean; activar: () => void; desactivar: () => void;
}) {
  if (!estado) return <Esqueleto filas={1} />;
  if (estado.tipo === "no_soportado") return <Alerta tipo="info">{estado.motivo}</Alerta>;
  if (estado.tipo === "bloqueado") {
    return (
      <Alerta tipo="aviso">
        Bloqueaste las notificaciones de Centinela en este navegador. Para activarlas, abre la configuración del sitio
        (el candado junto a la dirección), permite las notificaciones y recarga la página.
      </Alerta>
    );
  }
  if (estado.tipo === "activo") {
    return (
      <div className="fila-entre">
        <span className="fila" style={{ gap: 8 }}><BellRing size={18} aria-hidden style={{ color: "var(--bajo)" }} />
          <strong>Activadas en este dispositivo</strong></span>
        <button className="boton" onClick={desactivar} disabled={ocupado}>
          {ocupado ? <Girando size={15} /> : <BellOff size={15} aria-hidden />} Desactivar
        </button>
      </div>
    );
  }
  return (
    <div className="fila-entre">
      <span className="tenue">Este dispositivo no recibe notificaciones.</span>
      <button className="boton primario" onClick={activar} disabled={ocupado}>
        {ocupado ? <Girando size={15} /> : <BellRing size={15} aria-hidden />} Activar en este dispositivo
      </button>
    </div>
  );
}

export function Notificaciones() {
  const consultas = useQueryClient();
  const avisar = useTostadas();
  const config = useQuery({ queryKey: ["push", "configuracion"], queryFn: push.configuracion, staleTime: Infinity });
  const dispositivos = useQuery({ queryKey: ["push", "dispositivos"], queryFn: push.dispositivos });
  const [estado, setEstado] = useState<EstadoPush | null>(null);
  const [huella, setHuella] = useState<string | null>(null);
  const clave = config.data?.clave_publica ?? null;

  useEffect(() => {
    if (!config.data?.disponible) return;
    let vigente = true;
    void estadoPush(clave).then((e) => vigente && setEstado(e)).catch(() => vigente && setEstado({ tipo: "inactivo" }));
    return () => { vigente = false; };
  }, [config.data?.disponible, clave]);

  useEffect(() => {
    if (estado?.tipo === "activo") void huellaEndpoint(estado.endpoint).then(setHuella);
    else setHuella(null);
  }, [estado]);

  const recargar = () => void consultas.invalidateQueries({ queryKey: ["push", "dispositivos"] });
  const cambio = useMutation({
    mutationFn: (accion: "activar" | "desactivar") =>
      accion === "activar" && clave ? activarPush(clave) : desactivarPush().then((): EstadoPush => ({ tipo: "inactivo" })),
    onSuccess: (e, accion) => {
      setEstado(e);
      recargar();
      if (e.tipo === "activo") avisar("Notificaciones activadas en este dispositivo.");
      else if (accion === "desactivar") avisar("Notificaciones desactivadas en este dispositivo.");
    },
    onError: (e) => avisar(e instanceof ErrorApi ? e.message : "El navegador no pudo cambiar las notificaciones. Intenta de nuevo.",
      "error"),
  });
  const prueba = useMutation({
    mutationFn: push.probar,
    onSuccess: (r) => {
      recargar();
      if (r.entregados) avisar(`Enviamos la prueba a ${r.entregados} dispositivo(s). Debería aparecer en unos segundos.`);
      else avisar("No se pudo entregar la prueba. Desactiva y vuelve a activar las notificaciones.", "error");
    },
    onError: (e) => avisar(mensajeDeError(e), "error"),
  });
  const quitar = useMutation({
    mutationFn: (id: number) => push.quitar(id),
    onSuccess: (_, id) => {
      const propio = dispositivos.data?.find((d) => d.id === id)?.endpoint_hash === huella;
      if (propio) void desactivarPush().finally(() => setEstado({ tipo: "inactivo" }));
      recargar();
      avisar("Dispositivo quitado.");
    },
    onError: (e) => avisar(mensajeDeError(e), "error"),
  });

  if (config.isPending) return <Esqueleto filas={2} />;
  if (config.isError) return <ErrorCarga error={config.error} reintentar={() => void config.refetch()} />;
  if (!config.data.disponible) {
    return <Alerta tipo="info">Las notificaciones push aún no están configuradas en este servidor. Mientras tanto, los avisos te llegan por correo.</Alerta>;
  }

  const lista = dispositivos.data ?? [];
  return (
    <div className="pila" style={{ gap: 16 }}>
      <p className="tenue">
        Cuando Centinela detenga un correo peligroso te avisará al instante en este navegador o celular, aunque no tengas
        el panel abierto. El aviso no muestra el asunto ni el remitente: los ves al abrirlo.
      </p>
      <EsteDispositivo estado={estado} ocupado={cambio.isPending}
        activar={() => cambio.mutate("activar")} desactivar={() => cambio.mutate("desactivar")} />
      {lista.length > 0 && (
        <div className="pila" style={{ gap: 8 }}>
          <div className="fila-entre">
            <h3>Dispositivos con avisos</h3>
            <button className="boton pequeno" onClick={() => prueba.mutate()} disabled={prueba.isPending}>
              {prueba.isPending ? <Girando size={14} /> : <Send size={14} aria-hidden />} Enviar una prueba
            </button>
          </div>
          <ul className="lista-dispositivos">
            {lista.map((d) => (
              <li key={d.id}>
                <div>
                  <strong>{d.dispositivo}</strong>
                  {d.endpoint_hash === huella && <span className="insignia info" style={{ marginLeft: 8 }}>Este dispositivo</span>}
                  <div className="muy-tenue">
                    Activado {haceCuanto(d.creado_en)}{d.ultimo_envio_en ? ` · último aviso ${haceCuanto(d.ultimo_envio_en)}` : ""}
                  </div>
                </div>
                <button className="boton fantasma pequeno" onClick={() => quitar.mutate(d.id)} disabled={quitar.isPending}
                  aria-label={`Quitar ${d.dispositivo}`}>
                  <Trash2 size={15} aria-hidden /> Quitar
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
      <p className="muy-tenue">Al cerrar sesión, este navegador deja de recibir avisos de tu cuenta.</p>
    </div>
  );
}
