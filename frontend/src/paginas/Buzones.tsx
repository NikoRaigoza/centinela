// Buzones de Gmail del usuario: conectar (OAuth2), elegir qué hace Centinela, pausar, revisar ya y desconectar.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Mail, Pause, Play, Plus, RefreshCw, Unplug, Zap } from "lucide-react";
import { useState } from "react";
import { ErrorApi, mensajeDeError } from "../api/cliente";
import { buzones } from "../api/servicios";
import type { Buzon, ModoCuarentena } from "../api/tipos";
import { DialogoConfirmar } from "../componentes/Dialogo";
import { useTostadas } from "../componentes/Tostadas";
import { Alerta, ChipAutenticacion, ErrorCarga, Esqueleto, Girando, Interruptor, Vacio } from "../componentes/ui";
import { ESTADO_BUZON, MODO, formatoFechaHora, haceCuanto, remitente } from "../utilidades/textos";

const TONO_BUZON = { activo: "bajo", pausado: "", revocado: "alto", error: "medio" } as const;

function MensajesRecientes({ buzonId }: { buzonId: number }) {
  const mensajes = useQuery({ queryKey: ["mensajes", buzonId], queryFn: () => buzones.mensajes(buzonId, 20) });
  if (mensajes.isPending) return <Esqueleto />;
  if (mensajes.isError) return <ErrorCarga error={mensajes.error} />;
  if (mensajes.data.length === 0) return <p className="tenue">Todavía no hay correos revisados en este buzón.</p>;
  return (
    <div className="tabla-contenedor">
      <table className="tabla">
        <thead><tr><th>Recibido</th><th>Correo</th><th>Autenticación</th></tr></thead>
        <tbody>
          {mensajes.data.map((m) => (
            <tr key={m.id}>
              <td style={{ whiteSpace: "nowrap" }} title={formatoFechaHora(m.recibido_en)}>{haceCuanto(m.recibido_en)}</td>
              <td>
                <div className="asunto">{m.asunto || "(sin asunto)"}</div>
                <div className="secundario">{remitente(m.remitente_nombre, m.remitente_correo)}</div>
              </td>
              <td><div className="chips-auth"><ChipAutenticacion nombre="SPF" resultado={m.spf} /><ChipAutenticacion nombre="DMARC" resultado={m.dmarc} /></div></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TarjetaBuzon({ b }: { b: Buzon }) {
  const consultas = useQueryClient();
  const avisar = useTostadas();
  const [desconectar, setDesconectar] = useState(false);
  const desconectado = b.estado === "revocado";

  const refrescar = () => {
    void consultas.invalidateQueries({ queryKey: ["buzones"] });
    void consultas.invalidateQueries({ queryKey: ["resumen"] });
  };
  const actualizar = useMutation({
    mutationFn: (cambios: Parameters<typeof buzones.actualizar>[1]) => buzones.actualizar(b.id, cambios),
    onSuccess: (nuevo) => consultas.setQueryData<Buzon[]>(["buzones"], (l) => l?.map((x) => (x.id === nuevo.id ? nuevo : x))),
    onError: (e) => avisar(mensajeDeError(e), "error"),
  });
  const revisar = useMutation({
    mutationFn: () => buzones.revisar(b.id),
    onSuccess: (r) => {
      refrescar();
      void consultas.invalidateQueries({ queryKey: ["mensajes", b.id] });
      void consultas.invalidateQueries({ queryKey: ["casos"] });
      if (r.error) avisar(r.error, "error");
      else avisar(r.nuevos === 0 ? "Revisión lista: no llegaron correos nuevos." : `Revisión lista: ${r.nuevos} correo(s) nuevo(s) analizado(s).`);
    },
    onError: (e) => avisar(mensajeDeError(e), "error"),
  });
  const quitar = useMutation({
    mutationFn: () => buzones.desconectar(b.id),
    onSuccess: () => {
      setDesconectar(false);
      refrescar();
      avisar("Buzón desconectado. Centinela ya no tiene acceso a ese Gmail.");
    },
    onError: (e) => {
      setDesconectar(false);
      avisar(mensajeDeError(e), "error");
    },
  });

  return (
    <section className="tarjeta pila" style={{ gap: 16 }}>
      <div className="fila-entre">
        <div className="fila">
          <Mail size={20} color="var(--primario)" />
          <h2 style={{ overflowWrap: "anywhere" }}>{b.correo_gmail}</h2>
          <span className={`insignia ${TONO_BUZON[b.estado]}`}><span className="punto" />{ESTADO_BUZON[b.estado]}</span>
          {b.tiempo_real && b.estado === "activo" && (
            <span className="insignia info" title="Gmail avisa a Centinela apenas llega un correo: se revisa en segundos">
              <Zap size={12} aria-hidden /> Tiempo real
            </span>
          )}
        </div>
        {!desconectado && (
          <div className="fila">
            <button className="boton pequeno" onClick={() => revisar.mutate()} disabled={revisar.isPending || b.estado === "pausado"}>
              {revisar.isPending ? <Girando size={14} /> : <RefreshCw size={14} />} Revisar ahora
            </button>
            <button className="boton pequeno" onClick={() => actualizar.mutate({ pausado: b.estado !== "pausado" })} disabled={actualizar.isPending}>
              {b.estado === "pausado" ? <><Play size={14} /> Reanudar</> : <><Pause size={14} /> Pausar</>}
            </button>
            <button className="boton pequeno fantasma" onClick={() => setDesconectar(true)}><Unplug size={14} /> Desconectar</button>
          </div>
        )}
      </div>

      {b.ultimo_error && b.estado !== "activo" && <Alerta tipo={desconectado ? "error" : "aviso"}>{b.ultimo_error}</Alerta>}
      {desconectado && <p className="tenue">Para volver a protegerlo, conéctalo de nuevo con el botón «Conectar Gmail».</p>}

      {!desconectado && (
        <>
          <p className="muy-tenue">
            Conectado el {formatoFechaHora(b.conectado_en)} · última revisión {haceCuanto(b.ultima_revision_en)}
            {b.estado === "activo" && (b.tiempo_real ? " · revisa cada correo apenas llega" : " · revisa cada 30 segundos")}
          </p>
          <div className="rejilla rejilla-2">
            <fieldset className="pila" style={{ border: 0, padding: 0, margin: 0, gap: 8 }}>
              <legend className="rotulo" style={{ fontWeight: 600, marginBottom: 8 }}>Cuando llegue un correo peligroso</legend>
              {(Object.keys(MODO) as ModoCuarentena[]).map((m) => (
                <label key={m} className="casilla">
                  <input type="radio" name={`modo-${b.id}`} checked={b.modo === m} disabled={actualizar.isPending}
                    onChange={() => actualizar.mutate({ modo: m })} />
                  <span><strong>{MODO[m].titulo}</strong><br /><span className="muy-tenue">{MODO[m].detalle}</span></span>
                </label>
              ))}
            </fieldset>
            <div className="pila" style={{ gap: 8 }}>
              <span style={{ fontWeight: 600 }}>Avisos</span>
              <Interruptor activo={b.avisar_por_correo} deshabilitado={actualizar.isPending}
                cambiar={(v) => actualizar.mutate({ avisar_por_correo: v })}
                texto="Avisarme con un correo en este mismo buzón" />
              <span className="muy-tenue">El aviso explica en pocas palabras por qué el correo es peligroso y qué hacer.</span>
            </div>
          </div>
          <details className="plegable">
            <summary>Últimos correos revisados</summary>
            <MensajesRecientes buzonId={b.id} />
          </details>
        </>
      )}

      <DialogoConfirmar abierto={desconectar} titulo="¿Desconectar este buzón?" textoConfirmar="Desconectar" tono="peligro"
        ocupado={quitar.isPending} cancelar={() => setDesconectar(false)} confirmar={() => quitar.mutate()}>
        <p>Centinela dejará de revisar <strong>{b.correo_gmail}</strong> y le devolverá a Google el permiso de acceso.</p>
        <p>Los correos que ya están en cuarentena siguen en tu Gmail, en la etiqueta Centinela/Cuarentena.</p>
      </DialogoConfirmar>
    </section>
  );
}

export function PaginaBuzones() {
  const lista = useQuery({ queryKey: ["buzones"], queryFn: buzones.listar });
  const conectar = useMutation({
    mutationFn: buzones.urlConexion,
    // Se navega (no fetch) a Google: la autorización ocurre en la página de Google y vuelve a /api/gmail/callback.
    onSuccess: ({ url }) => window.location.assign(url),
  });
  const noConfigurado = conectar.error instanceof ErrorApi && conectar.error.estado === 503;

  return (
    <>
      <div className="encabezado">
        <div>
          <h1>Mis buzones</h1>
          <p>Las cuentas de Gmail que Centinela protege. Puedes conectar varias.</p>
        </div>
        <button className="boton primario" onClick={() => conectar.mutate()} disabled={conectar.isPending}>
          {conectar.isPending ? <Girando /> : <Plus size={16} />} Conectar Gmail
        </button>
      </div>
      {conectar.isError && (
        <Alerta tipo="error">
          {noConfigurado
            ? "La conexión con Gmail todavía no está configurada en el servidor. El administrador debe seguir la guía docs/guia_conexion_gmail.md."
            : mensajeDeError(conectar.error)}
        </Alerta>
      )}
      <Alerta>
        Centinela pide permiso para <strong>leer</strong> tus correos y <strong>moverlos de etiqueta</strong>. Nunca los borra ni los envía
        a terceros, y no guarda su contenido: solo lo necesario para explicarte cada alerta.
      </Alerta>
      {lista.isPending ? <Esqueleto filas={4} /> : lista.isError ? <ErrorCarga error={lista.error} reintentar={() => void lista.refetch()} /> :
        lista.data.length === 0 ? (
          <div className="tarjeta"><Vacio titulo="Aún no has conectado ningún buzón" icono={<Mail size={40} />}>
            <p>Pulsa «Conectar Gmail», elige tu cuenta y acepta los permisos. Volverás aquí automáticamente.</p>
          </Vacio></div>
        ) : lista.data.map((b) => <TarjetaBuzon key={b.id} b={b} />)}
    </>
  );
}
