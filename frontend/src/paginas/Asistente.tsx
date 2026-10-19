// Asistente de IA: conversaciones guardadas a la izquierda, chat a la derecha. Se abre en blanco, sobre una
// conversación (?c=ID) o sobre un correo de riesgo (?caso=ID, desde el detalle del caso).

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Bot, MessageSquarePlus, SendHorizontal, ShieldAlert, Sparkles, Trash2 } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { mensajeDeError } from "../api/cliente";
import { asistente, casos } from "../api/servicios";
import type { EstadoAsistente, Turno } from "../api/tipos";
import { DialogoConfirmar } from "../componentes/Dialogo";
import { TextoAsistente } from "../componentes/TextoAsistente";
import { useTostadas } from "../componentes/Tostadas";
import { Alerta, ErrorCarga, Esqueleto, Girando } from "../componentes/ui";
import { haceCuanto } from "../utilidades/textos";

const MAX_PREGUNTA = 1000;

function numero(valor: string | null): number | null {
  const n = Number(valor);
  return valor && Number.isInteger(n) && n > 0 ? n : null;
}

function Burbuja({ turno }: { turno: Turno }) {
  if (turno.rol === "usuario") return <div className="burbuja usuario">{turno.contenido}</div>;
  return (
    <div className="burbuja asistente">
      <TextoAsistente texto={turno.contenido} />
      {turno.proveedor === "local" && <div className="muy-tenue modo-basico">Respuesta en modo básico</div>}
    </div>
  );
}

function Cupo({ estado }: { estado: EstadoAsistente | undefined }) {
  if (!estado) return null;
  if (!estado.ia_disponible) {
    return <span className="insignia" title="Responde con reglas: sin IA externa">Modo básico</span>;
  }
  return (
    <span className={`insignia ${estado.restantes_ia ? "info" : "medio"}`} title="Respuestas con IA que te quedan hoy">
      <Sparkles size={13} aria-hidden /> IA · {estado.restantes_ia} de {estado.limite_ia} hoy
    </span>
  );
}

export function PaginaAsistente() {
  const [params, setParams] = useSearchParams();
  const conversacionId = numero(params.get("c"));
  const casoParam = numero(params.get("caso"));
  const consultas = useQueryClient();
  const navegar = useNavigate();
  const avisar = useTostadas();
  const [pregunta, setPregunta] = useState("");
  const [pendiente, setPendiente] = useState<string | null>(null);
  const [aviso, setAviso] = useState<{ conversacion: number; texto: string } | null>(null);
  const [borrar, setBorrar] = useState(false);
  const fin = useRef<HTMLDivElement>(null);
  const caja = useRef<HTMLTextAreaElement>(null);

  const estado = useQuery({ queryKey: ["asistente", "estado"], queryFn: asistente.estado });
  const lista = useQuery({ queryKey: ["asistente", "conversaciones"], queryFn: asistente.conversaciones });
  const conversacion = useQuery({
    queryKey: ["asistente", "conversacion", conversacionId],
    queryFn: () => asistente.conversacion(conversacionId!),
    enabled: conversacionId !== null,
  });
  const casoId = conversacionId !== null ? conversacion.data?.caso_id ?? null : casoParam;
  const caso = useQuery({ queryKey: ["caso", casoId], queryFn: () => casos.ver(casoId!), enabled: casoId !== null });

  const turnos = conversacionId !== null ? conversacion.data?.turnos ?? [] : [];

  useEffect(() => {
    fin.current?.scrollIntoView?.({ block: "end", behavior: "smooth" });
  }, [turnos.length, pendiente]);

  const preguntar = useMutation({
    mutationFn: (texto: string) =>
      asistente.preguntar(texto, conversacionId !== null ? { conversacion_id: conversacionId } : casoParam ? { caso_id: casoParam } : {}),
    onMutate: (texto) => {
      setPendiente(texto);
      setAviso(null);
      setPregunta("");
    },
    onSuccess: async (r) => {
      setAviso(r.aviso ? { conversacion: r.conversacion_id, texto: r.aviso } : null);
      consultas.setQueryData<EstadoAsistente>(["asistente", "estado"], (e) => (e ? { ...e, restantes_ia: r.restantes_ia } : e));
      void consultas.invalidateQueries({ queryKey: ["asistente", "conversaciones"] });
      // Se trae la conversación ANTES de cambiar la dirección: así no parpadea mientras carga
      await consultas.fetchQuery({ queryKey: ["asistente", "conversacion", r.conversacion_id],
        queryFn: () => asistente.conversacion(r.conversacion_id), staleTime: 0 }).catch(() => undefined);
      if (r.conversacion_id !== conversacionId) setParams({ c: String(r.conversacion_id) }, { replace: true });
      caja.current?.focus();
    },
    onError: (_, texto) => setPregunta(texto),          // no se pierde lo que escribió
    onSettled: () => setPendiente(null),
  });

  const eliminar = useMutation({
    mutationFn: () => asistente.eliminar(conversacionId!),
    onSuccess: () => {
      setBorrar(false);
      consultas.removeQueries({ queryKey: ["asistente", "conversacion", conversacionId] });
      void consultas.invalidateQueries({ queryKey: ["asistente", "conversaciones"] });
      navegar("/asistente", { replace: true });
      avisar("Conversación eliminada.");
    },
    onError: (e) => avisar(mensajeDeError(e), "error"),
  });

  const enviar = (texto: string) => {
    const t = texto.trim();
    if (t && t.length <= MAX_PREGUNTA && !preguntar.isPending) preguntar.mutate(t);
  };
  const alEnviar = (e: FormEvent) => {
    e.preventDefault();
    enviar(pregunta);
  };
  const alTeclear = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
      e.preventDefault();
      enviar(pregunta);
    }
  };

  const sugerencias = casoId !== null ? estado.data?.sugerencias_caso : estado.data?.sugerencias_generales;
  const vacia = turnos.length === 0 && !pendiente;
  const titulo = conversacion.data?.titulo ?? (casoId !== null ? "Pregunta sobre este correo" : "Nueva conversación");

  return (
    <>
      <div className="encabezado">
        <div>
          <h1>Asistente</h1>
          <p>Pregúntale por un correo sospechoso o por cómo usar Centinela.</p>
        </div>
        <Cupo estado={estado.data} />
      </div>

      <div className={`pagina-asistente ${conversacionId !== null ? "con-chat" : ""}`}>
        <aside className="tarjeta conversaciones" aria-label="Conversaciones guardadas">
          <Link to="/asistente" className="boton primario bloque"><MessageSquarePlus size={16} aria-hidden /> Nueva conversación</Link>
          {lista.isPending && <Esqueleto filas={3} />}
          {lista.isError && <ErrorCarga error={lista.error} reintentar={() => void lista.refetch()} />}
          {lista.data?.length === 0 && <p className="muy-tenue">Aquí quedarán tus conversaciones.</p>}
          <ul>
            {lista.data?.map((c) => (
              <li key={c.id}>
                <Link to={`/asistente?c=${c.id}`} className={c.id === conversacionId ? "activa" : undefined}
                  aria-current={c.id === conversacionId ? "page" : undefined}>
                  <span className="titulo">{c.titulo}</span>
                  <span className="muy-tenue">
                    {c.caso_id !== null && <><ShieldAlert size={12} aria-hidden /> Correo de riesgo · </>}
                    {haceCuanto(c.actualizado_en)}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </aside>

        <section className="tarjeta chat" aria-label={titulo}>
          <div className="chat-cabecera">
            <div style={{ minWidth: 0 }}>
              {conversacionId !== null && <Link to="/asistente" className="boton fantasma pequeno solo-movil"><ArrowLeft size={14} /> Conversaciones</Link>}
              <h2 className="titulo-chat">{titulo}</h2>
              {casoId !== null && caso.data && (
                <Link to={`/casos/${casoId}`} className="muy-tenue">
                  Sobre el correo «{caso.data.asunto || "(sin asunto)"}» →
                </Link>
              )}
            </div>
            {conversacionId !== null && (
              <button className="boton fantasma pequeno" onClick={() => setBorrar(true)} aria-label="Eliminar conversación">
                <Trash2 size={15} aria-hidden /> Eliminar
              </button>
            )}
          </div>

          <div className="mensajes" aria-live="polite">
            {conversacionId !== null && conversacion.isPending && <Esqueleto filas={4} />}
            {conversacion.isError && <ErrorCarga error={conversacion.error} />}
            {vacia && !(conversacionId !== null && conversacion.isPending) && !conversacion.isError && (
              <div className="chat-vacio">
                <Bot size={36} aria-hidden />
                <p>
                  {casoId !== null
                    ? "Te explico por qué este correo es riesgoso y qué hacer. Puedes empezar con una de estas preguntas:"
                    : "Hola, soy el asistente de Centinela. Puedes empezar con una de estas preguntas:"}
                </p>
                <div className="sugerencias">
                  {sugerencias?.map((s) => (
                    <button key={s} className="boton pequeno" onClick={() => enviar(s)} disabled={preguntar.isPending}>{s}</button>
                  ))}
                </div>
              </div>
            )}
            {turnos.map((t, i) => <Burbuja key={`${t.creado_en}-${i}`} turno={t} />)}
            {pendiente && (
              <>
                <div className="burbuja usuario">{pendiente}</div>
                <div className="burbuja asistente escribiendo"><Girando size={14} /> Pensando…</div>
              </>
            )}
            {aviso && aviso.conversacion === conversacionId && !pendiente && <Alerta tipo="aviso">{aviso.texto}</Alerta>}
            {preguntar.isError && <Alerta tipo="error">{mensajeDeError(preguntar.error)}</Alerta>}
            <div ref={fin} />
          </div>

          <form className="redactar" onSubmit={alEnviar}>
            <label htmlFor="pregunta" className="visualmente-oculto">Tu pregunta</label>
            <textarea id="pregunta" ref={caja} className="entrada" rows={2} maxLength={MAX_PREGUNTA} value={pregunta}
              placeholder="Escribe tu pregunta… (Enter para enviar, Shift+Enter para otra línea)"
              onChange={(e) => setPregunta(e.target.value)} onKeyDown={alTeclear} disabled={conversacion.isError} />
            <button className="boton primario" disabled={!pregunta.trim() || preguntar.isPending} aria-label="Enviar pregunta">
              {preguntar.isPending ? <Girando size={16} /> : <SendHorizontal size={16} aria-hidden />}
            </button>
          </form>
          <p className="muy-tenue aviso-ia">
            No escribas contraseñas, códigos ni datos personales. El asistente puede equivocarse: ante la duda, verifica por un
            canal oficial.
          </p>
        </section>
      </div>

      <DialogoConfirmar abierto={borrar} titulo="¿Eliminar esta conversación?" textoConfirmar="Eliminar" tono="peligro"
        ocupado={eliminar.isPending} confirmar={() => eliminar.mutate()} cancelar={() => setBorrar(false)}>
        <p>Se borra de forma permanente. El correo y su caso no cambian.</p>
      </DialogoConfirmar>
    </>
  );
}
