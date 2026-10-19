// Detalle de un correo de riesgo: por qué es peligroso, evidencia técnica, historial y decisiones del dueño.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Bot, Inbox, Paperclip, RotateCcw, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router";
import { mensajeDeError } from "../api/cliente";
import { casos } from "../api/servicios";
import type { Decision, DetalleCaso, Nivel } from "../api/tipos";
import { DialogoConfirmar } from "../componentes/Dialogo";
import { useTostadas } from "../componentes/Tostadas";
import { ChipAutenticacion, ErrorCarga, Esqueleto, InsigniaEstado, InsigniaNivel } from "../componentes/ui";
import { AREA, EVENTO, formatoFechaHora, formatoPorcentaje, remitente } from "../utilidades/textos";

function Medidor({ p, nivel }: { p: number; nivel: Nivel }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  return (
    <div className="medidor" role="img" aria-label={`Probabilidad de phishing: ${formatoPorcentaje(p)}`}>
      <svg viewBox="0 0 120 120">
        <circle cx="60" cy="60" r={r} fill="none" stroke="var(--borde)" strokeWidth="10" />
        <circle cx="60" cy="60" r={r} fill="none" stroke={`var(--${nivel})`} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={`${c * p} ${c}`} />
      </svg>
      <div>
        <div className="cifra">{formatoPorcentaje(p)}</div>
        <div className="sub">probabilidad<br />de phishing</div>
      </div>
    </div>
  );
}

type Accion = { tipo: "liberar" } | { tipo: "clasificar"; decision: Decision };

const TEXTO_ACCION: Record<string, { titulo: string; boton: string; tono: "primario" | "peligro" | "exito"; cuerpo: string }> = {
  liberar: {
    titulo: "¿Devolver el correo a tu bandeja?", boton: "Sí, liberar", tono: "exito",
    cuerpo: "El correo vuelve a tu bandeja de entrada de Gmail y quedará registrado como legítimo. Hazlo solo si estás seguro de que es confiable: si dudas, comunícate con la entidad por un canal oficial.",
  },
  confirmar: {
    titulo: "¿Confirmar que es phishing?", boton: "Sí, es phishing", tono: "peligro",
    cuerpo: "El correo seguirá fuera de tu bandeja. Tu confirmación ayuda a que Centinela aprenda.",
  },
  falso_positivo: {
    titulo: "¿Marcar como legítimo?", boton: "Sí, es legítimo", tono: "exito",
    cuerpo: "Centinela registrará que se equivocó con este correo. Esto ayuda a mejorar la detección.",
  },
  reabrir: {
    titulo: "¿Reabrir el caso?", boton: "Reabrir", tono: "primario",
    cuerpo: "El caso volverá a la lista de correos por atender.",
  },
};

function Acciones({ caso, elegir }: { caso: DetalleCaso; elegir: (a: Accion) => void }) {
  if (caso.estado === "en_cuarentena") {
    return (
      <div className="fila">
        <button className="boton peligro" onClick={() => elegir({ tipo: "clasificar", decision: "confirmar" })}>
          <ShieldAlert size={16} /> Es phishing
        </button>
        <button className="boton" onClick={() => elegir({ tipo: "liberar" })}><Inbox size={16} /> Liberar a la bandeja</button>
      </div>
    );
  }
  if (caso.estado === "nuevo") {
    return (
      <div className="fila">
        <button className="boton peligro" onClick={() => elegir({ tipo: "clasificar", decision: "confirmar" })}>
          <ShieldAlert size={16} /> Es phishing
        </button>
        <button className="boton" onClick={() => elegir({ tipo: "clasificar", decision: "falso_positivo" })}>
          <ShieldCheck size={16} /> Es legítimo
        </button>
      </div>
    );
  }
  return (
    <button className="boton" onClick={() => elegir({ tipo: "clasificar", decision: "reabrir" })}>
      <RotateCcw size={16} /> Reabrir caso
    </button>
  );
}

export function PaginaCaso() {
  const id = Number(useParams().id);
  const consultas = useQueryClient();
  const avisar = useTostadas();
  const [accion, setAccion] = useState<Accion | null>(null);
  const [comentario, setComentario] = useState("");
  const [nota, setNota] = useState("");
  const caso = useQuery({ queryKey: ["caso", id], queryFn: () => casos.ver(id), enabled: Number.isInteger(id) });

  const refrescar = () => {
    void consultas.invalidateQueries({ queryKey: ["caso", id] });
    void consultas.invalidateQueries({ queryKey: ["casos"] });
    void consultas.invalidateQueries({ queryKey: ["resumen"] });
  };

  const ejecutar = useMutation({
    mutationFn: (a: Accion) => (a.tipo === "liberar" ? casos.liberar(id) : casos.clasificar(id, a.decision, comentario.trim())),
    onSuccess: (_, a) => {
      setAccion(null);
      setComentario("");
      refrescar();
      avisar(a.tipo === "liberar" ? "El correo volvió a tu bandeja de entrada." : "Listo, guardamos tu decisión.");
    },
    onError: (e) => {
      setAccion(null);
      avisar(mensajeDeError(e), "error");
    },
  });

  const anotar = useMutation({
    mutationFn: () => casos.anotar(id, nota.trim()),
    onSuccess: () => {
      setNota("");
      refrescar();
    },
    onError: (e) => avisar(mensajeDeError(e), "error"),
  });

  if (caso.isPending) return <Esqueleto filas={8} />;
  if (caso.isError) return <><Link to="/casos" className="boton fantasma"><ArrowLeft size={16} /> Volver</Link><ErrorCarga error={caso.error} /></>;
  const c = caso.data;
  const textos = accion ? TEXTO_ACCION[accion.tipo === "liberar" ? "liberar" : accion.decision] : undefined;
  const otrasRazones = c.todas_las_razones.filter((r) => !c.razones.includes(r.texto));

  const enviarNota = (e: FormEvent) => {
    e.preventDefault();
    if (nota.trim()) anotar.mutate();
  };

  return (
    <>
      <Link to="/casos" className="boton fantasma pequeno" style={{ justifySelf: "start" }}><ArrowLeft size={16} /> Correos de riesgo</Link>

      <section className="tarjeta pila" style={{ gap: 18 }}>
        <div className="fila-entre">
          <div className="fila"><InsigniaNivel nivel={c.nivel} /><InsigniaEstado estado={c.estado} /></div>
          <div className="fila">
            <Link to={`/asistente?caso=${c.id}`} className="boton"><Bot size={16} aria-hidden /> Preguntar al asistente</Link>
            <Acciones caso={c} elegir={setAccion} />
          </div>
        </div>
        <div>
          <h1 style={{ overflowWrap: "anywhere" }}>{c.asunto || "(sin asunto)"}</h1>
          <p className="tenue" style={{ overflowWrap: "anywhere" }}>De {remitente(c.remitente_nombre, c.remitente_correo)}</p>
        </div>
        <div className="veredicto">
          <Medidor p={c.probabilidad} nivel={c.nivel} />
          <div className="pila">
            <p style={{ fontSize: "1.05rem" }}>{c.resumen}</p>
            {c.razones.length > 0 && (
              <>
                <h2>Por qué creemos que es {c.nivel === "alto" ? "peligroso" : "sospechoso"}</h2>
                <ol className={`razones ${c.nivel}`}>
                  {c.razones.map((texto) => {
                    const r = c.todas_las_razones.find((x) => x.texto === texto);
                    return (
                      <li key={texto}>
                        <div>{r && <div className="area">{AREA[r.area]}</div>}{texto}</div>
                      </li>
                    );
                  })}
                </ol>
              </>
            )}
          </div>
        </div>
        {c.estado === "en_cuarentena" && (
          <p className="muy-tenue">
            El correo no se borró: está en la etiqueta <strong>Centinela/Cuarentena</strong> de tu Gmail. No abras sus enlaces ni adjuntos.
          </p>
        )}
      </section>

      <div className="rejilla rejilla-2">
        <section className="tarjeta">
          <h2>Datos del correo</h2>
          <dl className="datos">
            <dt>Remitente</dt><dd>{remitente(c.remitente_nombre, c.remitente_correo)}</dd>
            <dt>Buzón</dt><dd>{c.buzon}</dd>
            <dt>Recibido</dt><dd>{formatoFechaHora(c.recibido_en)}</dd>
            <dt>Autenticación</dt>
            <dd className="chips-auth">
              <ChipAutenticacion nombre="SPF" resultado={c.spf} />
              <ChipAutenticacion nombre="DKIM" resultado={c.dkim} />
              <ChipAutenticacion nombre="DMARC" resultado={c.dmarc} />
            </dd>
            {c.adjuntos.length > 0 && (<><dt>Adjuntos</dt><dd className="pila" style={{ gap: 4 }}>
              {c.adjuntos.map((a) => <span key={a} className="fila" style={{ gap: 6 }}><Paperclip size={14} />{a}</span>)}
            </dd></>)}
          </dl>
          {c.enlaces.length > 0 && (
            <>
              <h3 style={{ margin: "18px 0 10px" }}>Enlaces ({c.enlaces.length})</h3>
              <div className="pila" style={{ gap: 8 }}>
                {c.enlaces.map((e, i) => (
                  <div key={`${e.dominio}-${i}`} className="enlace">
                    <div className="fila" style={{ gap: 8 }}>
                      <span className="mono" style={{ overflowWrap: "anywhere" }}>{e.dominio}</span>
                      {e.enganoso && <span className="insignia alto">Engañoso</span>}
                    </div>
                    {e.probabilidad != null && (
                      <div className="barra-prob sin-rotulo">
                        <span className="riel"><span className="relleno" style={{ width: `${e.probabilidad * 100}%`, display: "block" }} /></span>
                        <span className="cifra">{formatoPorcentaje(e.probabilidad)}</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
              <p className="muy-tenue" style={{ marginTop: 8 }}>
                El porcentaje es la estimación del modelo de enlaces por sí solo. Por tu seguridad, Centinela muestra solo el dominio.
              </p>
            </>
          )}
          {otrasRazones.length > 0 && (
            <details className="plegable" style={{ marginTop: 16 }}>
              <summary>Otras señales detectadas ({otrasRazones.length})</summary>
              <ul className="pila" style={{ margin: 0, paddingLeft: 18, gap: 6 }}>
                {otrasRazones.map((r) => <li key={r.texto}><span className="muy-tenue">{AREA[r.area]} · </span>{r.texto}</li>)}
              </ul>
            </details>
          )}
        </section>

        <section className="tarjeta">
          <h2>Historial</h2>
          <ol className="linea-tiempo">
            {c.historial.map((e, i) => (
              <li key={i} className={e.tipo === "nota" ? "nota" : ""}>
                <div className="que">{EVENTO[e.tipo]}</div>
                <div className="muy-tenue">{formatoFechaHora(e.fecha)}{e.autor ? ` · ${e.autor}` : ""}</div>
                {e.detalle && <div className="detalle">{e.detalle}</div>}
              </li>
            ))}
          </ol>
          <form onSubmit={enviarNota} className="pila" style={{ marginTop: 18 }}>
            <div className="campo">
              <label htmlFor="nota">Agregar una nota</label>
              <textarea id="nota" className="entrada" maxLength={2000} value={nota} onChange={(e) => setNota(e.target.value)}
                placeholder="Por ejemplo: llamé al banco y confirmaron que no enviaron este correo." />
            </div>
            <button className="boton" style={{ justifySelf: "start" }} disabled={!nota.trim() || anotar.isPending}>
              {anotar.isPending ? "Guardando…" : "Guardar nota"}
            </button>
          </form>
        </section>
      </div>

      <DialogoConfirmar abierto={!!accion} titulo={textos?.titulo ?? ""} textoConfirmar={textos?.boton ?? ""} tono={textos?.tono}
        ocupado={ejecutar.isPending} cancelar={() => setAccion(null)} confirmar={() => accion && ejecutar.mutate(accion)}>
        <p>{textos?.cuerpo}</p>
        {accion?.tipo === "clasificar" && accion.decision !== "reabrir" && (
          <div className="campo">
            <label htmlFor="comentario">Comentario (opcional)</label>
            <textarea id="comentario" className="entrada" maxLength={1000} value={comentario} onChange={(e) => setComentario(e.target.value)} />
          </div>
        )}
      </DialogoConfirmar>
    </>
  );
}
