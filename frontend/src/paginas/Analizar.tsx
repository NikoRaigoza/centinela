// Análisis manual: el usuario sube un .eml (Gmail → ⋮ → Descargar mensaje) y ve el veredicto. No se guarda nada.

import { useMutation } from "@tanstack/react-query";
import { FileUp, ShieldCheck } from "lucide-react";
import { useRef, useState, type DragEvent } from "react";
import { mensajeDeError } from "../api/cliente";
import { analisis } from "../api/servicios";
import type { Analisis } from "../api/tipos";
import { ListaAdjuntos } from "../componentes/Adjuntos";
import { Alerta, Girando, InsigniaNivel } from "../componentes/ui";
import { AREA, ORIGEN_ENLACE, formatoPorcentaje } from "../utilidades/textos";

const MAX_BYTES = 10_000_000;

function Componente({ nombre, p }: { nombre: string; p: number | null }) {
  const tono = p == null ? "" : p >= 0.7 ? "alto" : p >= 0.3 ? "medio" : "bajo";
  return (
    <div className="barra-prob">
      <span>{nombre}</span>
      <span className="riel"><span className={`relleno ${tono}`} style={{ width: `${(p ?? 0) * 100}%`, display: "block" }} /></span>
      <span className="cifra">{p == null ? "no aplica" : formatoPorcentaje(p)}</span>
    </div>
  );
}

function Resultado({ r }: { r: Analisis }) {
  return (
    <section className="tarjeta pila" style={{ gap: 16 }}>
      <div className="fila-entre">
        <InsigniaNivel nivel={r.nivel} />
        <span className="muy-tenue">Probabilidad de phishing: <strong>{formatoPorcentaje(r.probabilidad)}</strong></span>
      </div>
      <div>
        <h2 style={{ overflowWrap: "anywhere" }}>{r.asunto || "(sin asunto)"}</h2>
        <p className="tenue" style={{ overflowWrap: "anywhere" }}>De {r.remitente}</p>
      </div>
      <p style={{ fontSize: "1.05rem" }}>{r.resumen}</p>
      {r.razones.length > 0 && (
        <ol className={`razones ${r.nivel}`}>
          {r.razones.map((x) => <li key={x.texto}><div><div className="area">{AREA[x.area]}</div>{x.texto}</div></li>)}
        </ol>
      )}
      {r.adjuntos.length > 0 && (
        <div>
          <h3 style={{ marginBottom: 8 }}>Adjuntos revisados por dentro ({r.adjuntos.length})</h3>
          <ListaAdjuntos adjuntos={r.adjuntos} />
        </div>
      )}
      {r.senales_positivas.length > 0 && (
        <Alerta tipo="exito">
          <strong>Señales de confianza:</strong>
          <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>{r.senales_positivas.map((s) => <li key={s}>{s}</li>)}</ul>
        </Alerta>
      )}
      <details className="plegable">
        <summary>Detalle técnico del análisis</summary>
        <div className="pila">
          <Componente nombre="Texto (modelo)" p={r.componentes.contenido} />
          <Componente nombre="Enlaces (modelo)" p={r.componentes.enlaces} />
          <Componente nombre="Reglas técnicas" p={r.componentes.tecnico} />
          {r.enlaces.length > 0 && (
            <p className="muy-tenue">Dominios enlazados: {r.enlaces.map((e) => `${e.dominio} (${formatoPorcentaje(e.probabilidad)}`
              + `${e.origen && e.origen !== "cuerpo" ? ` · ${ORIGEN_ENLACE[e.origen].toLowerCase()}` : ""})`).join(", ")}</p>
          )}
          {r.todas_las_razones.length > r.razones.length && (
            <ul className="pila" style={{ margin: 0, paddingLeft: 18, gap: 4 }}>
              {r.todas_las_razones.map((x) => <li key={x.texto}><span className="muy-tenue">{AREA[x.area]} · {x.gravedad} · </span>{x.texto}</li>)}
            </ul>
          )}
          <p className="muy-tenue">
            Idioma: {r.idioma} · Tiempo: {r.tiempo_ms ?? "—"} ms · Modelos: texto #{r.modelo_contenido_id ?? "—"}, enlaces #{r.modelo_enlaces_id ?? "—"}
          </p>
        </div>
      </details>
    </section>
  );
}

export function PaginaAnalizar() {
  const entrada = useRef<HTMLInputElement>(null);
  const [arrastrando, setArrastrando] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nombre, setNombre] = useState<string | null>(null);
  const analizar = useMutation({ mutationFn: analisis.analizar });

  const recibir = (archivo: File | undefined) => {
    setError(null);
    analizar.reset();
    if (!archivo) return;
    if (!/\.eml$/i.test(archivo.name)) return setError("Sube un archivo .eml (en Gmail: abre el correo → ⋮ → Descargar mensaje).");
    if (archivo.size > MAX_BYTES) return setError("El archivo es demasiado grande (máximo 10 MB).");
    setNombre(archivo.name);
    analizar.mutate(archivo);
  };
  const soltar = (e: DragEvent) => {
    e.preventDefault();
    setArrastrando(false);
    recibir(e.dataTransfer.files[0]);
  };

  return (
    <>
      <div className="encabezado">
        <div>
          <h1>Analizar un correo</h1>
          <p>¿Te llegó algo raro a otra cuenta o te lo reenviaron? Revísalo aquí antes de hacer clic.</p>
        </div>
      </div>
      <div
        className={`zona-carga ${arrastrando ? "activa" : ""}`} role="button" tabIndex={0}
        onClick={() => entrada.current?.click()}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && entrada.current?.click()}
        onDragOver={(e) => { e.preventDefault(); setArrastrando(true); }}
        onDragLeave={() => setArrastrando(false)} onDrop={soltar}
      >
        {analizar.isPending ? <Girando size={36} /> : <FileUp size={36} />}
        <strong>{analizar.isPending ? `Analizando ${nombre}…` : "Arrastra aquí el archivo .eml o haz clic para elegirlo"}</strong>
        <span className="muy-tenue">En Gmail: abre el correo → menú ⋮ → «Descargar mensaje».</span>
        <input ref={entrada} type="file" accept=".eml,message/rfc822" hidden onChange={(e) => { recibir(e.target.files?.[0]); e.target.value = ""; }} />
      </div>
      <p className="muy-tenue fila" style={{ gap: 6 }}><ShieldCheck size={15} /> El correo se analiza en el servidor de Centinela y no se guarda.</p>
      {error && <Alerta tipo="error">{error}</Alerta>}
      {analizar.isError && <Alerta tipo="error">{mensajeDeError(analizar.error)}</Alerta>}
      {analizar.data && <Resultado r={analizar.data} />}
    </>
  );
}
