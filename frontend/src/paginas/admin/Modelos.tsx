// Modelos de detección registrados: versión, datos de entrenamiento, umbrales, huella e indicadores de validación.
// Solo lectura: los modelos se registran y activan con `centinela modelos registrar` (quedan auditados).

import { useQuery } from "@tanstack/react-query";
import { BrainCircuit, Fingerprint } from "lucide-react";
import { Fragment } from "react";
import { admin } from "../../api/servicios";
import type { Modelo } from "../../api/tipos";
import { ErrorCarga, Esqueleto, Vacio } from "../../componentes/ui";
import { formatoFecha } from "../../utilidades/textos";

const TIPO = { contenido: "Texto del correo", enlaces: "Enlaces (URL)" };

/** Aplana {a: {b: 1}} → [["a · b", "1"]] para mostrar las métricas sin conocer su forma de antemano. */
function aplanar(obj: Record<string, unknown>, prefijo = ""): [string, string][] {
  return Object.entries(obj).flatMap(([k, v]): [string, string][] => {
    const clave = (prefijo ? `${prefijo} · ` : "") + k.replace(/_/g, " ");
    if (v && typeof v === "object" && !Array.isArray(v)) return aplanar(v as Record<string, unknown>, clave);
    if (typeof v === "number") return [[clave, Math.abs(v) < 1e-3 && v !== 0 ? v.toExponential(2) : v.toLocaleString("es-CO", { maximumFractionDigits: 4 })]];
    return [[clave, String(v)]];
  });
}

function TarjetaModelo({ m }: { m: Modelo }) {
  const metricas = aplanar(m.metricas);
  return (
    <section className="tarjeta pila">
      <div className="fila-entre">
        <div className="fila"><BrainCircuit size={20} color="var(--primario)" /><h2>{TIPO[m.tipo]} · {m.version}</h2></div>
        {m.activo ? <span className="insignia bajo"><span className="punto" />En uso</span> : <span className="insignia">Inactivo</span>}
      </div>
      <dl className="datos">
        <dt>Nombre</dt><dd>{m.nombre}</dd>
        <dt>Datos</dt><dd>{m.dataset}</dd>
        <dt>Umbrales</dt><dd>sospechoso desde {m.umbral_medio.toLocaleString("es-CO")} · peligroso desde {m.umbral_alto.toLocaleString("es-CO")}</dd>
        <dt>Registrado</dt><dd>{formatoFecha(m.creado_en)}</dd>
        <dt>Huella</dt><dd className="fila" style={{ gap: 6 }}><Fingerprint size={14} /><code title={m.sha256}>{m.sha256.slice(0, 16)}…</code></dd>
      </dl>
      {metricas.length > 0 && (
        <details className="plegable">
          <summary>Métricas de validación</summary>
          <dl className="datos">{metricas.map(([k, v]) => <Fragment key={k}><dt>{k}</dt><dd>{v}</dd></Fragment>)}</dl>
        </details>
      )}
    </section>
  );
}

export function PaginaModelos() {
  const lista = useQuery({ queryKey: ["admin", "modelos"], queryFn: admin.modelos });
  return (
    <>
      <div className="encabezado"><div><h1>Modelos de detección</h1>
        <p>Los modelos de machine learning que usa Centinela. Cada archivo se verifica con su huella SHA-256 antes de cargarse.</p></div></div>
      {lista.isPending ? <Esqueleto filas={6} /> : lista.isError ? <ErrorCarga error={lista.error} /> : lista.data.length === 0 ? (
        <div className="tarjeta"><Vacio titulo="No hay modelos registrados" icono={<BrainCircuit size={40} />}>
          <p>Registra uno con <code>uv run centinela modelos registrar &lt;carpeta&gt; --activar</code>.</p></Vacio></div>
      ) : (
        <div className="rejilla rejilla-2">
          {[...lista.data].sort((a, b) => Number(b.activo) - Number(a.activo) || b.id - a.id).map((m) => <TarjetaModelo key={m.id} m={m} />)}
        </div>
      )}
    </>
  );
}
