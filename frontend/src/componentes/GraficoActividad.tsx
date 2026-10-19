// Correos revisados por día, apilados por nivel de riesgo (peligrosos abajo, luego sospechosos, luego sin riesgo).
// Las tres partes suman el total revisado del día. Incluye globo al pasar el cursor y una tabla con los datos.

import { useEffect, useRef, useState } from "react";
import type { DiaResumen } from "../api/tipos";
import { formatoDia, formatoEntero } from "../utilidades/textos";

const ALTO_SVG = 220;
const M = { arriba: 12, derecha: 8, abajo: 26, izquierda: 36 };
const GROSOR_MAX = 24;
const HUECO = 2;            // separación del color de fondo entre segmentos apilados
const RADIO = 4;

function marcasEje(maximo: number): number[] {
  if (maximo <= 0) return [0, 1];
  const paso0 = maximo / 4;
  const potencia = 10 ** Math.floor(Math.log10(paso0));
  const paso = [1, 2, 5, 10].map((f) => f * potencia).find((p) => p >= paso0) ?? potencia * 10;
  const pasoEntero = Math.max(1, Math.ceil(paso));
  const marcas = [];
  for (let v = 0; v <= maximo + pasoEntero - 1; v += pasoEntero) marcas.push(v);
  return marcas;
}

const compacto = (v: number) => (v >= 1000 ? `${(v / 1000).toLocaleString("es-CO", { maximumFractionDigits: 1 })} mil` : String(v));

/** Rectángulo con las esquinas superiores redondeadas (la base queda recta, apoyada en el eje). */
function barraRedondeada(x: number, y: number, ancho: number, alto: number, r: number): string {
  const rr = Math.min(r, alto, ancho / 2);
  return `M${x},${y + alto}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + ancho - rr}Q${x + ancho},${y} ${x + ancho},${y + rr}V${y + alto}Z`;
}

export function GraficoActividad({ serie }: { serie: DiaResumen[] }) {
  const contenedor = useRef<HTMLDivElement>(null);
  const [ancho, setAncho] = useState(640);
  const [foco, setFoco] = useState<number | null>(null);

  useEffect(() => {
    const el = contenedor.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const obs = new ResizeObserver(([e]) => e && setAncho(Math.max(280, e.contentRect.width)));
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  const marcas = marcasEje(Math.max(0, ...serie.map((d) => d.revisados)));
  const tope = marcas[marcas.length - 1] ?? 1;
  const anchoUtil = ancho - M.izquierda - M.derecha;
  const altoUtil = ALTO_SVG - M.arriba - M.abajo;
  const banda = anchoUtil / Math.max(1, serie.length);
  const grosor = Math.min(GROSOR_MAX, Math.max(3, banda * 0.62));
  const y = (v: number) => M.arriba + altoUtil - (v / tope) * altoUtil;
  const cadaCuanto = Math.ceil(serie.length / Math.max(2, Math.floor(anchoUtil / 64)));
  const dFoco = foco != null ? serie[foco] : undefined;

  return (
    <div className="pila">
      <div className="leyenda" aria-hidden>
        <span><i style={{ background: "var(--serie-alto)" }} />Peligrosos</span>
        <span><i style={{ background: "var(--serie-medio)" }} />Sospechosos</span>
        <span><i style={{ background: "var(--serie-sin-riesgo)" }} />Sin riesgo</span>
      </div>
      <div ref={contenedor} style={{ position: "relative" }} onMouseLeave={() => setFoco(null)}>
        <svg className="grafico" viewBox={`0 0 ${ancho} ${ALTO_SVG}`} width={ancho} height={ALTO_SVG} role="img"
          aria-label={`Correos revisados por día en los últimos ${serie.length} días, por nivel de riesgo`}>
          {marcas.map((m) => (
            <g key={m}>
              <line className="guia" x1={M.izquierda} x2={ancho - M.derecha} y1={y(m)} y2={y(m)} />
              <text className="eje" x={M.izquierda - 8} y={y(m)} dy="0.32em" textAnchor="end">{compacto(m)}</text>
            </g>
          ))}
          {serie.map((d, i) => {
            const x0 = M.izquierda + i * banda;
            const x = x0 + (banda - grosor) / 2;
            const sinRiesgo = Math.max(0, d.revisados - d.sospechosos - d.peligrosos);
            const partes = [
              { clase: "peligrosos", valor: d.peligrosos },
              { clase: "sospechosos", valor: d.sospechosos },
              { clase: "sin-riesgo", valor: sinRiesgo },
            ].filter((p) => p.valor > 0);
            let base = 0;
            return (
              <g key={d.fecha}>
                {foco === i && <rect className="foco" x={x0} y={M.arriba} width={banda} height={altoUtil} />}
                {partes.map((p, j) => {
                  const yArriba = y(base + p.valor);
                  const yAbajo = y(base) - (j > 0 ? HUECO : 0);
                  base += p.valor;
                  const alto = Math.max(1, yAbajo - yArriba);
                  const ultima = j === partes.length - 1;
                  return ultima
                    ? <path key={p.clase} className={p.clase} d={barraRedondeada(x, yArriba, grosor, alto, RADIO)} />
                    : <rect key={p.clase} className={p.clase} x={x} y={yArriba} width={grosor} height={alto} />;
                })}
                {i % cadaCuanto === 0 && (
                  <text className="eje" x={x0 + banda / 2} y={ALTO_SVG - 8} textAnchor="middle">{formatoDia(d.fecha)}</text>
                )}
                {/* zona sensible: toda la columna, más grande que la barra */}
                <rect x={x0} y={M.arriba} width={banda} height={altoUtil} fill="transparent"
                  onMouseEnter={() => setFoco(i)} onFocus={() => setFoco(i)} onBlur={() => setFoco(null)} tabIndex={-1} />
              </g>
            );
          })}
          <line className="guia" x1={M.izquierda} x2={ancho - M.derecha} y1={y(0)} y2={y(0)} />
        </svg>
        {dFoco && foco != null && (
          <div className="globo" style={{ left: M.izquierda + (foco + 0.5) * banda, top: y(dFoco.revisados) }}>
            <strong>{formatoDia(dFoco.fecha)}</strong>
            <br />
            {formatoEntero(dFoco.revisados)} revisados
            <br />
            {formatoEntero(dFoco.peligrosos)} peligrosos · {formatoEntero(dFoco.sospechosos)} sospechosos
          </div>
        )}
      </div>
      <details className="plegable">
        <summary>Ver los datos en tabla</summary>
        <div className="tabla-contenedor">
          <table className="tabla">
            <thead>
              <tr><th>Día</th><th className="num">Revisados</th><th className="num">Sospechosos</th><th className="num">Peligrosos</th></tr>
            </thead>
            <tbody>
              {serie.filter((d) => d.revisados > 0).map((d) => (
                <tr key={d.fecha}>
                  <td>{formatoDia(d.fecha)}</td>
                  <td className="num">{formatoEntero(d.revisados)}</td>
                  <td className="num">{formatoEntero(d.sospechosos)}</td>
                  <td className="num">{formatoEntero(d.peligrosos)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
