// Muestra las respuestas del asistente con el formato mínimo que usa (párrafos, listas, **negrita**).
// Se arma con elementos de React, nunca con HTML: aunque la respuesta traiga etiquetas, se ven como texto.

import { Fragment, type ReactNode } from "react";

function enLinea(texto: string): ReactNode[] {
  const partes = texto.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return partes.filter(Boolean).map((p, i) => {
    if (p.startsWith("**") && p.endsWith("**") && p.length > 4) return <strong key={i}>{p.slice(2, -2)}</strong>;
    if (p.startsWith("`") && p.endsWith("`") && p.length > 2) return <code key={i}>{p.slice(1, -1)}</code>;
    return p;
  });
}

type Bloque = { tipo: "p"; lineas: string[] } | { tipo: "ul" | "ol"; items: string[] };

const VINETA = /^\s*[-*•]\s+/;
const NUMERO = /^\s*\d+[.)]\s+/;

function bloques(texto: string): Bloque[] {
  const salida: Bloque[] = [];
  for (const cruda of texto.replace(/\r\n/g, "\n").split("\n")) {
    const linea = cruda.replace(/^#{1,6}\s+/, "");      // títulos markdown: se muestran como texto normal
    const ultimo = salida[salida.length - 1];
    const tipo = VINETA.test(linea) ? "ul" : NUMERO.test(linea) ? "ol" : linea.trim() ? "p" : null;
    if (tipo === null) {
      salida.push({ tipo: "p", lineas: [] });            // línea en blanco: cierra el bloque actual
    } else if (tipo === "p") {
      if (ultimo?.tipo === "p") ultimo.lineas.push(linea.trim());
      else salida.push({ tipo: "p", lineas: [linea.trim()] });
    } else {
      const item = linea.replace(tipo === "ul" ? VINETA : NUMERO, "");
      if (ultimo?.tipo === tipo) ultimo.items.push(item);
      else salida.push({ tipo, items: [item] });
    }
  }
  return salida.filter((b) => (b.tipo === "p" ? b.lineas.length > 0 : true));
}

export function TextoAsistente({ texto }: { texto: string }) {
  return (
    <div className="texto-asistente">
      {bloques(texto).map((b, i) => {
        if (b.tipo === "p") {
          return <p key={i}>{b.lineas.map((l, j) => <Fragment key={j}>{j > 0 && <br />}{enLinea(l)}</Fragment>)}</p>;
        }
        const Lista = b.tipo;
        return <Lista key={i}>{b.items.map((t, j) => <li key={j}>{enLinea(t)}</li>)}</Lista>;
      })}
    </div>
  );
}
