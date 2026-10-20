// Adjuntos de un correo (con el motivo si son peligrosos) y la etiqueta de dónde salió un enlace (QR o adjunto).
// Centinela nunca guarda los archivos: solo el nombre y el resultado de la inspección.

import { FileWarning, Paperclip, QrCode } from "lucide-react";
import type { Adjunto, Enlace } from "../api/tipos";
import { ORIGEN_ENLACE, formatoTamano } from "../utilidades/textos";

export function ListaAdjuntos({ adjuntos }: { adjuntos: Adjunto[] }) {
  return (
    <ul className="lista-adjuntos">
      {adjuntos.map((a, i) => (
        <li key={`${a.nombre}-${i}`} className={a.peligroso ? "peligroso" : undefined}>
          {a.peligroso ? <FileWarning size={16} aria-hidden /> : <Paperclip size={15} aria-hidden />}
          <div>
            <span className="nombre">{a.nombre}</span>
            {a.tamano_bytes != null && <span className="muy-tenue"> · {formatoTamano(a.tamano_bytes)}</span>}
            {a.peligroso && <span className="insignia alto" style={{ marginLeft: 8 }}>Peligroso</span>}
            {a.motivo && <div className="motivo">{a.motivo}</div>}
          </div>
        </li>
      ))}
    </ul>
  );
}

export function OrigenDelEnlace({ enlace }: { enlace: Enlace }) {
  if (!enlace.origen || enlace.origen === "cuerpo") return null;
  return (
    <span className="insignia info" title={enlace.origen === "qr" ? "Leído de un código QR en una imagen del correo" :
      "Escrito dentro de un archivo adjunto (PDF o página web)"}>
      {enlace.origen === "qr" && <QrCode size={12} aria-hidden />} {ORIGEN_ENLACE[enlace.origen]}
    </span>
  );
}
