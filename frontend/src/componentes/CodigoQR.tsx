// Código QR para la app autenticadora. Se genera EN el navegador: el secreto del doble factor nunca se envía a
// un servicio externo de códigos QR.

import QRCode from "qrcode";
import { useEffect, useState } from "react";

export function CodigoQR({ texto, descripcion }: { texto: string; descripcion: string }) {
  const [imagen, setImagen] = useState<string | null>(null);

  useEffect(() => {
    let vigente = true;
    QRCode.toDataURL(texto, { margin: 1, width: 352, errorCorrectionLevel: "M" })
      .then((url) => vigente && setImagen(url))
      .catch(() => vigente && setImagen(null));
    return () => {
      vigente = false;
    };
  }, [texto]);

  return imagen ? <img className="qr" src={imagen} alt={descripcion} /> : <div className="qr esqueleto" aria-label="Generando código QR" />;
}
