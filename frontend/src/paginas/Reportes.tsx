// Reportes descargables: PDF para leer o imprimir y Excel para analizar las cifras. Los administradores también
// pueden descargar el de toda la organización, que trae solo cifras (ningún asunto ni remitente).

import { useMutation, useQuery } from "@tanstack/react-query";
import { Building2, Download, FileSpreadsheet, FileText, Lock, User } from "lucide-react";
import { useState, type ReactNode } from "react";
import { guardarArchivo, mensajeDeError } from "../api/cliente";
import { panel, reportes } from "../api/servicios";
import type { FormatoReporte } from "../api/tipos";
import { useTostadas } from "../componentes/Tostadas";
import { Girando, Pestanas } from "../componentes/ui";
import { useSesion } from "../sesion/Sesion";
import { formatoEntero } from "../utilidades/textos";

const PERIODOS = [
  { valor: "7", texto: "7 días" },
  { valor: "30", texto: "30 días" },
  { valor: "90", texto: "90 días" },
  { valor: "365", texto: "1 año" },
] as const;
type Periodo = (typeof PERIODOS)[number]["valor"];
type Alcance = "propio" | "organizacion";

const FORMATOS: Record<FormatoReporte, { titulo: string; detalle: string; icono: ReactNode; contenido: string[] }> = {
  pdf: {
    titulo: "PDF",
    detalle: "Para leer, imprimir o adjuntar a un informe.",
    icono: <FileText size={22} aria-hidden />,
    contenido: ["Indicadores del periodo", "Gráfico de correos de riesgo por día", "Tipos de amenaza y entidades suplantadas",
      "Detalle de cada correo de riesgo con sus razones"],
  },
  xlsx: {
    titulo: "Excel",
    detalle: "Para filtrar, ordenar y hacer tus propias gráficas.",
    icono: <FileSpreadsheet size={22} aria-hidden />,
    contenido: ["Hoja «Resumen» con todas las cifras", "Hoja «Por día» con su gráfico", "Hoja «Correos de riesgo» con filtros",
      "Fechas en hora de Colombia"],
  },
};

function TarjetaFormato({ formato, ocupado, descargar }: { formato: FormatoReporte; ocupado: boolean; descargar: () => void }) {
  const f = FORMATOS[formato];
  return (
    <section className="tarjeta formato-reporte">
      <div className="fila" style={{ gap: 12 }}>
        <span className={`icono-formato ${formato}`}>{f.icono}</span>
        <div>
          <h2>{f.titulo}</h2>
          <p className="tenue">{f.detalle}</p>
        </div>
      </div>
      <ul>{f.contenido.map((c) => <li key={c}>{c}</li>)}</ul>
      <button className="boton primario" onClick={descargar} disabled={ocupado} aria-label={`Descargar reporte en ${f.titulo}`}>
        {ocupado ? <Girando size={16} /> : <Download size={16} aria-hidden />} Descargar {f.titulo}
      </button>
    </section>
  );
}

export function PaginaReportes() {
  const { esAdmin } = useSesion();
  const avisar = useTostadas();
  const [periodo, setPeriodo] = useState<Periodo>("30");
  const [alcance, setAlcance] = useState<Alcance>("propio");
  const dias = Number(periodo);
  const organizacion = esAdmin && alcance === "organizacion";
  // Vista previa de las cifras (el resumen del panel llega hasta 90 días y es solo de los buzones propios)
  const previa = useQuery({ queryKey: ["resumen", dias], queryFn: () => panel.resumen(dias), enabled: dias <= 90 && !organizacion });

  const descarga = useMutation({
    mutationFn: (formato: FormatoReporte) => reportes.descargar(formato, dias, organizacion),
    onSuccess: (archivo) => {
      guardarArchivo(archivo);
      avisar(`Reporte descargado: ${archivo.nombre}`);
    },
    onError: (e) => avisar(mensajeDeError(e), "error"),
  });
  const ocupado = (f: FormatoReporte) => descarga.isPending && descarga.variables === f;
  const r = previa.data;

  return (
    <>
      <div className="encabezado">
        <div>
          <h1>Reportes</h1>
          <p>Descarga un resumen de lo que Centinela detectó, para guardarlo o compartirlo.</p>
        </div>
        <Pestanas etiqueta="Periodo del reporte" opciones={[...PERIODOS]} valor={periodo} cambiar={setPeriodo} />
      </div>

      {esAdmin && (
        <fieldset className="tarjeta alcance-reporte">
          <legend className="visualmente-oculto">Qué buzones incluye</legend>
          <label className={alcance === "propio" ? "activo" : undefined}>
            <input type="radio" name="alcance" checked={alcance === "propio"} onChange={() => setAlcance("propio")} />
            <User size={18} aria-hidden />
            <span><strong>Mis buzones</strong><span className="muy-tenue">Con el detalle de cada correo de riesgo.</span></span>
          </label>
          <label className={alcance === "organizacion" ? "activo" : undefined}>
            <input type="radio" name="alcance" checked={alcance === "organizacion"} onChange={() => setAlcance("organizacion")} />
            <Building2 size={18} aria-hidden />
            <span><strong>Toda la organización</strong>
              <span className="muy-tenue">Cifras de todos los buzones, sin asuntos ni remitentes.</span></span>
          </label>
        </fieldset>
      )}

      {r && (
        <p className="tenue resumen-reporte" aria-live="polite">
          En los últimos {dias} días: <strong>{formatoEntero(r.revisados)}</strong> correos revisados,{" "}
          <strong>{formatoEntero(r.sospechosos)}</strong> sospechosos y <strong>{formatoEntero(r.peligrosos)}</strong> peligrosos.
        </p>
      )}

      <div className="rejilla rejilla-2">
        <TarjetaFormato formato="pdf" ocupado={ocupado("pdf")} descargar={() => descarga.mutate("pdf")} />
        <TarjetaFormato formato="xlsx" ocupado={ocupado("xlsx")} descargar={() => descarga.mutate("xlsx")} />
      </div>

      <p className="muy-tenue fila" style={{ gap: 6 }}>
        <Lock size={14} aria-hidden />
        Los reportes no incluyen el contenido de los correos: Centinela no lo guarda. Cada descarga queda registrada.
      </p>
    </>
  );
}
