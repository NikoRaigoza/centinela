// Piezas visuales pequeñas y reutilizables.

import { AlertTriangle, CheckCircle2, Info, Inbox, RefreshCw, XCircle } from "lucide-react";
import type { ReactNode } from "react";
import { mensajeDeError } from "../api/cliente";
import type { EstadoCaso, Nivel, ResultadoAuth } from "../api/tipos";
import { AUTENTICACION, ESTADO_CASO, NIVEL } from "../utilidades/textos";

export function InsigniaNivel({ nivel }: { nivel: Nivel }) {
  return (
    <span className={`insignia ${nivel}`}>
      <span className="punto" aria-hidden />
      {NIVEL[nivel]}
    </span>
  );
}

const TONO_ESTADO: Record<EstadoCaso, string> = {
  nuevo: "medio",
  en_cuarentena: "alto",
  liberado: "info",
  confirmado: "",
  falso_positivo: "bajo",
};

export function InsigniaEstado({ estado }: { estado: EstadoCaso }) {
  return <span className={`insignia ${TONO_ESTADO[estado]}`}>{ESTADO_CASO[estado]}</span>;
}

export function ChipAutenticacion({ nombre, resultado }: { nombre: string; resultado: ResultadoAuth | null }) {
  const r = resultado ? AUTENTICACION[resultado] : null;
  const tono = r?.tono === "bien" ? "bajo" : r?.tono === "mal" ? "alto" : "";
  return (
    <span className={`insignia ${tono}`} title={`${nombre}: ${r?.texto ?? "sin dato"}`}>
      {nombre} · {r?.texto ?? "sin dato"}
    </span>
  );
}

type TipoAlerta = "info" | "error" | "aviso" | "exito";
const ICONO_ALERTA = { info: Info, error: XCircle, aviso: AlertTriangle, exito: CheckCircle2 };

export function Alerta({ tipo = "info", children }: { tipo?: TipoAlerta; children: ReactNode }) {
  const Icono = ICONO_ALERTA[tipo];
  return (
    <div className={`alerta ${tipo}`} role={tipo === "error" ? "alert" : "status"}>
      <Icono size={18} aria-hidden />
      <div>{children}</div>
    </div>
  );
}

export function Vacio({ titulo, children, icono }: { titulo: string; children?: ReactNode; icono?: ReactNode }) {
  return (
    <div className="vacio">
      {icono ?? <Inbox size={36} aria-hidden />}
      <h3>{titulo}</h3>
      {children}
    </div>
  );
}

export function Esqueleto({ filas = 3 }: { filas?: number }) {
  return (
    <div className="pila" aria-busy="true" aria-label="Cargando">
      {Array.from({ length: filas }, (_, i) => (
        <div key={i} className="esqueleto" style={{ width: `${90 - i * 12}%` }} />
      ))}
    </div>
  );
}

export function ErrorCarga({ error, reintentar }: { error: unknown; reintentar?: () => void }) {
  return (
    <Alerta tipo="error">
      <div className="fila-entre">
        <span>{mensajeDeError(error)}</span>
        {reintentar && (
          <button className="boton pequeno" onClick={reintentar}>
            <RefreshCw size={14} aria-hidden /> Reintentar
          </button>
        )}
      </div>
    </Alerta>
  );
}

export function Pestanas<T extends string>({
  opciones,
  valor,
  cambiar,
  etiqueta,
}: {
  opciones: { valor: T; texto: string }[];
  valor: T;
  cambiar: (v: T) => void;
  etiqueta: string;
}) {
  return (
    <div className="pestanas" role="tablist" aria-label={etiqueta}>
      {opciones.map((o) => (
        <button key={o.valor} role="tab" aria-selected={o.valor === valor} onClick={() => cambiar(o.valor)}>
          {o.texto}
        </button>
      ))}
    </div>
  );
}

export function Interruptor({
  activo,
  cambiar,
  texto,
  deshabilitado,
}: {
  activo: boolean;
  cambiar: (v: boolean) => void;
  texto: ReactNode;
  deshabilitado?: boolean;
}) {
  return (
    <label className="interruptor">
      <input type="checkbox" checked={activo} disabled={deshabilitado} onChange={(e) => cambiar(e.target.checked)} />
      <span className="riel" aria-hidden />
      <span>{texto}</span>
    </label>
  );
}

export function Girando({ size = 16 }: { size?: number }) {
  return <RefreshCw size={size} className="girando" aria-hidden />;
}
