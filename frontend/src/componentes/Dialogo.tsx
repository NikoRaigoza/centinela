// Diálogo de confirmación para acciones con consecuencias (liberar un correo, desconectar un buzón…).

import { useEffect, useId, useRef, type ReactNode } from "react";

interface Props {
  abierto: boolean;
  titulo: string;
  children: ReactNode;
  textoConfirmar: string;
  tono?: "primario" | "peligro" | "exito";
  ocupado?: boolean;
  confirmar: () => void;
  cancelar: () => void;
}

export function DialogoConfirmar({ abierto, titulo, children, textoConfirmar, tono = "primario", ocupado, confirmar, cancelar }: Props) {
  const id = useId();
  const caja = useRef<HTMLDivElement>(null);
  const previo = useRef<Element | null>(null);

  useEffect(() => {
    if (!abierto) return;
    previo.current = document.activeElement;
    caja.current?.querySelector<HTMLElement>("[data-autofoco]")?.focus();
    const alTeclear = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !ocupado) cancelar();
      if (e.key === "Tab" && caja.current) {               // el foco no se escapa del diálogo
        const enfocables = caja.current.querySelectorAll<HTMLElement>("button, textarea, input, select, a[href]");
        const primero = enfocables[0];
        const ultimo = enfocables[enfocables.length - 1];
        if (e.shiftKey && document.activeElement === primero) {
          e.preventDefault();
          ultimo?.focus();
        } else if (!e.shiftKey && document.activeElement === ultimo) {
          e.preventDefault();
          primero?.focus();
        }
      }
    };
    document.addEventListener("keydown", alTeclear);
    return () => {
      document.removeEventListener("keydown", alTeclear);
      (previo.current as HTMLElement | null)?.focus?.();
    };
  }, [abierto, ocupado, cancelar]);

  if (!abierto) return null;
  return (
    <div className="dialogo-fondo" onMouseDown={(e) => e.target === e.currentTarget && !ocupado && cancelar()}>
      <div className="dialogo" role="dialog" aria-modal="true" aria-labelledby={id} ref={caja}>
        <h2 id={id}>{titulo}</h2>
        <div className="pila tenue">{children}</div>
        <div className="acciones">
          <button className="boton" onClick={cancelar} disabled={ocupado}>
            Cancelar
          </button>
          <button className={`boton ${tono}`} onClick={confirmar} disabled={ocupado} data-autofoco>
            {ocupado ? "Un momento…" : textoConfirmar}
          </button>
        </div>
      </div>
    </div>
  );
}
