// Mensajes breves de confirmación o error tras una acción ("Correo liberado", "No se pudo conectar…").

import { CheckCircle2, XCircle } from "lucide-react";
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

interface Tostada {
  id: number;
  texto: string;
  tipo: "exito" | "error";
}

type Avisar = (texto: string, tipo?: Tostada["tipo"]) => void;
const Contexto = createContext<Avisar>(() => undefined);
let siguiente = 1;

export function ProveedorTostadas({ children }: { children: ReactNode }) {
  const [tostadas, setTostadas] = useState<Tostada[]>([]);

  const avisar = useCallback<Avisar>((texto, tipo = "exito") => {
    const id = siguiente++;
    setTostadas((t) => [...t.slice(-2), { id, texto, tipo }]);
    setTimeout(() => setTostadas((t) => t.filter((x) => x.id !== id)), tipo === "error" ? 7000 : 4000);
  }, []);

  const valor = useMemo(() => avisar, [avisar]);
  return (
    <Contexto.Provider value={valor}>
      {children}
      <div className="tostadas" aria-live="polite">
        {tostadas.map((t) => (
          <div key={t.id} className={`tostada ${t.tipo}`} role={t.tipo === "error" ? "alert" : "status"}>
            {t.tipo === "error" ? <XCircle size={18} aria-hidden /> : <CheckCircle2 size={18} aria-hidden />}
            <span>{t.texto}</span>
          </div>
        ))}
      </div>
    </Contexto.Provider>
  );
}

export const useTostadas = () => useContext(Contexto);
