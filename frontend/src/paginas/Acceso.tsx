// Marco de las pantallas sin sesión (ingreso y registro): a la izquierda qué es Centinela, a la derecha el formulario.

import { EyeOff, MessageSquareText, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router";
import { Escudo } from "../componentes/Escudo";

export function MarcoAcceso({ children }: { children: ReactNode }) {
  return (
    <div className="acceso">
      <section className="acceso-lado">
        <div className="fila" style={{ color: "#fff" }}>
          <Escudo tamano={34} />
          <strong style={{ fontSize: "1.3rem" }}>Centinela</strong>
        </div>
        <div className="pila" style={{ gap: 22 }}>
          <h1>Detecta el phishing que llega a tu Gmail antes de que caigas.</h1>
          <ul>
            <li><ShieldCheck size={20} />Revisa cada correo apenas llega y aparta los peligrosos en cuarentena, sin borrarlos.</li>
            <li><MessageSquareText size={20} />Te explica en español, con máximo tres razones, por qué un correo es sospechoso.</li>
            <li><EyeOff size={20} />Conoce las entidades que más suplantan en Colombia: DIAN, Bancolombia, Nequi y más.</li>
          </ul>
        </div>
        <p className="pie-lado" style={{ fontSize: "0.82rem", opacity: 0.7 }}>
          Centinela nunca te pedirá tu contraseña por correo ni por mensaje.
        </p>
      </section>
      <section className="acceso-formulario">
        <div className="acceso-caja">
          {children}
          <nav className="enlaces-legales muy-tenue" aria-label="Información legal">
            <Link to="/privacidad">Política de privacidad</Link> · <Link to="/terminos">Términos de uso</Link>
          </nav>
        </div>
      </section>
    </div>
  );
}
