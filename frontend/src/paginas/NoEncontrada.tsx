import { Compass } from "lucide-react";
import { Link } from "react-router";
import { Vacio } from "../componentes/ui";

export function PaginaNoEncontrada() {
  return (
    <div className="tarjeta">
      <Vacio titulo="Esta página no existe" icono={<Compass size={40} />}>
        <p>Puede que el enlace esté mal escrito o que no tengas permiso para verla.</p>
        <Link to="/" className="boton primario">Ir al inicio</Link>
      </Vacio>
    </div>
  );
}
