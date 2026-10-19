// Solicitud de cuenta. La cuenta queda pendiente hasta que un administrador la aprueba.

import { useMutation } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { mensajeDeError } from "../api/cliente";
import { auth } from "../api/servicios";
import { Alerta } from "../componentes/ui";
import { MarcoAcceso } from "./Acceso";

export function PaginaRegistro() {
  const [nombre, setNombre] = useState("");
  const [correo, setCorreo] = useState("");
  const [clave, setClave] = useState("");
  const [repetida, setRepetida] = useState("");
  const registro = useMutation({ mutationFn: () => auth.registrar(correo.trim(), nombre.trim(), clave) });
  const noCoinciden = repetida.length > 0 && repetida !== clave;

  if (registro.isSuccess) {
    return (
      <MarcoAcceso>
        <h1>Solicitud enviada</h1>
        <Alerta tipo="exito">{registro.data.mensaje}</Alerta>
        <Link className="boton primario" to="/ingreso">Ir a iniciar sesión</Link>
      </MarcoAcceso>
    );
  }

  const enviar = (e: FormEvent) => {
    e.preventDefault();
    if (!noCoinciden) registro.mutate();
  };
  return (
    <MarcoAcceso>
      <div className="pila">
        <h1>Solicita acceso</h1>
        <p className="tenue">Un administrador revisará tu solicitud. Después podrás conectar tu Gmail.</p>
      </div>
      <form onSubmit={enviar}>
        <div className="campo">
          <label htmlFor="nombre">Nombre</label>
          <input id="nombre" className="entrada" autoComplete="name" required maxLength={120} value={nombre}
            onChange={(e) => setNombre(e.target.value)} autoFocus />
        </div>
        <div className="campo">
          <label htmlFor="correo">Correo</label>
          <input id="correo" className="entrada" type="email" autoComplete="email" required maxLength={254} value={correo}
            onChange={(e) => setCorreo(e.target.value)} />
        </div>
        <div className="campo">
          <label htmlFor="clave">Contraseña</label>
          <input id="clave" className="entrada" type="password" autoComplete="new-password" required minLength={10} maxLength={128}
            value={clave} onChange={(e) => setClave(e.target.value)} aria-describedby="ayuda-clave" />
          <span className="ayuda" id="ayuda-clave">Mínimo 10 caracteres, con letras y números. Una frase larga es más segura.</span>
        </div>
        <div className="campo">
          <label htmlFor="repetida">Repite la contraseña</label>
          <input id="repetida" className="entrada" type="password" autoComplete="new-password" required value={repetida}
            onChange={(e) => setRepetida(e.target.value)} aria-invalid={noCoinciden} />
          {noCoinciden && <span className="ayuda" style={{ color: "var(--alto)" }}>Las contraseñas no coinciden.</span>}
        </div>
        {registro.isError && <Alerta tipo="error">{mensajeDeError(registro.error)}</Alerta>}
        <button className="boton primario" disabled={registro.isPending || noCoinciden}>
          {registro.isPending ? "Enviando…" : "Enviar solicitud"}
        </button>
      </form>
      <p className="tenue">¿Ya tienes cuenta? <Link to="/ingreso">Inicia sesión</Link></p>
    </MarcoAcceso>
  );
}
