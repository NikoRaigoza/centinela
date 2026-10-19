// Mi cuenta: datos, notificaciones push, cambio de contraseña y doble factor.

import { useMutation } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { mensajeDeError } from "../api/cliente";
import { cuenta } from "../api/servicios";
import { Configurar2FA } from "../componentes/Configurar2FA";
import { Notificaciones } from "../componentes/Notificaciones";
import { useTostadas } from "../componentes/Tostadas";
import { Alerta } from "../componentes/ui";
import { useSesion, useUsuario } from "../sesion/Sesion";
import { formatoFechaHora } from "../utilidades/textos";

function CambiarClave() {
  const { entrar } = useSesion();
  const avisar = useTostadas();
  const [actual, setActual] = useState("");
  const [nueva, setNueva] = useState("");
  const [repetida, setRepetida] = useState("");
  const cambio = useMutation({
    mutationFn: () => cuenta.cambiarClave(actual, nueva),
    onSuccess: (acceso) => {
      entrar(acceso);                    // el backend cierra las demás sesiones y abre una nueva
      setActual(""); setNueva(""); setRepetida("");
      avisar("Contraseña actualizada. Cerramos tus sesiones en otros dispositivos.");
    },
  });
  const noCoinciden = repetida.length > 0 && repetida !== nueva;
  const enviar = (e: FormEvent) => {
    e.preventDefault();
    if (!noCoinciden) cambio.mutate();
  };
  return (
    <form className="pila" onSubmit={enviar}>
      <div className="campo">
        <label htmlFor="actual">Contraseña actual</label>
        <input id="actual" className="entrada" type="password" autoComplete="current-password" required value={actual} onChange={(e) => setActual(e.target.value)} />
      </div>
      <div className="campo">
        <label htmlFor="nueva">Contraseña nueva</label>
        <input id="nueva" className="entrada" type="password" autoComplete="new-password" required minLength={10} maxLength={128}
          value={nueva} onChange={(e) => setNueva(e.target.value)} />
        <span className="ayuda">Mínimo 10 caracteres, con letras y números.</span>
      </div>
      <div className="campo">
        <label htmlFor="repetida">Repite la contraseña nueva</label>
        <input id="repetida" className="entrada" type="password" autoComplete="new-password" required value={repetida}
          onChange={(e) => setRepetida(e.target.value)} aria-invalid={noCoinciden} />
        {noCoinciden && <span className="ayuda" style={{ color: "var(--alto)" }}>Las contraseñas no coinciden.</span>}
      </div>
      {cambio.isError && <Alerta tipo="error">{mensajeDeError(cambio.error)}</Alerta>}
      <button className="boton primario" style={{ justifySelf: "start" }} disabled={cambio.isPending || noCoinciden}>
        {cambio.isPending ? "Guardando…" : "Cambiar contraseña"}
      </button>
    </form>
  );
}

function DobleFactor() {
  const usuario = useUsuario();
  const { actualizarUsuario } = useSesion();
  const [configurando, setConfigurando] = useState(false);
  const avisar = useTostadas();

  if (usuario.totp_activo) {
    return (
      <Alerta tipo="exito">
        <strong>Activado.</strong> Al iniciar sesión te pediremos el código de tu app autenticadora. Si pierdes el celular, usa uno de tus
        códigos de recuperación.
      </Alerta>
    );
  }
  if (configurando) {
    return (
      <Configurar2FA alTerminar={() => {
        setConfigurando(false);
        void cuenta.yo().then(actualizarUsuario);
        avisar("Doble factor activado.");
      }} />
    );
  }
  return (
    <div className="pila">
      <p className="tenue">Además de tu contraseña, te pediremos un código de 6 dígitos que cambia cada 30 segundos en tu celular. Así, aunque alguien robe tu contraseña, no podrá entrar.</p>
      <button className="boton primario" style={{ justifySelf: "start" }} onClick={() => setConfigurando(true)}>
        <ShieldCheck size={16} /> Activar doble factor
      </button>
    </div>
  );
}

export function PaginaCuenta() {
  const usuario = useUsuario();
  return (
    <>
      <div className="encabezado"><div><h1>Mi cuenta</h1><p>Tus datos, tus avisos y la seguridad de tu acceso al panel.</p></div></div>
      <section className="tarjeta">
        <h2>Datos</h2>
        <dl className="datos">
          <dt>Nombre</dt><dd>{usuario.nombre}</dd>
          <dt>Correo</dt><dd>{usuario.correo}</dd>
          <dt>Rol</dt><dd>{usuario.rol === "administrador" ? "Administrador" : "Usuario"}</dd>
          <dt>Último acceso</dt><dd>{formatoFechaHora(usuario.ultimo_acceso)}</dd>
          <dt>Cuenta creada</dt><dd>{formatoFechaHora(usuario.creado_en)}</dd>
        </dl>
      </section>
      <section className="tarjeta" id="notificaciones"><h2>Notificaciones</h2><Notificaciones /></section>
      <div className="rejilla rejilla-2">
        <section className="tarjeta"><h2>Doble factor (2FA)</h2><DobleFactor /></section>
        <section className="tarjeta"><h2>Cambiar contraseña</h2><CambiarClave /></section>
      </div>
    </>
  );
}
