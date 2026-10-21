// Inicio de sesión: contraseña → (si el administrador le asignó una temporal) elegir la definitiva → código del doble
// factor, o configurarlo por primera vez (obligatorio para administradores).

import { useMutation } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { ErrorApi, mensajeDeError } from "../api/cliente";
import { auth } from "../api/servicios";
import type { RespuestaInicio, TokenAcceso } from "../api/tipos";
import { Configurar2FA } from "../componentes/Configurar2FA";
import { Alerta } from "../componentes/ui";
import { useSesion } from "../sesion/Sesion";
import { MarcoAcceso } from "./Acceso";

type Paso =
  | { tipo: "clave" }
  | { tipo: "verificar"; token: string }
  | { tipo: "configurar"; token: string }
  | { tipo: "cambiar"; token: string };

export function PaginaIngreso() {
  const [paso, setPaso] = useState<Paso>({ tipo: "clave" });
  const [correo, setCorreo] = useState("");
  const [clave, setClave] = useState("");
  const [codigo, setCodigo] = useState("");
  const [usarRecuperacion, setUsarRecuperacion] = useState(false);
  const { entrar } = useSesion();
  // Al entrar, la ruta de acceso redirige sola a la página pedida (ver SinSesion en app/rutas.tsx)
  const completar = (acceso: TokenAcceso) => entrar(acceso);

  const seguir = (r: RespuestaInicio) => {
    if (r.paso === "completo" && r.acceso) completar(r.acceso);
    else if (r.paso === "verificar_2fa" && r.token_desafio) setPaso({ tipo: "verificar", token: r.token_desafio });
    else if (r.paso === "configurar_2fa" && r.token_desafio) setPaso({ tipo: "configurar", token: r.token_desafio });
    else if (r.paso === "cambiar_clave" && r.token_desafio) setPaso({ tipo: "cambiar", token: r.token_desafio });
  };
  const inicio = useMutation({
    mutationFn: () => auth.iniciar(correo.trim(), clave),
    onSuccess: (r) => {
      setClave("");
      seguir(r);
    },
  });
  const [nueva, setNueva] = useState("");
  const [repetida, setRepetida] = useState("");
  const cambio = useMutation({
    mutationFn: (token: string) => auth.cambiarClaveTemporal(nueva, token),
    onSuccess: (r) => {
      setNueva("");
      setRepetida("");
      seguir(r);
    },
    onError: (e) => {
      if (e instanceof ErrorApi && e.estado === 401) setPaso({ tipo: "clave" });
    },
  });

  const verificacion = useMutation({
    mutationFn: (token: string) => auth.verificar2fa(codigo.trim(), token),
    onSuccess: completar,
    onError: (e) => {
      if (e instanceof ErrorApi && e.estado === 401 && /expir/i.test(e.message)) setPaso({ tipo: "clave" });
    },
  });

  const reiniciar = () => {
    setPaso({ tipo: "clave" });
    setCodigo("");
    inicio.reset();
    verificacion.reset();
    cambio.reset();
  };

  if (paso.tipo === "cambiar") {
    const noCoinciden = repetida.length > 0 && repetida !== nueva;
    const enviar = (e: FormEvent) => {
      e.preventDefault();
      if (!noCoinciden) cambio.mutate(paso.token);
    };
    return (
      <MarcoAcceso>
        <div className="pila">
          <h1>Elige tu nueva contraseña</h1>
          <p className="tenue">Entraste con una contraseña temporal que te dio el administrador. Antes de seguir, elige una
            que solo tú conozcas.</p>
        </div>
        <form onSubmit={enviar}>
          <div className="campo">
            <label htmlFor="nueva">Nueva contraseña</label>
            <input id="nueva" className="entrada" type="password" autoComplete="new-password" required minLength={10}
              maxLength={128} value={nueva} onChange={(e) => setNueva(e.target.value)} autoFocus aria-describedby="ayuda-nueva" />
            <span className="ayuda" id="ayuda-nueva">Mínimo 10 caracteres, con letras y números.</span>
          </div>
          <div className="campo">
            <label htmlFor="repetida">Repite la contraseña</label>
            <input id="repetida" className="entrada" type="password" autoComplete="new-password" required value={repetida}
              onChange={(e) => setRepetida(e.target.value)} aria-invalid={noCoinciden} />
            {noCoinciden && <span className="ayuda" style={{ color: "var(--alto)" }}>Las contraseñas no coinciden.</span>}
          </div>
          {cambio.isError && <Alerta tipo="error">{mensajeDeError(cambio.error)}</Alerta>}
          <button className="boton primario" disabled={cambio.isPending || noCoinciden}>
            {cambio.isPending ? "Guardando…" : "Guardar y entrar"}
          </button>
        </form>
        <button className="boton fantasma" onClick={reiniciar}><ArrowLeft size={16} /> Volver</button>
      </MarcoAcceso>
    );
  }

  if (paso.tipo === "configurar") {
    return (
      <MarcoAcceso>
        <div className="pila">
          <h1>Protege tu cuenta</h1>
          <p className="tenue">
            Las cuentas de administrador deben usar doble factor: además de la contraseña, un código que cambia cada 30 segundos en tu celular.
          </p>
        </div>
        <Configurar2FA tokenDesafio={paso.token} alTerminar={(r) => (r.acceso ? completar(r.acceso) : reiniciar())} />
        <button className="boton fantasma" onClick={reiniciar}><ArrowLeft size={16} /> Volver</button>
      </MarcoAcceso>
    );
  }

  if (paso.tipo === "verificar") {
    const enviar = (e: FormEvent) => {
      e.preventDefault();
      verificacion.mutate(paso.token);
    };
    return (
      <MarcoAcceso>
        <div className="pila">
          <h1>Verificación en dos pasos</h1>
          <p className="tenue">
            {usarRecuperacion
              ? "Escribe uno de tus códigos de recuperación. Cada código sirve una sola vez."
              : "Abre tu app autenticadora y escribe el código de 6 dígitos."}
          </p>
        </div>
        <form onSubmit={enviar}>
          <div className="campo">
            <label htmlFor="codigo">{usarRecuperacion ? "Código de recuperación" : "Código de la app"}</label>
            {usarRecuperacion ? (
              <input id="codigo" className="entrada" autoComplete="off" value={codigo} onChange={(e) => setCodigo(e.target.value)}
                maxLength={20} autoFocus />
            ) : (
              <input id="codigo" className="entrada entrada-codigo" inputMode="numeric" autoComplete="one-time-code" maxLength={6}
                value={codigo} onChange={(e) => setCodigo(e.target.value.replace(/\D/g, ""))} autoFocus />
            )}
          </div>
          {verificacion.isError && <Alerta tipo="error">{mensajeDeError(verificacion.error)}</Alerta>}
          <button className="boton primario" disabled={codigo.trim().length < 6 || verificacion.isPending}>
            {verificacion.isPending ? "Verificando…" : "Entrar"}
          </button>
        </form>
        <div className="fila-entre">
          <button className="boton fantasma pequeno" onClick={reiniciar}><ArrowLeft size={15} /> Volver</button>
          <button className="boton fantasma pequeno" onClick={() => { setUsarRecuperacion((v) => !v); setCodigo(""); }}>
            {usarRecuperacion ? "Usar la app autenticadora" : "Usar un código de recuperación"}
          </button>
        </div>
      </MarcoAcceso>
    );
  }

  const enviar = (e: FormEvent) => {
    e.preventDefault();
    inicio.mutate();
  };
  return (
    <MarcoAcceso>
      <div className="pila">
        <h1>Inicia sesión</h1>
        <p className="tenue">Entra al panel para revisar los correos que Centinela detuvo.</p>
      </div>
      <form onSubmit={enviar}>
        <div className="campo">
          <label htmlFor="correo">Correo</label>
          <input id="correo" className="entrada" type="email" autoComplete="username" required value={correo}
            onChange={(e) => setCorreo(e.target.value)} autoFocus />
        </div>
        <div className="campo">
          <label htmlFor="clave">Contraseña</label>
          <input id="clave" className="entrada" type="password" autoComplete="current-password" required value={clave}
            onChange={(e) => setClave(e.target.value)} />
        </div>
        {inicio.isError && <Alerta tipo="error">{mensajeDeError(inicio.error)}</Alerta>}
        <button className="boton primario" disabled={inicio.isPending}>{inicio.isPending ? "Entrando…" : "Entrar"}</button>
      </form>
      <p className="tenue">¿No tienes cuenta? <Link to="/registro">Solicita acceso</Link></p>
      <p className="muy-tenue">¿Olvidaste tu contraseña? Pídele al administrador una contraseña temporal.</p>
    </MarcoAcceso>
  );
}
