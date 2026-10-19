// Activación del doble factor (TOTP): código QR → primer código de 6 dígitos → códigos de recuperación.
// Se usa al iniciar sesión (administrador obligado) y desde "Mi cuenta" (opcional para usuarios).

import { useMutation, useQuery } from "@tanstack/react-query";
import { Copy, Download } from "lucide-react";
import { useState, type FormEvent } from "react";
import { mensajeDeError } from "../api/cliente";
import { auth } from "../api/servicios";
import type { Activacion2FA } from "../api/tipos";
import { CodigoQR } from "./CodigoQR";
import { Alerta, Esqueleto } from "./ui";

interface Props {
  /** Token de desafío del inicio de sesión. Sin él se usa la sesión actual. */
  tokenDesafio?: string;
  alTerminar: (resultado: Activacion2FA) => void;
}

export function Configurar2FA({ tokenDesafio, alTerminar }: Props) {
  const [codigo, setCodigo] = useState("");
  const [activado, setActivado] = useState<Activacion2FA | null>(null);
  const [guardados, setGuardados] = useState(false);

  const config = useQuery({
    queryKey: ["2fa-configuracion", tokenDesafio ?? "sesion"],
    queryFn: () => auth.iniciarConfig2fa(tokenDesafio),
    staleTime: Infinity,
    gcTime: 0,
    retry: false,
  });
  const confirmar = useMutation({
    mutationFn: () => auth.confirmarConfig2fa(codigo.trim(), tokenDesafio),
    onSuccess: setActivado,
  });

  if (activado) {
    const texto = activado.codigos_recuperacion.join("\n");
    const descargar = () => {
      const url = URL.createObjectURL(new Blob([`Códigos de recuperación de Centinela\n\n${texto}\n`], { type: "text/plain" }));
      const a = Object.assign(document.createElement("a"), { href: url, download: "centinela-codigos-recuperacion.txt" });
      a.click();
      URL.revokeObjectURL(url);
    };
    return (
      <div className="pila">
        <Alerta tipo="exito">El doble factor quedó activado.</Alerta>
        <p>
          Guarda estos <strong>códigos de recuperación</strong> en un lugar seguro. Cada uno sirve <strong>una sola vez</strong>{" "}
          para entrar si pierdes el celular. No volverás a verlos.
        </p>
        <div className="codigos">{activado.codigos_recuperacion.map((c) => <span key={c}>{c}</span>)}</div>
        <div className="fila">
          <button className="boton pequeno" type="button" onClick={() => void navigator.clipboard?.writeText(texto)}>
            <Copy size={14} aria-hidden /> Copiar
          </button>
          <button className="boton pequeno" type="button" onClick={descargar}>
            <Download size={14} aria-hidden /> Descargar .txt
          </button>
        </div>
        <label className="casilla">
          <input type="checkbox" checked={guardados} onChange={(e) => setGuardados(e.target.checked)} />
          <span>Ya guardé mis códigos de recuperación.</span>
        </label>
        <button className="boton primario" disabled={!guardados} onClick={() => alTerminar(activado)}>
          Continuar
        </button>
      </div>
    );
  }

  if (config.isPending) return <Esqueleto filas={4} />;
  if (config.isError) return <Alerta tipo="error">{mensajeDeError(config.error)}</Alerta>;

  const enviar = (e: FormEvent) => {
    e.preventDefault();
    if (codigo.trim().length === 6) confirmar.mutate();
  };
  return (
    <form className="pila" onSubmit={enviar}>
      <ol className="pila tenue" style={{ paddingLeft: 18, margin: 0, gap: 6 }}>
        <li>Instala una app autenticadora: Google Authenticator, Microsoft Authenticator o similar.</li>
        <li>Escanea este código con la app.</li>
        <li>Escribe el código de 6 dígitos que aparece en la app.</li>
      </ol>
      <div style={{ display: "grid", justifyItems: "center", gap: 8 }}>
        <CodigoQR texto={config.data.uri} descripcion="Código QR para configurar la app autenticadora" />
        <details className="plegable" style={{ width: "100%" }}>
          <summary>¿No puedes escanearlo? Escribe la clave a mano</summary>
          <div className="secreto">{config.data.secreto}</div>
        </details>
      </div>
      <div className="campo">
        <label htmlFor="codigo-2fa">Código de la app</label>
        <input id="codigo-2fa" className="entrada entrada-codigo" inputMode="numeric" autoComplete="one-time-code"
          maxLength={6} value={codigo} onChange={(e) => setCodigo(e.target.value.replace(/\D/g, ""))} autoFocus />
      </div>
      {confirmar.isError && <Alerta tipo="error">{mensajeDeError(confirmar.error)}</Alerta>}
      <button className="boton primario" disabled={codigo.length !== 6 || confirmar.isPending}>
        {confirmar.isPending ? "Verificando…" : "Activar doble factor"}
      </button>
    </form>
  );
}
