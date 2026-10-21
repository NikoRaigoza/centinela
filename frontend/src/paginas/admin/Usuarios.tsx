// Administración de cuentas: aprobar o rechazar solicitudes, desactivar, reactivar y dar una contraseña temporal a
// quien olvidó la suya.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, KeyRound, ShieldCheck, Users } from "lucide-react";
import { useState } from "react";
import { mensajeDeError } from "../../api/cliente";
import { admin } from "../../api/servicios";
import type { AccionCuenta, EstadoCuenta, Usuario } from "../../api/tipos";
import { DialogoConfirmar } from "../../componentes/Dialogo";
import { useTostadas } from "../../componentes/Tostadas";
import { ErrorCarga, Esqueleto, Pestanas, Vacio } from "../../componentes/ui";
import { useUsuario } from "../../sesion/Sesion";
import { ESTADO_CUENTA, formatoFechaHora, haceCuanto } from "../../utilidades/textos";

const ACCIONES: Record<EstadoCuenta, AccionCuenta[]> = {
  pendiente: ["aprobar", "rechazar"],
  activo: ["desactivar"],
  desactivado: ["reactivar"],
  rechazado: [],
};
const TEXTO: Record<AccionCuenta, { boton: string; tono: "primario" | "peligro" | "exito"; pregunta: string; hecho: string }> = {
  aprobar: { boton: "Aprobar", tono: "exito", pregunta: "podrá iniciar sesión y conectar sus buzones de Gmail.", hecho: "Cuenta aprobada." },
  rechazar: { boton: "Rechazar", tono: "peligro", pregunta: "no podrá entrar al panel.", hecho: "Solicitud rechazada." },
  desactivar: { boton: "Desactivar", tono: "peligro", pregunta: "perderá el acceso y se cerrarán sus sesiones abiertas.", hecho: "Cuenta desactivada." },
  reactivar: { boton: "Reactivar", tono: "primario", pregunta: "podrá volver a iniciar sesión.", hecho: "Cuenta reactivada." },
};
const TONO: Record<EstadoCuenta, string> = { pendiente: "medio", activo: "bajo", desactivado: "", rechazado: "alto" };
type Filtro = EstadoCuenta | "todos";

export function PaginaUsuarios() {
  const yo = useUsuario();
  const consultas = useQueryClient();
  const avisar = useTostadas();
  const [filtro, setFiltro] = useState<Filtro>("pendiente");
  const [pendiente, setPendiente] = useState<{ u: Usuario; accion: AccionCuenta } | null>(null);
  const [restablecer, setRestablecer] = useState<Usuario | null>(null);
  const [temporal, setTemporal] = useState<{ u: Usuario; clave: string } | null>(null);
  const claveTemporal = useMutation({
    mutationFn: (u: Usuario) => admin.claveTemporal(u.id),
    onSuccess: (r, u) => {
      setRestablecer(null);
      setTemporal({ u, clave: r.clave_temporal });
    },
    onError: (e) => {
      setRestablecer(null);
      avisar(mensajeDeError(e), "error");
    },
  });
  const lista = useQuery({
    queryKey: ["admin", "usuarios", filtro],
    queryFn: () => admin.usuarios(filtro === "todos" ? undefined : filtro),
  });
  const cambiar = useMutation({
    mutationFn: ({ u, accion }: { u: Usuario; accion: AccionCuenta }) => admin.cambiarEstado(u.id, accion),
    onSuccess: (_, { accion }) => {
      setPendiente(null);
      void consultas.invalidateQueries({ queryKey: ["admin", "usuarios"] });
      avisar(TEXTO[accion].hecho);
    },
    onError: (e) => {
      setPendiente(null);
      avisar(mensajeDeError(e), "error");
    },
  });

  return (
    <>
      <div className="encabezado"><div><h1>Usuarios</h1><p>Aprueba las solicitudes de acceso y administra las cuentas.</p></div></div>
      <Pestanas etiqueta="Filtrar cuentas" valor={filtro} cambiar={setFiltro} opciones={[
        { valor: "pendiente", texto: "Solicitudes" }, { valor: "activo", texto: "Activas" },
        { valor: "desactivado", texto: "Desactivadas" }, { valor: "rechazado", texto: "Rechazadas" }, { valor: "todos", texto: "Todas" },
      ]} />
      <section className="tarjeta">
        {lista.isPending ? <Esqueleto filas={5} /> : lista.isError ? <ErrorCarga error={lista.error} reintentar={() => void lista.refetch()} /> :
          lista.data.length === 0 ? (
            <Vacio titulo={filtro === "pendiente" ? "No hay solicitudes pendientes" : "No hay cuentas en esta vista"} icono={<Users size={40} />} />
          ) : (
            <div className="tabla-contenedor">
              <table className="tabla">
                <thead><tr><th>Persona</th><th>Rol</th><th>Estado</th><th>2FA</th><th>Último acceso</th><th /></tr></thead>
                <tbody>
                  {lista.data.map((u) => (
                    <tr key={u.id}>
                      <td><div className="asunto">{u.nombre}</div><div className="secundario">{u.correo}</div>
                        <div className="secundario">Solicitó acceso {formatoFechaHora(u.creado_en)}</div></td>
                      <td>{u.rol === "administrador" ? "Administrador" : "Usuario"}</td>
                      <td><span className={`insignia ${TONO[u.estado]}`}>{ESTADO_CUENTA[u.estado]}</span></td>
                      <td>{u.totp_activo ? <span className="insignia bajo"><ShieldCheck size={13} /> Sí</span> : <span className="muy-tenue">No</span>}</td>
                      <td style={{ whiteSpace: "nowrap" }}>{haceCuanto(u.ultimo_acceso)}</td>
                      <td>
                        <div className="fila" style={{ justifyContent: "flex-end" }}>
                          {u.id !== yo.id && u.estado === "activo" && (
                            <button className="boton pequeno" onClick={() => setRestablecer(u)} title="Contraseña temporal">
                              <KeyRound size={14} aria-hidden /> Contraseña
                            </button>
                          )}
                          {u.id !== yo.id && ACCIONES[u.estado].map((a) => (
                            <button key={a} className={`boton pequeno ${a === "aprobar" ? "exito" : ""}`} onClick={() => setPendiente({ u, accion: a })}>
                              {TEXTO[a].boton}
                            </button>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </section>
      <DialogoConfirmar abierto={!!pendiente} titulo={pendiente ? `¿${TEXTO[pendiente.accion].boton} la cuenta?` : ""}
        textoConfirmar={pendiente ? TEXTO[pendiente.accion].boton : ""} tono={pendiente ? TEXTO[pendiente.accion].tono : "primario"}
        ocupado={cambiar.isPending} cancelar={() => setPendiente(null)} confirmar={() => pendiente && cambiar.mutate(pendiente)}>
        {pendiente && <p><strong>{pendiente.u.nombre}</strong> ({pendiente.u.correo}) {TEXTO[pendiente.accion].pregunta}</p>}
      </DialogoConfirmar>
      <DialogoConfirmar abierto={!!restablecer} titulo="¿Dar una contraseña temporal?" textoConfirmar="Generar contraseña"
        ocupado={claveTemporal.isPending} cancelar={() => setRestablecer(null)}
        confirmar={() => restablecer && claveTemporal.mutate(restablecer)}>
        {restablecer && <p>Se cerrarán las sesiones de <strong>{restablecer.nombre}</strong> ({restablecer.correo}) y su
          contraseña actual dejará de servir. Al entrar con la temporal deberá elegir una nueva. Si tiene doble factor, lo
          seguirá necesitando.</p>}
      </DialogoConfirmar>
      <DialogoConfirmar abierto={!!temporal} titulo="Contraseña temporal" textoConfirmar="Listo" cancelar={() => setTemporal(null)}
        confirmar={() => setTemporal(null)}>
        {temporal && (
          <div className="pila">
            <p>Entrégasela a <strong>{temporal.u.nombre}</strong> por un canal seguro (en persona o por teléfono). No se
              volverá a mostrar.</p>
            <div className="fila clave-temporal">
              <code>{temporal.clave}</code>
              <button className="boton pequeno" onClick={() => void navigator.clipboard?.writeText(temporal.clave)
                .then(() => avisar("Contraseña copiada."))}><Copy size={14} aria-hidden /> Copiar</button>
            </div>
          </div>
        )}
      </DialogoConfirmar>
    </>
  );
}
