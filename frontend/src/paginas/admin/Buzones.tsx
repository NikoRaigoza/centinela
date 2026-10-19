// Vista de administrador: todos los buzones conectados y su estado de salud.

import { useQuery } from "@tanstack/react-query";
import { Mail } from "lucide-react";
import { admin } from "../../api/servicios";
import { ErrorCarga, Esqueleto, Vacio } from "../../componentes/ui";
import { ESTADO_BUZON, MODO, formatoFechaHora, haceCuanto } from "../../utilidades/textos";

const TONO = { activo: "bajo", pausado: "", revocado: "alto", error: "medio" } as const;

export function PaginaAdminBuzones() {
  const lista = useQuery({ queryKey: ["admin", "buzones"], queryFn: admin.buzones, refetchInterval: 60_000 });
  const usuarios = useQuery({ queryKey: ["admin", "usuarios", "todos"], queryFn: () => admin.usuarios() });
  const nombre = (id: number) => usuarios.data?.find((u) => u.id === id)?.nombre ?? `Usuario #${id}`;

  return (
    <>
      <div className="encabezado"><div><h1>Todos los buzones</h1><p>Estado de cada Gmail conectado a Centinela. Revisa los que tienen problemas.</p></div></div>
      <section className="tarjeta">
        {lista.isPending ? <Esqueleto filas={5} /> : lista.isError ? <ErrorCarga error={lista.error} reintentar={() => void lista.refetch()} /> :
          lista.data.length === 0 ? <Vacio titulo="Todavía no hay buzones conectados" icono={<Mail size={40} />} /> : (
            <div className="tabla-contenedor">
              <table className="tabla">
                <thead><tr><th>Buzón</th><th>Dueño</th><th>Estado</th><th>Modo</th><th>Última revisión</th></tr></thead>
                <tbody>
                  {lista.data.map((b) => (
                    <tr key={b.id}>
                      <td><div className="asunto">{b.correo_gmail}</div><div className="secundario">Conectado {formatoFechaHora(b.conectado_en)}</div></td>
                      <td>{nombre(b.usuario_id)}</td>
                      <td>
                        <span className={`insignia ${TONO[b.estado]}`}><span className="punto" />{ESTADO_BUZON[b.estado]}</span>
                        {b.ultimo_error && <div className="secundario" title={b.ultimo_error}>{b.ultimo_error}</div>}
                      </td>
                      <td>{MODO[b.modo].titulo}</td>
                      <td style={{ whiteSpace: "nowrap" }} title={formatoFechaHora(b.ultima_revision_en)}>{haceCuanto(b.ultima_revision_en)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </section>
    </>
  );
}
