// Pantalla de inicio: qué pasó en los buzones propios y qué requiere atención.

import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Inbox, MailCheck, ShieldAlert, ShieldQuestion, UserPlus } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Link } from "react-router";
import { admin, buzones, casos, panel } from "../api/servicios";
import { GraficoActividad } from "../componentes/GraficoActividad";
import { ErrorCarga, Esqueleto, InsigniaEstado, InsigniaNivel, Pestanas, Vacio } from "../componentes/ui";
import { useSesion, useUsuario } from "../sesion/Sesion";
import { formatoEntero, haceCuanto, remitente } from "../utilidades/textos";

const PERIODOS = [
  { valor: "7", texto: "7 días" },
  { valor: "30", texto: "30 días" },
  { valor: "90", texto: "90 días" },
] as const;
type Periodo = (typeof PERIODOS)[number]["valor"];

function saludo(): string {
  const h = Number(new Intl.DateTimeFormat("es-CO", { hour: "numeric", hourCycle: "h23", timeZone: "America/Bogota" }).format(new Date()));
  return h < 12 ? "Buenos días" : h < 19 ? "Buenas tardes" : "Buenas noches";
}

function Indicador({ etiqueta, valor, nota, tono, icono }: { etiqueta: string; valor: number; nota: string; tono?: string; icono: ReactNode }) {
  return (
    <div className={`tarjeta indicador ${tono ?? ""}`}>
      <span className="etiqueta">{icono}{etiqueta}</span>
      <span className="valor">{formatoEntero(valor)}</span>
      <span className="nota">{nota}</span>
    </div>
  );
}

export function PaginaInicio() {
  const usuario = useUsuario();
  const { esAdmin } = useSesion();
  const [periodo, setPeriodo] = useState<Periodo>("30");
  const dias = Number(periodo);
  const resumen = useQuery({ queryKey: ["resumen", dias], queryFn: () => panel.resumen(dias) });
  const misBuzones = useQuery({ queryKey: ["buzones"], queryFn: buzones.listar });
  const abiertos = useQuery({ queryKey: ["casos", "inicio"], queryFn: () => casos.listar(["en_cuarentena", "nuevo"], 5, 0) });
  const pendientes = useQuery({ queryKey: ["admin", "usuarios", "pendiente"], queryFn: () => admin.usuarios("pendiente"), enabled: esAdmin });

  const sinBuzones = misBuzones.data?.length === 0;
  const conProblemas = misBuzones.data?.filter((b) => b.estado === "error" || b.estado === "revocado") ?? [];
  const r = resumen.data;
  const maxEntidad = Math.max(1, ...(r?.entidades_suplantadas.map((e) => e.correos) ?? []));

  return (
    <>
      <div className="encabezado">
        <div>
          <h1>{saludo()}, {usuario.nombre.split(" ")[0]}</h1>
          <p>Resumen de lo que Centinela revisó en tus buzones.</p>
        </div>
        <Pestanas etiqueta="Periodo" opciones={[...PERIODOS]} valor={periodo} cambiar={setPeriodo} />
      </div>

      {esAdmin && !!pendientes.data?.length && (
        <Link to="/admin/usuarios" className="tarjeta fila-entre" style={{ textDecoration: "none", color: "inherit" }}>
          <span className="fila"><UserPlus size={20} color="var(--primario)" />
            <span><strong>{pendientes.data.length}</strong> {pendientes.data.length === 1 ? "solicitud de cuenta espera" : "solicitudes de cuenta esperan"} tu aprobación.</span>
          </span>
          <ArrowRight size={18} />
        </Link>
      )}

      {sinBuzones && (
        <div className="tarjeta">
          <Vacio titulo="Conecta tu primer buzón de Gmail" icono={<Inbox size={40} />}>
            <p>Centinela empezará a revisar cada correo nuevo que llegue y te avisará si alguno es peligroso.</p>
            <Link to="/buzones" className="boton primario">Conectar Gmail</Link>
          </Vacio>
        </div>
      )}

      {conProblemas.map((b) => (
        <Link key={b.id} to="/buzones" className="alerta aviso" style={{ textDecoration: "none", color: "inherit" }}>
          <ShieldQuestion size={18} />
          <span>
            <strong>{b.correo_gmail}</strong> no se está revisando{b.ultimo_error ? `: ${b.ultimo_error}` : "."} Revisa la conexión.
          </span>
        </Link>
      ))}

      {resumen.isError ? (
        <ErrorCarga error={resumen.error} reintentar={() => void resumen.refetch()} />
      ) : (
        <div className="rejilla rejilla-indicadores">
          <Indicador etiqueta="Correos revisados" valor={r?.revisados ?? 0} nota={`últimos ${dias} días`} icono={<MailCheck size={16} />} />
          <Indicador etiqueta="Peligrosos" valor={r?.peligrosos ?? 0} nota="riesgo alto" tono="alto" icono={<ShieldAlert size={16} />} />
          <Indicador etiqueta="Sospechosos" valor={r?.sospechosos ?? 0} nota="riesgo medio" tono="medio" icono={<ShieldQuestion size={16} />} />
          <Indicador etiqueta="En cuarentena ahora" valor={r?.casos_por_estado.en_cuarentena ?? 0}
            nota={`${r?.casos_por_estado.nuevo ?? 0} más por revisar`} icono={<Inbox size={16} />} />
        </div>
      )}

      <div className="rejilla rejilla-principal">
        <section className="tarjeta">
          <h2>Actividad diaria</h2>
          {r ? <GraficoActividad serie={r.serie} /> : <Esqueleto filas={5} />}
        </section>
        <section className="tarjeta">
          <h2>Entidades más suplantadas</h2>
          {!r ? <Esqueleto /> : r.entidades_suplantadas.length === 0 ? (
            <p className="tenue">Ningún correo de riesgo se hizo pasar por una entidad conocida en este periodo.</p>
          ) : (
            <div className="barras-h">
              {r.entidades_suplantadas.map((e) => (
                <div className="fila-barra" key={e.nombre}>
                  <span>{e.nombre}</span>
                  <span className="riel"><span className="relleno" style={{ width: `${(e.correos / maxEntidad) * 100}%`, display: "block" }} /></span>
                  <span className="cifra">{e.correos}</span>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      <section className="tarjeta">
        <div className="tarjeta-titulo">
          <h2>Requieren tu atención</h2>
          <Link to="/casos" className="boton pequeno">Ver todos <ArrowRight size={14} /></Link>
        </div>
        {abiertos.isPending ? <Esqueleto /> : abiertos.isError ? <ErrorCarga error={abiertos.error} /> : abiertos.data.length === 0 ? (
          <p className="tenue">No hay correos de riesgo pendientes. 👍</p>
        ) : (
          <div className="pila" style={{ gap: 8 }}>
            {abiertos.data.map((c) => (
              <Link key={c.id} to={`/casos/${c.id}`} className="item-caso">
                <div className="fila-entre">
                  <span className="fila"><InsigniaNivel nivel={c.nivel} /><InsigniaEstado estado={c.estado} /></span>
                  <span className="muy-tenue">{haceCuanto(c.recibido_en)}</span>
                </div>
                <span className="asunto">{c.asunto || "(sin asunto)"}</span>
                <span className="muy-tenue">{remitente(c.remitente_nombre, c.remitente_correo)}</span>
              </Link>
            ))}
          </div>
        )}
      </section>
    </>
  );
}
