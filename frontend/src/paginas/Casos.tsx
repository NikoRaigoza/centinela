// Lista de correos de riesgo (casos), filtrada por estado y paginada.

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, ShieldCheck } from "lucide-react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { casos } from "../api/servicios";
import type { EstadoCaso } from "../api/tipos";
import { ErrorCarga, Esqueleto, InsigniaEstado, InsigniaNivel, Pestanas, Vacio } from "../componentes/ui";
import { formatoFechaHora, formatoPorcentaje, haceCuanto, remitente } from "../utilidades/textos";

const FILTROS = {
  pendientes: { texto: "Por atender", estados: ["en_cuarentena", "nuevo"] },
  en_cuarentena: { texto: "En cuarentena", estados: ["en_cuarentena"] },
  cerrados: { texto: "Resueltos", estados: ["liberado", "confirmado", "falso_positivo"] },
  todos: { texto: "Todos", estados: [] },
} satisfies Record<string, { texto: string; estados: EstadoCaso[] }>;
type Filtro = keyof typeof FILTROS;
const POR_PAGINA = 25;

export function PaginaCasos() {
  const [params, setParams] = useSearchParams();
  const navegar = useNavigate();
  const filtro: Filtro = (params.get("filtro") as Filtro) in FILTROS ? (params.get("filtro") as Filtro) : "pendientes";
  const pagina = Math.max(0, Number(params.get("pagina") ?? 0) || 0);

  // se pide uno de más para saber si hay página siguiente
  const lista = useQuery({
    queryKey: ["casos", filtro, pagina],
    queryFn: () => casos.listar(FILTROS[filtro].estados, POR_PAGINA + 1, pagina * POR_PAGINA),
    placeholderData: keepPreviousData,
  });
  const filas = lista.data?.slice(0, POR_PAGINA) ?? [];
  const haySiguiente = (lista.data?.length ?? 0) > POR_PAGINA;
  const ir = (cambios: Record<string, string>) => setParams({ filtro, pagina: String(pagina), ...cambios });

  return (
    <>
      <div className="encabezado">
        <div>
          <h1>Correos de riesgo</h1>
          <p>Cada correo sospechoso o peligroso que Centinela detectó en tus buzones.</p>
        </div>
      </div>
      <Pestanas etiqueta="Filtrar por estado" valor={filtro} cambiar={(f) => ir({ filtro: f, pagina: "0" })}
        opciones={Object.entries(FILTROS).map(([valor, f]) => ({ valor: valor as Filtro, texto: f.texto }))} />

      <section className="tarjeta">
        {lista.isPending ? <Esqueleto filas={6} /> : lista.isError ? (
          <ErrorCarga error={lista.error} reintentar={() => void lista.refetch()} />
        ) : filas.length === 0 ? (
          <Vacio titulo={filtro === "pendientes" ? "Nada pendiente" : "Sin correos en esta vista"} icono={<ShieldCheck size={40} />}>
            <p>{filtro === "pendientes" ? "No hay correos de riesgo esperando tu revisión." : "Prueba con otro filtro."}</p>
          </Vacio>
        ) : (
          <>
            <div className="tabla-contenedor tabla-casos">
              <table className="tabla">
                <thead>
                  <tr><th>Riesgo</th><th>Correo</th><th>Buzón</th><th>Recibido</th><th>Estado</th></tr>
                </thead>
                <tbody>
                  {filas.map((c) => (
                    <tr key={c.id} className="clicable" onClick={() => navegar(`/casos/${c.id}`)}>
                      <td><InsigniaNivel nivel={c.nivel} /><div className="muy-tenue">{formatoPorcentaje(c.probabilidad)}</div></td>
                      <td>
                        <Link to={`/casos/${c.id}`} className="asunto" style={{ color: "inherit", textDecoration: "none", display: "block" }}>
                          {c.asunto || "(sin asunto)"}
                        </Link>
                        <div className="secundario">{remitente(c.remitente_nombre, c.remitente_correo)}</div>
                        {c.razones[0] && <div className="secundario">{c.razones[0]}</div>}
                      </td>
                      <td className="muy-tenue">{c.buzon}</td>
                      <td title={formatoFechaHora(c.recibido_en)} style={{ whiteSpace: "nowrap" }}>{haceCuanto(c.recibido_en)}</td>
                      <td><InsigniaEstado estado={c.estado} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="lista-casos">
              {filas.map((c) => (
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
          </>
        )}
        {(pagina > 0 || haySiguiente) && (
          <div className="fila-entre" style={{ marginTop: 14 }}>
            <button className="boton pequeno" disabled={pagina === 0} onClick={() => ir({ pagina: String(pagina - 1) })}>
              <ChevronLeft size={15} /> Anterior
            </button>
            <span className="muy-tenue">Página {pagina + 1}</span>
            <button className="boton pequeno" disabled={!haySiguiente} onClick={() => ir({ pagina: String(pagina + 1) })}>
              Siguiente <ChevronRight size={15} />
            </button>
          </div>
        )}
      </section>
    </>
  );
}
