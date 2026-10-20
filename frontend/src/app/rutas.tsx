// Mapa de pantallas. Las de administración solo se montan para el rol administrador (la API también lo exige:
// ocultarlas en el panel es comodidad, no seguridad).

import { Navigate, Outlet, createBrowserRouter, useLocation, useSearchParams, type RouteObject } from "react-router";
import { useSesion } from "../sesion/Sesion";
import { PaginaAnalizar } from "../paginas/Analizar";
import { PaginaAsistente } from "../paginas/Asistente";
import { PaginaBuzones } from "../paginas/Buzones";
import { PaginaCaso } from "../paginas/Caso";
import { PaginaCasos } from "../paginas/Casos";
import { PaginaCuenta } from "../paginas/Cuenta";
import { PaginaIngreso } from "../paginas/Ingreso";
import { PaginaInicio } from "../paginas/Inicio";
import { PaginaNoEncontrada } from "../paginas/NoEncontrada";
import { PaginaRegistro } from "../paginas/Registro";
import { PaginaReportes } from "../paginas/Reportes";
import { PaginaAdminBuzones } from "../paginas/admin/Buzones";
import { PaginaModelos } from "../paginas/admin/Modelos";
import { PaginaUsuarios } from "../paginas/admin/Usuarios";
import { Marco } from "./Marco";

function Cargando() {
  return <div className="cargando-pantalla">Cargando Centinela…</div>;
}

function ConSesion() {
  const { estado } = useSesion();
  const ubicacion = useLocation();
  if (estado.tipo === "cargando") return <Cargando />;
  if (estado.tipo === "anonimo") {
    if (estado.voluntario) return <Navigate to="/ingreso" replace />;
    const volver = ubicacion.pathname + ubicacion.search;
    return <Navigate to={volver === "/" ? "/ingreso" : `/ingreso?volver=${encodeURIComponent(volver)}`} replace />;
  }
  return <Marco />;
}

/** Solo se vuelve a rutas internas del panel (evita redirecciones abiertas a otros sitios). */
export function destinoSeguro(volver: string | null): string {
  return volver && volver.startsWith("/") && !volver.startsWith("//") && !volver.startsWith("/\\") ? volver : "/";
}

function SinSesion() {
  const { estado } = useSesion();
  const [params] = useSearchParams();
  if (estado.tipo === "cargando") return <Cargando />;
  if (estado.tipo === "autenticado") return <Navigate to={destinoSeguro(params.get("volver"))} replace />;
  return <Outlet />;
}

function SoloAdmin() {
  const { esAdmin } = useSesion();
  return esAdmin ? <Outlet /> : <PaginaNoEncontrada />;
}

export const rutas: RouteObject[] = [
  {
    element: <SinSesion />,
    children: [
      { path: "/ingreso", element: <PaginaIngreso /> },
      { path: "/registro", element: <PaginaRegistro /> },
    ],
  },
  {
    element: <ConSesion />,
    children: [
      { path: "/", element: <PaginaInicio /> },
      { path: "/casos", element: <PaginaCasos /> },
      { path: "/casos/:id", element: <PaginaCaso /> },
      { path: "/buzones", element: <PaginaBuzones /> },
      { path: "/analizar", element: <PaginaAnalizar /> },
      { path: "/asistente", element: <PaginaAsistente /> },
      { path: "/reportes", element: <PaginaReportes /> },
      { path: "/cuenta", element: <PaginaCuenta /> },
      {
        element: <SoloAdmin />,
        children: [
          { path: "/admin/usuarios", element: <PaginaUsuarios /> },
          { path: "/admin/buzones", element: <PaginaAdminBuzones /> },
          { path: "/admin/modelos", element: <PaginaModelos /> },
        ],
      },
      { path: "*", element: <PaginaNoEncontrada /> },
    ],
  },
];

export const crearEnrutador = () => createBrowserRouter(rutas);
