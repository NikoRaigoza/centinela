// Estructura de las pantallas con sesión: menú lateral (cajón en el celular) y contenido.

import { useQuery } from "@tanstack/react-query";
import {
  Bot,
  BrainCircuit,
  FileSearch,
  Gauge,
  Inbox,
  LogOut,
  Mail,
  Menu,
  ShieldAlert,
  UserCog,
  Users,
  X,
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { NavLink, Outlet, useLocation } from "react-router";
import { panel } from "../api/servicios";
import { Escudo } from "../componentes/Escudo";
import { useSesion, useUsuario } from "../sesion/Sesion";

function Enlace({ a, icono, children, contador }: { a: string; icono: ReactNode; children: ReactNode; contador?: number }) {
  return (
    <NavLink to={a} end={a === "/"} className="nav-enlace">
      {icono}
      <span>{children}</span>
      {!!contador && <span className="contador" aria-label={`${contador} por atender`}>{contador}</span>}
    </NavLink>
  );
}

export function Marco() {
  const usuario = useUsuario();
  const { esAdmin, salir } = useSesion();
  const [abierto, setAbierto] = useState(false);
  const ubicacion = useLocation();
  const resumen = useQuery({ queryKey: ["resumen", 30], queryFn: () => panel.resumen(30), refetchInterval: 60_000 });
  const porAtender = resumen.data ? resumen.data.casos_por_estado.nuevo + resumen.data.casos_por_estado.en_cuarentena : 0;

  useEffect(() => setAbierto(false), [ubicacion.pathname]);

  return (
    <div className={`marco ${abierto ? "menu-abierto" : ""}`}>
      <aside className="lateral" aria-label="Menú principal">
        <NavLink to="/" className="marca">
          <Escudo tamano={30} />
          <div>
            <strong>Centinela</strong>
            <small>Protección contra phishing</small>
          </div>
        </NavLink>
        <nav className="pila" style={{ gap: 2 }}>
          <Enlace a="/" icono={<Gauge size={18} aria-hidden />}>Inicio</Enlace>
          <Enlace a="/casos" icono={<ShieldAlert size={18} aria-hidden />} contador={porAtender}>Correos de riesgo</Enlace>
          <Enlace a="/buzones" icono={<Inbox size={18} aria-hidden />}>Mis buzones</Enlace>
          <Enlace a="/analizar" icono={<FileSearch size={18} aria-hidden />}>Analizar un correo</Enlace>
          <Enlace a="/asistente" icono={<Bot size={18} aria-hidden />}>Asistente</Enlace>
          <Enlace a="/cuenta" icono={<UserCog size={18} aria-hidden />}>Mi cuenta</Enlace>
          {esAdmin && (
            <>
              <div className="nav-titulo">Administración</div>
              <Enlace a="/admin/usuarios" icono={<Users size={18} aria-hidden />}>Usuarios</Enlace>
              <Enlace a="/admin/buzones" icono={<Mail size={18} aria-hidden />}>Todos los buzones</Enlace>
              <Enlace a="/admin/modelos" icono={<BrainCircuit size={18} aria-hidden />}>Modelos de detección</Enlace>
            </>
          )}
        </nav>
        <div className="lateral-pie">
          <div className="nombre">{usuario.nombre}</div>
          <div className="rol">{usuario.correo}</div>
          <div className="rol">{esAdmin ? "Administrador" : "Usuario"}</div>
          <button className="boton pequeno bloque" onClick={() => void salir()}>
            <LogOut size={15} aria-hidden /> Cerrar sesión
          </button>
        </div>
      </aside>
      {abierto && <div className="velo" onClick={() => setAbierto(false)} aria-hidden />}
      <div className="contenido">
        <header className="barra-movil">
          <button className="boton" onClick={() => setAbierto((v) => !v)} aria-label={abierto ? "Cerrar menú" : "Abrir menú"}>
            {abierto ? <X size={22} /> : <Menu size={22} />}
          </button>
          <Escudo tamano={24} />
          <strong>Centinela</strong>
        </header>
        <main className="pagina" id="contenido">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
