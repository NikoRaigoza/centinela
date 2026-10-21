import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RouterProvider, createMemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { rutas } from "../app/rutas";
import { ProveedorTostadas } from "../componentes/Tostadas";
import { acceso, servidorFalso } from "../pruebas/http";
import { ProveedorSesion } from "../sesion/Sesion";

const legal = { version_politica: "2026-10-20", responsable: "Niko R.", correo_contacto: "contacto@centinela.me",
  dias_sin_riesgo: 30, dias_casos: 365 };
const resumen = { dias: 30, revisados: 0, sospechosos: 0, peligrosos: 0, entidades_suplantadas: [], serie: [],
  casos_por_estado: { nuevo: 0, en_cuarentena: 0, liberado: 0, confirmado: 0, falso_positivo: 0 } };

function montar(ruta: string) {
  const router = createMemoryRouter(rutas, { initialEntries: [ruta] });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <ProveedorSesion><ProveedorTostadas><RouterProvider router={router} /></ProveedorTostadas></ProveedorSesion>
    </QueryClientProvider>,
  );
  return router;
}

describe("Ley 1581 y acceso", () => {
  it("la política es pública y muestra los datos que entrega el servidor", async () => {
    servidorFalso(({ ruta }) => {
      if (ruta === "/api/auth/renovacion") return { estado: 401, cuerpo: { codigo: "x", mensaje: "sin sesión" } };
      if (ruta === "/api/publico/legal") return { cuerpo: legal };
      return { estado: 404 };
    });
    montar("/privacidad");
    expect(await screen.findByText("Niko R.")).toBeInTheDocument();
    for (const a of screen.getAllByRole("link", { name: "contacto@centinela.me" })) expect(a).toHaveAttribute("href", "mailto:contacto@centinela.me");
    expect(screen.getByText("30 días")).toBeInTheDocument();
    expect(screen.getByText(/Nunca\s+guardamos el cuerpo del correo/)).toBeInTheDocument();
  });

  it("el registro exige la autorización del tratamiento de datos", async () => {
    let cuerpoEnviado: unknown;
    servidorFalso(({ ruta, cuerpo }) => {
      if (ruta === "/api/auth/renovacion") return { estado: 401, cuerpo: { codigo: "x", mensaje: "sin sesión" } };
      if (ruta === "/api/auth/registro") {
        cuerpoEnviado = cuerpo;
        return { estado: 202, cuerpo: { mensaje: "Recibimos tu solicitud." } };
      }
      return { estado: 404 };
    });
    montar("/registro");
    const u = userEvent.setup();
    await u.type(await screen.findByLabelText("Nombre"), "Ana Pérez");
    await u.type(screen.getByLabelText("Correo"), "ana@gmail.com");
    await u.type(screen.getByLabelText("Contraseña"), "Clave-segura-2026");
    await u.type(screen.getByLabelText("Repite la contraseña"), "Clave-segura-2026");
    const enviar = screen.getByRole("button", { name: "Enviar solicitud" });
    expect(enviar).toBeDisabled();
    await u.click(screen.getByRole("checkbox"));
    await u.click(enviar);
    expect(await screen.findByText("Recibimos tu solicitud.")).toBeInTheDocument();
    expect(cuerpoEnviado).toEqual({ correo: "ana@gmail.com", nombre: "Ana Pérez", clave: "Clave-segura-2026", acepta_politica: true });
  });

  it("con una contraseña temporal pide elegir la definitiva antes de entrar", async () => {
    const peticiones = servidorFalso(({ ruta, cuerpo }) => {
      if (ruta === "/api/auth/renovacion") return { estado: 401, cuerpo: { codigo: "x", mensaje: "sin sesión" } };
      if (ruta === "/api/auth/inicio") return { cuerpo: { paso: "cambiar_clave", acceso: null, token_desafio: "desafio-1" } };
      if (ruta === "/api/auth/clave-temporal") {
        expect(cuerpo).toEqual({ nueva: "Mi-clave-nueva-2027" });
        return { cuerpo: { paso: "completo", acceso: acceso("t1"), token_desafio: null } };
      }
      if (ruta.startsWith("/api/panel/resumen")) return { cuerpo: resumen };
      return { cuerpo: [] };
    });
    const router = montar("/ingreso");
    const u = userEvent.setup();
    await u.type(await screen.findByLabelText("Correo"), "ana@gmail.com");
    await u.type(screen.getByLabelText("Contraseña"), "Temp-abcd-efgh-123");
    await u.click(screen.getByRole("button", { name: "Entrar" }));
    expect(await screen.findByRole("heading", { name: "Elige tu nueva contraseña" })).toBeInTheDocument();
    await u.type(screen.getByLabelText("Nueva contraseña"), "Mi-clave-nueva-2027");
    await u.type(screen.getByLabelText("Repite la contraseña"), "Mi-clave-nueva-2027");
    await u.click(screen.getByRole("button", { name: "Guardar y entrar" }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/"));
    expect(peticiones.find((p) => p.ruta === "/api/auth/clave-temporal")?.autorizacion).toBe("Bearer desafio-1");
  });
});
