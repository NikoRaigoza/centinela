import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RouterProvider, createMemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { rutas } from "../app/rutas";
import { ProveedorTostadas } from "../componentes/Tostadas";
import { acceso, servidorFalso } from "../pruebas/http";
import { ProveedorSesion } from "../sesion/Sesion";

const resumenVacio = {
  dias: 30, revisados: 0, sospechosos: 0, peligrosos: 0, entidades_suplantadas: [], serie: [],
  casos_por_estado: { nuevo: 0, en_cuarentena: 0, liberado: 0, confirmado: 0, falso_positivo: 0 },
};

function montar(ruta: string) {
  const router = createMemoryRouter(rutas, { initialEntries: [ruta] });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <ProveedorSesion><ProveedorTostadas><RouterProvider router={router} /></ProveedorTostadas></ProveedorSesion>
    </QueryClientProvider>,
  );
  return router;
}

function apiConDobleFactor() {
  return servidorFalso(({ ruta, cuerpo, cabeceras }) => {
    if (ruta === "/api/auth/renovacion") return { estado: 401 };
    if (ruta === "/api/auth/inicio") return { cuerpo: { paso: "verificar_2fa", acceso: null, token_desafio: "desafio-1" } };
    if (ruta === "/api/auth/2fa/verificacion") {
      expect(cabeceras.Authorization).toBe("Bearer desafio-1");
      return (cuerpo as { codigo: string }).codigo === "123456" ? { cuerpo: acceso("acceso-1") } : { estado: 401, cuerpo: { codigo: "x", mensaje: "Código incorrecto." } };
    }
    if (ruta.startsWith("/api/panel/resumen")) return { cuerpo: resumenVacio };
    return { cuerpo: [] };
  });
}

describe("inicio de sesión", () => {
  it("sin sesión, una ruta protegida lleva al ingreso recordando a dónde volver", async () => {
    apiConDobleFactor();
    const router = montar("/casos?filtro=todos");
    await screen.findByRole("heading", { name: "Inicia sesión" });
    expect(router.state.location.search).toBe(`?volver=${encodeURIComponent("/casos?filtro=todos")}`);
  });

  it("contraseña → código del doble factor → vuelve a la página pedida", async () => {
    apiConDobleFactor();
    const router = montar("/casos");
    const u = userEvent.setup();
    await u.type(await screen.findByLabelText("Correo"), "ana@gmail.com");
    await u.type(screen.getByLabelText("Contraseña"), "Clave-segura-2026");
    await u.click(screen.getByRole("button", { name: "Entrar" }));
    await screen.findByRole("heading", { name: "Verificación en dos pasos" });

    await u.type(screen.getByLabelText("Código de la app"), "000000");
    await u.click(screen.getByRole("button", { name: "Entrar" }));
    expect(await screen.findByText("Código incorrecto.")).toBeInTheDocument();

    await u.clear(screen.getByLabelText("Código de la app"));
    await u.type(screen.getByLabelText("Código de la app"), "123456");
    await u.click(screen.getByRole("button", { name: "Entrar" }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/casos"));
    expect(await screen.findByRole("heading", { name: "Correos de riesgo" })).toBeInTheDocument();
  });

  it("no redirige a otros sitios con ?volver= (redirección abierta)", async () => {
    servidorFalso(({ ruta }) => {
      if (ruta === "/api/auth/renovacion") return { estado: 401 };
      if (ruta === "/api/auth/inicio") return { cuerpo: { paso: "completo", acceso: acceso("a"), token_desafio: null } };
      if (ruta.startsWith("/api/panel/resumen")) return { cuerpo: resumenVacio };
      return { cuerpo: [] };
    });
    const router = montar("/ingreso?volver=%2F%2Fevil.example");
    const u = userEvent.setup();
    await u.type(await screen.findByLabelText("Correo"), "ana@gmail.com");
    await u.type(screen.getByLabelText("Contraseña"), "Clave-segura-2026");
    await u.click(screen.getByRole("button", { name: "Entrar" }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/"));
  });

  it("las pantallas de administración no existen para un usuario", async () => {
    servidorFalso(({ ruta }) => {
      if (ruta === "/api/auth/renovacion") return { cuerpo: acceso("a") };
      if (ruta.startsWith("/api/panel/resumen")) return { cuerpo: resumenVacio };
      return { cuerpo: [] };
    });
    montar("/admin/usuarios");
    expect(await screen.findByText("Esta página no existe")).toBeInTheDocument();
    expect(screen.queryByText("Administración")).not.toBeInTheDocument();
  });
});
