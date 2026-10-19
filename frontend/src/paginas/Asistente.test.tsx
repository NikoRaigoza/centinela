import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RouterProvider, createMemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";
import { rutas } from "../app/rutas";
import { ProveedorTostadas } from "../componentes/Tostadas";
import { acceso, servidorFalso } from "../pruebas/http";
import { ProveedorSesion } from "../sesion/Sesion";

const resumen = {
  dias: 30, revisados: 0, sospechosos: 0, peligrosos: 0, entidades_suplantadas: [], serie: [],
  casos_por_estado: { nuevo: 0, en_cuarentena: 0, liberado: 0, confirmado: 0, falso_positivo: 0 },
};
const estado = {
  ia_disponible: true, proveedor: "gemini", limite_ia: 30, restantes_ia: 30,
  sugerencias_generales: ["¿Cómo reconozco un correo falso?"], sugerencias_caso: ["¿Por qué es sospechoso?"],
};
const ahora = "2026-10-19T15:00:00Z";

function montar(ruta: string) {
  const router = createMemoryRouter(rutas, { initialEntries: [ruta] });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <ProveedorSesion><ProveedorTostadas><RouterProvider router={router} /></ProveedorTostadas></ProveedorSesion>
    </QueryClientProvider>,
  );
  return router;
}

describe("asistente", () => {
  it("pregunta sobre un caso desde una sugerencia y la conversación queda guardada", async () => {
    const turnos: { rol: string; contenido: string; proveedor: string | null; creado_en: string }[] = [];
    const peticiones = servidorFalso(({ metodo, ruta, cuerpo }) => {
      if (ruta === "/api/auth/renovacion") return { cuerpo: acceso("t1") };
      if (ruta.startsWith("/api/panel/resumen")) return { cuerpo: resumen };
      if (ruta === "/api/asistente/estado") return { cuerpo: estado };
      if (ruta === "/api/casos/7") return { cuerpo: { id: 7, asunto: "Su cuenta será bloqueada" } };
      if (ruta === "/api/asistente/conversaciones") {
        return { cuerpo: turnos.length ? [{ id: 3, titulo: "¿Por qué es sospechoso?", caso_id: 7, creado_en: ahora, actualizado_en: ahora }] : [] };
      }
      if (metodo === "POST" && ruta === "/api/asistente/preguntas") {
        expect(cuerpo).toEqual({ pregunta: "¿Por qué es sospechoso?", caso_id: 7 });
        turnos.push({ rol: "usuario", contenido: "¿Por qué es sospechoso?", proveedor: null, creado_en: ahora },
          { rol: "asistente", contenido: "Porque **suplanta** a tu banco.", proveedor: "local", creado_en: ahora });
        return { cuerpo: { conversacion_id: 3, turno: turnos[1], aviso: "Te respondo en modo básico porque no hay conexión con Gemini.", restantes_ia: 30 } };
      }
      if (ruta === "/api/asistente/conversaciones/3") {
        return { cuerpo: { id: 3, titulo: "¿Por qué es sospechoso?", caso_id: 7, creado_en: ahora, actualizado_en: ahora, turnos } };
      }
      return { cuerpo: [] };
    });
    const router = montar("/asistente?caso=7");
    expect(await screen.findByText(/Sobre el correo «Su cuenta será bloqueada»/)).toBeInTheDocument();
    await userEvent.setup().click(await screen.findByRole("button", { name: "¿Por qué es sospechoso?" }));

    expect(await screen.findByText("suplanta", { selector: "strong" })).toBeInTheDocument();
    expect(screen.getByText(/modo básico porque no hay conexión/)).toBeInTheDocument();
    expect(screen.getByText("Respuesta en modo básico")).toBeInTheDocument();
    await waitFor(() => expect(router.state.location.search).toBe("?c=3"));
    expect(await screen.findByRole("link", { name: /¿Por qué es sospechoso\?.*Correo de riesgo/ })).toHaveAttribute("aria-current", "page");
    expect(peticiones.filter((p) => p.metodo === "POST" && p.ruta === "/api/asistente/preguntas")).toHaveLength(1);
  });

  it("si la pregunta falla, el texto no se pierde", async () => {
    servidorFalso(({ metodo, ruta }) => {
      if (ruta === "/api/auth/renovacion") return { cuerpo: acceso("t1") };
      if (ruta.startsWith("/api/panel/resumen")) return { cuerpo: resumen };
      if (ruta === "/api/asistente/estado") return { cuerpo: estado };
      if (metodo === "POST" && ruta === "/api/asistente/preguntas") {
        return { estado: 429, cuerpo: { codigo: "limite_alcanzado", mensaje: "Llegaste al máximo de preguntas de hoy." } };
      }
      return { cuerpo: [] };
    });
    montar("/asistente");
    const u = userEvent.setup();
    const caja = await screen.findByLabelText("Tu pregunta");
    await u.type(caja, "¿Qué es DMARC?{Enter}");
    expect(await screen.findByText("Llegaste al máximo de preguntas de hoy.")).toBeInTheDocument();
    expect(caja).toHaveValue("¿Qué es DMARC?");
  });
});
