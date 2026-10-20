import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { RouterProvider, createMemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { nombreDeArchivo } from "../api/cliente";
import { rutas } from "../app/rutas";
import { ListaAdjuntos, OrigenDelEnlace } from "../componentes/Adjuntos";
import { ProveedorTostadas } from "../componentes/Tostadas";
import { acceso, usuarioDemo } from "../pruebas/http";
import { ProveedorSesion } from "../sesion/Sesion";

const resumen = {
  dias: 30, revisados: 1234, sospechosos: 12, peligrosos: 5, entidades_suplantadas: [], serie: [],
  casos_por_estado: { nuevo: 0, en_cuarentena: 0, liberado: 0, confirmado: 0, falso_positivo: 0 },
};

/** API falsa que además entrega archivos binarios (los reportes) con su nombre en Content-Disposition. */
function apiFalsa(usuario = usuarioDemo) {
  const descargas: { ruta: string; autorizacion?: string; acepta?: string }[] = [];
  vi.stubGlobal("fetch", vi.fn(async (ruta: string, init: RequestInit = {}) => {
    const cabeceras = (init.headers ?? {}) as Record<string, string>;
    const json = (cuerpo: unknown) => new Response(JSON.stringify(cuerpo), { headers: { "Content-Type": "application/json" } });
    if (ruta === "/api/auth/renovacion") return json(acceso("t1", usuario));
    if (ruta.startsWith("/api/panel/resumen")) return json(resumen);
    if (ruta.startsWith("/api/reportes")) {
      descargas.push({ ruta, autorizacion: cabeceras.Authorization, acepta: cabeceras.Accept });
      const formato = new URL(ruta, "http://x").searchParams.get("formato");
      return new Response(formato === "pdf" ? "%PDF-1.4" : "PK", {
        headers: { "Content-Type": "application/octet-stream",
          "Content-Disposition": `attachment; filename="centinela-reporte-personal-2026-09-21-a-2026-10-20.${formato}"` } });
    }
    return json([]);
  }));
  const creados: Blob[] = [];
  // jsdom no implementa las URL de objetos: se simulan para ver qué archivo se entregó al navegador
  Object.defineProperty(URL, "createObjectURL", { configurable: true,
    value: vi.fn((b: Blob) => { creados.push(b); return "blob:reporte"; }) });
  Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: vi.fn() });
  const clics = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  return { descargas, creados, clics };
}

function montar() {
  const router = createMemoryRouter(rutas, { initialEntries: ["/reportes"] });
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <ProveedorSesion><ProveedorTostadas><RouterProvider router={router} /></ProveedorTostadas></ProveedorSesion>
    </QueryClientProvider>,
  );
}

describe("reportes", () => {
  it("descarga el PDF y el Excel del periodo elegido con la sesión actual", async () => {
    const { descargas, creados, clics } = apiFalsa();
    montar();
    const u = userEvent.setup();
    expect(await screen.findByText(/correos revisados/)).toHaveTextContent("1.234 correos revisados, 12 sospechosos y 5 peligrosos");
    expect(screen.queryByText("Toda la organización")).not.toBeInTheDocument();      // solo administradores

    await u.click(screen.getByRole("button", { name: "Descargar reporte en PDF" }));
    expect(await screen.findByText(/Reporte descargado: centinela-reporte-personal-.*\.pdf/)).toBeInTheDocument();
    expect(descargas[0]).toEqual({ ruta: "/api/reportes?formato=pdf&dias=30&organizacion=false",
      autorizacion: "Bearer t1", acepta: "*/*" });
    expect(clics).toHaveBeenCalledTimes(1);
    expect(await creados[0]?.text()).toBe("%PDF-1.4");

    await u.click(screen.getByRole("tab", { name: "1 año" }));
    await u.click(screen.getByRole("button", { name: "Descargar reporte en Excel" }));
    await waitFor(() => expect(descargas[1]?.ruta).toBe("/api/reportes?formato=xlsx&dias=365&organizacion=false"));
  });

  it("el administrador puede pedir el de toda la organización", async () => {
    const { descargas } = apiFalsa({ ...usuarioDemo, rol: "administrador" as never });
    montar();
    const u = userEvent.setup();
    await u.click(await screen.findByRole("radio", { name: /Toda la organización/ }));
    await u.click(screen.getByRole("button", { name: "Descargar reporte en PDF" }));
    await waitFor(() => expect(descargas[0]?.ruta).toBe("/api/reportes?formato=pdf&dias=30&organizacion=true"));
  });
});

describe("piezas", () => {
  it("toma el nombre del archivo del servidor sin rutas ni caracteres peligrosos", () => {
    expect(nombreDeArchivo('attachment; filename="reporte.pdf"', "x.pdf")).toBe("reporte.pdf");
    expect(nombreDeArchivo('attachment; filename="../../etc/pass:wd.pdf"', "x.pdf")).toBe("....etcpasswd.pdf");
    expect(nombreDeArchivo(null, "x.pdf")).toBe("x.pdf");
  });

  it("muestra por qué un adjunto es peligroso y de dónde salió un enlace", () => {
    render(
      <>
        <ListaAdjuntos adjuntos={[
          { nombre: "factura.zip", tipo_mime: "application/zip", tamano_bytes: 2048, peligroso: true,
            motivo: "El comprimido «factura.zip» trae adentro un programa." },
          { nombre: "foto.jpg", tipo_mime: "image/jpeg", tamano_bytes: 500, peligroso: false, motivo: null },
        ]} />
        <OrigenDelEnlace enlace={{ dominio: "evil.top", probabilidad: 0.9, origen: "qr" }} />
        <OrigenDelEnlace enlace={{ dominio: "a.co", probabilidad: 0.1, origen: "cuerpo" }} />
      </>,
    );
    expect(screen.getByText("Peligroso")).toBeInTheDocument();
    expect(screen.getByText(/trae adentro un programa/)).toBeInTheDocument();
    expect(screen.getByText("· 2 KB", { exact: false })).toBeInTheDocument();
    expect(screen.getAllByText("Peligroso")).toHaveLength(1);
    expect(screen.getByText("Código QR")).toBeInTheDocument();
    expect(screen.queryByText("En el texto")).not.toBeInTheDocument();
  });
});
