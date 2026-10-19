import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider } from "react-router";
import { ErrorApi } from "./api/cliente";
import { crearEnrutador } from "./app/rutas";
import { ProveedorTostadas } from "./componentes/Tostadas";
import { ProveedorSesion } from "./sesion/Sesion";
import "./estilos/centinela.css";

const consultas = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      // Un 401/403/404 no se arregla reintentando; un corte de red sí.
      retry: (intentos, error) => !(error instanceof ErrorApi && error.estado >= 400 && error.estado < 500) && intentos < 2,
      refetchOnWindowFocus: true,
    },
  },
});

const enrutador = crearEnrutador();
const raiz = document.getElementById("raiz");
if (!raiz) throw new Error("Falta el elemento #raiz en index.html");

createRoot(raiz).render(
  <StrictMode>
    <QueryClientProvider client={consultas}>
      <ProveedorSesion>
        <ProveedorTostadas>
          <RouterProvider router={enrutador} />
        </ProveedorTostadas>
      </ProveedorSesion>
    </QueryClientProvider>
  </StrictMode>,
);
