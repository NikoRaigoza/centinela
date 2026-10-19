import { beforeEach, describe, expect, it } from "vitest";
import { acceso, servidorFalso } from "../pruebas/http";
import { ErrorApi, fijarAcceso, pedir, suscribirSesion } from "./cliente";

describe("cliente de la API", () => {
  beforeEach(() => fijarAcceso(null));

  it("renueva el token una vez ante un 401 y repite la petición", async () => {
    fijarAcceso(acceso("viejo"));
    const peticiones = servidorFalso(({ ruta, cabeceras }) => {
      if (ruta === "/api/auth/renovacion") return { cuerpo: acceso("nuevo") };
      return cabeceras.Authorization === "Bearer nuevo" ? { cuerpo: [1, 2] } : { estado: 401, cuerpo: { codigo: "credenciales_invalidas", mensaje: "x" } };
    });
    expect(await pedir<number[]>("/api/casos")).toEqual([1, 2]);
    expect(peticiones.map((p) => p.ruta)).toEqual(["/api/casos", "/api/auth/renovacion", "/api/casos"]);
  });

  it("varias peticiones con el token vencido comparten UNA sola renovación", async () => {
    fijarAcceso(acceso("viejo"));
    const peticiones = servidorFalso(({ ruta, cabeceras }) => {
      if (ruta === "/api/auth/renovacion") return { cuerpo: acceso("nuevo") };
      return cabeceras.Authorization === "Bearer nuevo" ? { cuerpo: {} } : { estado: 401 };
    });
    await Promise.all([pedir("/api/a"), pedir("/api/b"), pedir("/api/c")]);
    expect(peticiones.filter((p) => p.ruta === "/api/auth/renovacion")).toHaveLength(1);
  });

  it("si la renovación falla, cierra la sesión y avisa", async () => {
    fijarAcceso(acceso("viejo"));
    const eventos: unknown[] = [];
    const quitar = suscribirSesion((a) => eventos.push(a));
    servidorFalso(() => ({ estado: 401, cuerpo: { codigo: "credenciales_invalidas", mensaje: "Tu sesión expiró." } }));
    await expect(pedir("/api/casos")).rejects.toMatchObject({ estado: 401 });
    expect(eventos).toContain(null);
    quitar();
  });

  it("no repite operaciones marcadas como no repetibles (clave actual incorrecta)", async () => {
    fijarAcceso(acceso("vigente"));
    const peticiones = servidorFalso(() => ({ estado: 401, cuerpo: { codigo: "credenciales_invalidas", mensaje: "La contraseña actual no es correcta." } }));
    await expect(pedir("/api/usuarios/yo/clave", { metodo: "PUT", json: {}, reintentar: false }))
      .rejects.toThrow("La contraseña actual no es correcta.");
    expect(peticiones).toHaveLength(1);
  });

  it("traduce errores del servidor y la falta de conexión a mensajes en español", async () => {
    servidorFalso(() => ({ estado: 409, cuerpo: { codigo: "transicion_invalida", mensaje: "Solo se pueden liberar correos en cuarentena." } }));
    const e = await pedir("/api/casos/1/liberacion", { metodo: "POST" }).catch((x) => x);
    expect(e).toBeInstanceOf(ErrorApi);
    expect(e).toMatchObject({ estado: 409, codigo: "transicion_invalida" });
    fetchRoto();
    await expect(pedir("/api/salud")).rejects.toMatchObject({ codigo: "sin_conexion" });
  });
});

function fetchRoto() {
  globalThis.fetch = (() => Promise.reject(new TypeError("Failed to fetch"))) as typeof fetch;
}
