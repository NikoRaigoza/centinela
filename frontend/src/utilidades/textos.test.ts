import { describe, expect, it } from "vitest";
import { formatoPorcentaje, haceCuanto, remitente } from "./textos";

describe("textos", () => {
  it("formatea porcentajes con coma decimal", () => {
    expect(formatoPorcentaje(0.987, 1)).toBe("98,7 %");
    expect(formatoPorcentaje(null)).toBe("—");
  });
  it("expresa tiempos relativos en español", () => {
    const ahora = Date.parse("2026-10-19T12:00:00Z");
    expect(haceCuanto("2026-10-19T11:58:00Z", ahora)).toBe("hace 2 minutos");
    expect(haceCuanto(null)).toBe("nunca");
  });
  it("arma el remitente con lo que haya", () => {
    expect(remitente("DIAN", "x@dian.gov.co")).toBe("DIAN <x@dian.gov.co>");
    expect(remitente(null, null)).toBe("Remitente desconocido");
  });
});
