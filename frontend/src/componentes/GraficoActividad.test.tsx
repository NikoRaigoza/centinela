import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { GraficoActividad } from "./GraficoActividad";

describe("gráfico de actividad", () => {
  it("apila peligrosos, sospechosos y sin riesgo, y ofrece la tabla de datos", () => {
    const serie = [
      { fecha: "2026-10-18", revisados: 0, sospechosos: 0, peligrosos: 0 },
      { fecha: "2026-10-19", revisados: 10, sospechosos: 2, peligrosos: 3 },
    ];
    const { container } = render(<GraficoActividad serie={serie} />);
    expect(screen.getByRole("img", { name: /últimos 2 días/ })).toBeInTheDocument();
    expect(container.querySelectorAll(".peligrosos, .sospechosos, .sin-riesgo")).toHaveLength(3);
    const filas = screen.getAllByRole("row");
    expect(filas).toHaveLength(2);                  // encabezado + el único día con correos
    expect(filas[1]).toHaveTextContent("10");
  });
});
