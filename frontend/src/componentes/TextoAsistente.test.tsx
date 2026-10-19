import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { TextoAsistente } from "./TextoAsistente";

describe("texto del asistente", () => {
  it("muestra párrafos, listas y negritas", () => {
    const { container } = render(
      <TextoAsistente texto={"Te recomiendo:\n1. **No abras** el enlace.\n2. Llama a tu banco.\n\nOtra cosa:\n- uno\n- dos"} />,
    );
    expect(container.querySelectorAll("ol li")).toHaveLength(2);
    expect(container.querySelectorAll("ul li")).toHaveLength(2);
    expect(container.querySelector("strong")?.textContent).toBe("No abras");
    expect(container.querySelectorAll("p")).toHaveLength(2);
  });

  it("nunca interpreta HTML: un intento de inyección se ve como texto", () => {
    const { container } = render(<TextoAsistente texto={'<img src=x onerror="alert(1)"> **<b>hola</b>**'} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect(container.textContent).toContain('<img src=x onerror="alert(1)">');
  });
});
