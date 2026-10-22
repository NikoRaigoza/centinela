// Logo de Centinela. «blanco» va sobre fondos oscuros (barra lateral, pantalla de acceso), «oscuro» sobre fondos
// claros y «auto» sigue el tema del sistema (páginas con el fondo normal, como las legales).
type Variante = "blanco" | "oscuro" | "auto";

export function Logo({ tamano = 28, variante = "blanco" }: { tamano?: number; variante?: Variante }) {
  const imagen = (src: string) => (
    <img src={src} alt="" aria-hidden height={tamano} style={{ height: tamano, width: "auto", flex: "none" }} />
  );
  if (variante !== "auto") return imagen(variante === "blanco" ? "/logo-blanco.png" : "/logo-oscuro.png");
  return (
    <picture style={{ display: "contents" }}>
      <source srcSet="/logo-blanco.png" media="(prefers-color-scheme: dark)" />
      {imagen("/logo-oscuro.png")}
    </picture>
  );
}
