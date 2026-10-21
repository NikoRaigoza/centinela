"""Registra en datos/colombia/manifiesto.csv los correos que agregaste a mano (exportados de Gmail, contribuidos,
sintéticos) y agrupa las campañas. Los de sandboxes se registran solos al importarlos (importar_sandbox.py).

    uv run python -I scripts/manifiesto.py --solo-arbol                 # crea carpetas y CSV vacíos
    uv run python -I scripts/manifiesto.py                              # nuevos = gmail_propio
    uv run python -I scripts/manifiesto.py --origen contribuido --url-fuente "autorización 03"
    uv run python -I scripts/manifiesto.py --recalcular-campanas        # rehace las campañas automáticas

Puedes corregir a mano origen, url_fuente, fecha y campana en el CSV: se respetan. Una campaña escrita a mano (que
no empieza por "auto-") nunca se recalcula. La carpeta del archivo manda sobre etiqueta y categoría.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))      # python -I no agrega la carpeta del script
import conjunto_colombia as cc


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--origen", default="gmail_propio", choices=[o for o in cc.ORIGENES if o != "reconstruido"],
                    help="origen de los correos NUEVOS (reconstruidos.csv siempre es «reconstruido»)")
    ap.add_argument("--url-fuente", default="", help="para los correos nuevos (p. ej. referencia de la autorización)")
    ap.add_argument("--recalcular-campanas", action="store_true")
    ap.add_argument("--solo-arbol", action="store_true")
    args = ap.parse_args()

    for hecho in cc.crear_arbol():
        print(f"· {hecho}")
    if args.solo_arbol:
        return
    if args.origen in ("anyrun", "malwarebazaar"):
        raise SystemExit("Los correos de sandboxes se agregan con scripts/importar_sandbox.py (los sanea).")
    nuevos = {}
    if args.url_fuente:
        conocidos = {r["sha256"] for r in cc.leer_manifiesto()}
        nuevos = {c.archivo: {"url_fuente": args.url_fuente} for c in cc.explorar()[0] if c.sha256 not in conocidos}
    filas, s = cc.sincronizar(args.origen, nuevos, args.recalcular_campanas)
    for a in s.avisos:
        print(f"! {a}")
    for repetido, conservado in s.duplicados:
        print(f"= {repetido} es idéntico a {conservado}: no se cuenta dos veces (puedes borrarlo)")
    for r in s.retirados:
        print(f"- {r} ya no existe: se quitó del manifiesto")
    print(f"\nManifiesto: {len(filas)} correos únicos ({s.nuevos} nuevos), "
          f"{len({f['campana'] for f in filas})} campañas")
    for clave in ("etiqueta", "origen", "categoria"):
        print(f"  por {clave}: " + ", ".join(f"{k} {v}" for k, v in sorted(Counter(f[clave] for f in filas).items())))
    tamanos = Counter(Counter(f["campana"] for f in filas).values())
    print("  campañas por tamaño: " + ", ".join(f"{n} correo(s): {k}" for n, k in sorted(tamanos.items())))


if __name__ == "__main__":
    main()
