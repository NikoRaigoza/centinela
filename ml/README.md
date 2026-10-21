# Centinela · ML

Experimentos y entrenamiento de los modelos (proyecto aparte del backend: `uv sync` aquí).

## Datos (no se suben a git)

| Dataset | Dónde ponerlo | Fuente |
|---|---|---|
| SpearPhishMX v2 | `datos/spearphishmx/` | Mendeley Data, DOI 10.17632/h4bxjk84jb.2 (CC BY 4.0) |
| SpaPhish | `datos/spaphish/` | Mendeley Data, DOI 10.17632/hz2d6gz7pc (CC BY 4.0) |

## Scripts

```bash
uv run python -I scripts/explorar.py  "$PWD/datos"   # descripción y artefactos de SpearPhishMX
uv run python -I scripts/explorar2.py "$PWD/datos"   # semántica de las etiquetas
uv run python -I scripts/cruce.py     "$PWD/datos"   # cruce de etiquetas con SpaPhish
```

Resultados en `hallazgos_calidad_datos.md`.

### Conjunto colombiano (experimento central)

Guía completa en `GUIA_DATOS_COLOMBIA.md`.

```bash
uv run python -I scripts/manifiesto.py --solo-arbol          # carpetas y CSV vacíos en datos/colombia/
uv run python -I scripts/importar_sandbox.py ZIP --origen anyrun --categoria bancos --url-fuente URL  # saneado
uv run python -I scripts/manifiesto.py                       # registra correos agregados a mano y sus campañas
uv run python -I scripts/evaluar_colombia.py [--solo-contenido]   # conjunto de ajuste
uv run pytest tests                                          # pruebas de la ingesta, el manifiesto y la división
```
