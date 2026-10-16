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
