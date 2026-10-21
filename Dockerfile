# syntax=docker/dockerfile:1
# Imagen única de Centinela: la misma sirve para la API (que también entrega el panel), el worker y las migraciones.
#   docker compose -f docker-compose.prod.yml build
# Funciona en servidores x86 (amd64) y ARM (arm64).

# ---------------------------------------------------------------------- 1. Panel web (React → archivos estáticos)
FROM node:24-bookworm-slim AS panel
WORKDIR /panel
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---------------------------------------------------------------------- 2. Backend (Python + modelos + panel)
FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH=/app/.venv/bin:$PATH \
    CENTINELA_DIR_PANEL=/app/panel \
    CENTINELA_DIR_MODELOS=/app/modelos
COPY --from=ghcr.io/astral-sh/uv:0.12.23 /uv /bin/uv
WORKDIR /app

# Dependencias primero: si solo cambia el código, esta capa se reutiliza y la construcción tarda segundos
COPY backend/pyproject.toml backend/uv.lock backend/README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY backend/src ./src
RUN uv sync --frozen --no-dev

COPY backend/alembic.ini ./
COPY backend/migraciones ./migraciones
COPY backend/modelos ./modelos
COPY --from=panel /panel/dist ./panel

# Sin privilegios: el proceso no puede modificar su propio código ni los modelos
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin centinela
USER centinela

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/salud', timeout=4)"]
CMD ["centinela", "api", "--host", "0.0.0.0", "--puerto", "8000", "--proxy"]
