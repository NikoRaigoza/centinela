# Centinela

Detección de phishing en correos de Gmail para usuarios en Colombia. Proyecto de grado.

Centinela se conecta a un buzón de Gmail (OAuth2), analiza cada correo nuevo con reglas de seguridad y modelos de
machine learning (XGBoost), pone en cuarentena los de riesgo alto sin borrarlos, avisa al dueño del buzón y explica en
español, con máximo tres razones, por qué el correo es peligroso. Incluye un panel web con doble factor y un asistente de IA.

## Estructura

```
backend/            API y lógica (Python, FastAPI, arquitectura hexagonal)
  src/centinela/
    dominio/        Entidades y reglas puras (usuario, riesgo, caso)
    aplicacion/     Puertos (interfaces) y casos de uso
    adaptadores/
      entrada/      API REST y consola
      salida/       PostgreSQL, Gmail (OAuth2 + API), lector MIME, criptografía
  migraciones/      Alembic (la migración 0001 crea el esquema completo)
  tests/            Unitarias (sin BD) e integración (PostgreSQL real)
frontend/           Panel web (React + TypeScript + Vite)
  src/api/          Cliente HTTP (sesión segura) y una función por operación de la API
  src/paginas/      Pantallas: inicio, correos de riesgo, buzones, análisis, cuenta, administración
  src/componentes/  Piezas reutilizables (gráfico, diálogos, código QR del 2FA…)
ml/                 Entrenamiento y evaluación de los modelos (ver ml/README.md)
docs/               Diseño del modelo de datos y guía de conexión con Gmail
legacy/             Prototipo original en Streamlit (solo referencia)
docker-compose.yml  Base de datos PostgreSQL en contenedor
```

## Puesta en marcha (desarrollo)

Requisitos: Python 3.12+, [uv](https://docs.astral.sh/uv/), PostgreSQL 16 (local o con Docker).

```bash
# 1. Base de datos: crea roles (centinela_owner, centinela_app) y las bases centinela y centinela_pruebas
psql -d postgres -v clave_owner='...' -v clave_app='...' -f backend/scripts/crear_bd.sql
#    o con Docker:  cp .env.example .env  &&  docker compose up -d bd

# 2. Backend
cd backend
cp .env.example .env           # completa URLs, secreto JWT y llave de cifrado
uv sync
uv run alembic upgrade head    # crea el esquema
uv run centinela crear-admin --correo admin@tuempresa.co --nombre "Administración"
uv run centinela api --recargar   # http://127.0.0.1:8000/api/docs
uv run centinela worker           # revisa los buzones de Gmail conectados (ver docs/guia_conexion_gmail.md)

# 3. Panel web (en otra terminal)
cd frontend
npm install
npm run dev                    # http://localhost:5173 (reenvía /api al backend en el puerto 8000)

# 4. Pruebas
cd backend && uv run pytest
cd frontend && npm test
```

### Producción

`cd frontend && npm run build` genera `frontend/dist/`. Si esa carpeta existe, la API también sirve el panel
(`CENTINELA_DIR_PANEL` permite cambiar la ruta), así que basta un proceso: `uv run centinela api` detrás de HTTPS
con `CENTINELA_ENTORNO=produccion` (cookies `Secure`, HSTS y sin `/api/docs`).

### Seguridad del panel
- El token de acceso (15 min) vive solo en memoria; el de renovación, en una cookie `httpOnly` y `SameSite=Strict`
  que rota en cada uso (si alguien reutiliza uno viejo, se cierran todas las sesiones).
- Panel y API en el mismo origen: sin CORS en producción. CSP estricta: el panel no carga nada de terceros.
- El código QR del doble factor se genera en el navegador; el secreto nunca sale hacia otros servicios.
