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
      salida/       PostgreSQL, criptografía (argon2, TOTP, Fernet)
  migraciones/      Alembic (la migración 0001 crea el esquema completo)
  tests/            Unitarias (sin BD) e integración (PostgreSQL real)
docs/diseno/        Diseño del modelo de datos
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

# 3. Pruebas
uv run pytest
```
