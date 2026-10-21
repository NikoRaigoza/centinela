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
  migraciones/      Alembic (0001 crea el esquema; las siguientes lo amplían sin tocarla)
  tests/            Unitarias (sin BD) e integración (PostgreSQL real)
frontend/           Panel web (React + TypeScript + Vite)
  src/api/          Cliente HTTP (sesión segura) y una función por operación de la API
  src/paginas/      Pantallas: inicio, correos de riesgo, buzones, análisis, cuenta, administración
  src/componentes/  Piezas reutilizables (gráfico, diálogos, código QR del 2FA…)
ml/                 Entrenamiento y evaluación de los modelos (ver ml/README.md)
docs/               Diseño del modelo de datos y guías de Gmail (conexión y tiempo real)
legacy/             Prototipo original en Streamlit (solo referencia)
docker-compose.yml  Base de datos PostgreSQL en contenedor (desarrollo)
docker-compose.prod.yml + Dockerfile + despliegue/   Producción: Caddy, API, worker, PostgreSQL y respaldos
.github/workflows/  Integración continua: pruebas, linter, auditoría de dependencias e imagen
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
uv run centinela worker           # revisa los buzones de Gmail conectados y entrega los avisos (ver docs/guia_conexion_gmail.md)

# 3. Panel web (en otra terminal)
cd frontend
npm install
npm run dev                    # http://localhost:5173 (reenvía /api al backend en el puerto 8000)

# 4. Pruebas
cd backend && uv run pytest
cd frontend && npm test
```

### Asistente de IA y notificaciones push (opcionales)

- **Asistente**: con `CENTINELA_GEMINI_CLAVE` en `backend/.env` (clave de https://aistudio.google.com/apikey) responde con
  Google Gemini; sin ella, o si Gemini falla o se agota el cupo diario (`asistente.max_preguntas_dia`, 30 por defecto),
  responde en **modo básico** con reglas. Las conversaciones quedan guardadas por usuario.
- **Notificaciones push** (estándar Web Push, sin Firebase): genera las llaves una sola vez con
  `uv run centinela generar-vapid --contacto mailto:tu@correo.co` y copia las dos líneas que imprime en `backend/.env`.
  Cada persona las activa en **Mi cuenta → Notificaciones**. Las entrega el `worker` (solo correos de riesgo alto).
  Si cambias las llaves, hay que reactivarlas.
- **Celulares**: necesitan que el panel se abra por **HTTPS** (en desarrollo, `localhost` solo sirve en el mismo computador).
  - *Android* (Chrome, Edge, Firefox, Samsung Internet): funcionan desde el navegador, incluso con la pestaña cerrada.
    También se puede instalar como app («Agregar a la pantalla principal»).
  - *iPhone / iPad* (iOS 16.4 o posterior): solo si Centinela se agrega a la pantalla de inicio desde Safari
    (Compartir → Agregar a inicio), se abre desde ese ícono, se inicia sesión ahí y se activan los avisos.

### Detección avanzada, reportes y Gmail en tiempo real

- **Adjuntos por dentro**: además del nombre, Centinela mira el contenido real de cada adjunto, en memoria y sin
  guardarlo: programas disfrazados de PDF o de foto, comprimidos con programas adentro (también un .zip dentro de otro),
  comprimidos con clave, Office con macros o con plantilla remota, PDF con código o archivos ocultos, y páginas HTML/SVG
  que piden la contraseña o ejecutan código. El caso muestra cada adjunto con el motivo si es peligroso.
- **Códigos QR (quishing)**: lee los QR de las imágenes del correo y de los PDF adjuntos (zxing-cpp) y analiza su enlace
  como cualquier otro. Un QR hacia un sitio oficial del catálogo (p. ej. el de la DIAN en una factura electrónica) o
  hacia el propio dominio del remitente no se marca.
- **Fraude sin enlaces**: detector con puntaje para la suplantación de un jefe o proveedor (BEC), las tarjetas de regalo,
  el cambio de cuenta bancaria y la extorsión en criptomonedas. Suma lo que el correo pide y el contexto del remitente
  (cuenta gratuita, dominio parecido al de la organización, respuestas a otro dominio, primera vez que escribe).
- **Reportes** (menú **Reportes**): PDF y Excel del periodo (7, 30, 90 o 365 días) con indicadores, gráfico por día,
  tipos de amenaza, entidades suplantadas y el detalle de cada correo de riesgo. El administrador puede descargar el
  de toda la organización, solo con cifras. Cada descarga queda en la auditoría.
- **Gmail en tiempo real** (opcional): con Google Cloud Pub/Sub, Gmail avisa apenas llega un correo y el worker lo
  revisa en menos de un segundo. Pasos en [docs/guia_tiempo_real_gmail.md](docs/guia_tiempo_real_gmail.md).

### Producción

Despliegue completo (Docker Compose con HTTPS automático, respaldos cifrados y costo cero en Azure for Students):
**[despliegue/README.md](despliegue/README.md)**. Plan y estado: [docs/plan_produccion.md](docs/plan_produccion.md).

`cd frontend && npm run build` genera `frontend/dist/`. Si esa carpeta existe, la API también sirve el panel
(`CENTINELA_DIR_PANEL` permite cambiar la ruta), así que basta un proceso: `uv run centinela api` detrás de HTTPS
con `CENTINELA_ENTORNO=produccion` (cookies `Secure`, HSTS y sin `/api/docs`).

### Seguridad del panel
- El token de acceso (15 min) vive solo en memoria; el de renovación, en una cookie `httpOnly` y `SameSite=Strict`
  que rota en cada uso (si alguien reutiliza uno viejo, se cierran todas las sesiones).
- Panel y API en el mismo origen: sin CORS en producción. CSP estricta: el panel no carga nada de terceros.
- El código QR del doble factor se genera en el navegador; el secreto nunca sale hacia otros servicios.
- Asistente: al proveedor de IA solo salen datos mínimos y anonimizados del caso (dominios, sin direcciones de correo,
  enlaces completos ni números largos; el cuerpo del correo nunca se guarda). Las respuestas se muestran como texto,
  nunca como HTML.
- Push: el aviso va cifrado de punta a punta (RFC 8291) y no incluye el asunto ni el remitente (los escribe el atacante).
  El servidor solo envía a servicios push conocidos (Google, Mozilla, Apple, Microsoft): evita peticiones a
  direcciones internas. Al cerrar sesión, el navegador deja de recibir avisos de la cuenta.
