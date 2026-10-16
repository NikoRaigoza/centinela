# Guía: conectar Centinela con Gmail (Google Cloud)

Centinela usa OAuth2 para leer y organizar el correo **sin conocer la contraseña** de la persona.
Para eso necesita un proyecto propio en Google Cloud. Es gratis y se hace una sola vez.

> La interfaz de Google Cloud cambia de vez en cuando; los nombres de los menús pueden variar un poco.

## 1. Crear el proyecto y activar la API de Gmail

1. Entra a <https://console.cloud.google.com/> con tu cuenta de Google.
2. Crea un proyecto nuevo llamado **Centinela**.
3. Ve a **APIs y servicios → Biblioteca**, busca **Gmail API** y pulsa **Habilitar**.

## 2. Configurar la pantalla de consentimiento

En **Google Auth Platform** (antes «Pantalla de consentimiento de OAuth»):

1. **Información de la marca**: nombre de la app `Centinela`, tu correo de asistencia y tu correo de contacto.
2. **Público**: tipo de usuario **Externo**.
3. **Acceso a los datos** → **Agregar o quitar permisos**: agrega
   `https://www.googleapis.com/auth/gmail.modify` (leer, etiquetar e insertar correos; **no permite borrar**).
4. **Público → Publicar la app** para pasarla a **En producción**.

| Estado | Qué pasa | Para Centinela |
|---|---|---|
| Prueba | Solo usuarios de prueba; **el permiso vence cada 7 días** | No sirve: habría que reconectar cada semana |
| En producción **sin verificar** | Hasta 100 cuentas; Google muestra una advertencia al conectar | ✅ Lo que usamos para la tesis y el piloto |
| En producción verificada | Sin límite, sin advertencia; exige auditoría de seguridad anual de pago | Trabajo futuro |

Al conectar un buzón, Google mostrará **«Google no verificó esta app»**. Pulsa
**Configuración avanzada → Ir a Centinela (no seguro)**. Es esperado en una app no verificada.

## 3. Crear las credenciales

1. **Google Auth Platform → Clientes → Crear cliente**.
2. Tipo de aplicación: **Aplicación web**. Nombre: `Centinela local`.
3. **URI de redireccionamiento autorizados**: `http://localhost:8000/api/gmail/callback`
4. Copia el **ID de cliente** y el **secreto del cliente** en `backend/.env`:

```
CENTINELA_GMAIL_CLIENT_ID=xxxxxxxx.apps.googleusercontent.com
CENTINELA_GMAIL_CLIENT_SECRET=GOCSPX-xxxxxxxx
```

El secreto **nunca** se sube a git (`.env` está en `.gitignore`).

## 4. Probar la conexión (antes de tener el panel React)

```bash
cd backend
uv run centinela api        # terminal 1
uv run centinela worker     # terminal 2: revisa los buzones cada 30 s
```

1. Abre <http://localhost:8000/api/docs> **en el mismo navegador** con el que vas a conectar Gmail.
2. `POST /api/auth/inicio` con tu usuario y copia `token_acceso` (si es el administrador, completa antes el doble factor).
3. Pulsa **Authorize** y pega el token.
4. Ejecuta `POST /api/buzones/conexion` y abre en una pestaña la `url` que devuelve.
5. Acepta el permiso en Google. Verás «Buzón conectado».
6. Envíate un correo a ese Gmail: en máximo 30 s aparecerá en `GET /api/buzones/{id}/mensajes`.

En tu Gmail aparecerán dos etiquetas nuevas: **Centinela/Cuarentena** y **Centinela/Sospechoso**.

## Qué guarda Centinela y qué no

- Guarda el permiso de Google **cifrado** (Fernet). La llave está en `.env`, fuera de la base de datos.
- De cada correo guarda remitente, asunto, fecha, resultados de SPF/DKIM/DMARC y datos de los adjuntos. **Nunca el cuerpo.**
- Al desconectar un buzón, Centinela borra el permiso y también lo revoca en la cuenta de Google.
- La persona puede quitar el permiso en cualquier momento desde <https://myaccount.google.com/permissions>.
  Centinela lo detecta y marca el buzón como desconectado.
