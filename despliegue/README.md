# Despliegue de Centinela en Azure (costo cero)

Arquitectura: **un solo servidor** (Azure for Students) con Docker Compose:

```
Internet ──HTTPS──► caddy (certificado Let's Encrypt automático)
                      └──► api (FastAPI + panel React)   ─┐
                           worker (Gmail, avisos, retención) ├──► bd (PostgreSQL 16, sin puerto público)
                           migrar (alembic, al arrancar)  ─┘
                           respaldo (pg_dump diario cifrado → ./respaldos [→ Azure Blob, opcional])
```

Tiempo estimado: 1–2 horas, más la espera del DNS. Marca cada paso en `docs/plan_produccion.md`.

---

## 0. Antes de empezar (en tu computador)

1. **Azure for Students**: https://azure.microsoft.com/free/students → «Activar ahora» con tu **correo institucional**.
   No pide tarjeta. Revisa en el portal → *Suscripciones* que aparezca «Azure for Students» con su crédito.
2. **GitHub Student Developer Pack**: https://education.github.com/pack con el mismo correo institucional (la
   aprobación puede tardar unos días). Luego, en la oferta de **Namecheap**, reclama un dominio `.me` gratis por un
   año (por ejemplo `centinela-tesis.me`). Alternativa inmediata y gratuita: un subdominio de **DuckDNS**
   (https://www.duckdns.org, p. ej. `centinela-tesis.duckdns.org`).
3. **Repositorio privado en GitHub** con este proyecto (`git remote add origin ...` y `git push -u origin main`).
   La integración continua (`.github/workflows/pruebas.yml`) correrá sola en cada `push`.
4. **Llave SSH** (si no tienes una): `ssh-keygen -t ed25519 -C "centinela-azure"`. La pública queda en
   `~/.ssh/id_ed25519.pub`.

## 1. Crear la máquina virtual

Portal de Azure → *Máquinas virtuales* → *Crear* → *Máquina virtual de Azure*:

| Campo | Valor |
|---|---|
| Suscripción | Azure for Students |
| Grupo de recursos | nuevo: `centinela` |
| Nombre | `centinela` |
| Región | la más cercana que tenga el tamaño gratuito (p. ej. *East US 2* o *Brazil South*) |
| Imagen | **Ubuntu Server 24.04 LTS** |
| Tamaño | uno marcado como **«Apto para servicios gratuitos»** (B1s, o B2ats v2 / B2pts v2 si aparecen). Con 1 GB de RAM alcanza: el script crea 2 GB de swap |
| Autenticación | **Clave pública SSH**, usuario `centinela`, pega el contenido de `id_ed25519.pub` |
| Puertos de entrada | SSH (22) por ahora |
| Disco del SO | SSD estándar (el gratuito es de hasta 64 GB) |
| Red → IP pública | nueva, **estática** |

Al terminar, en la VM → *Configuración de red* agrega reglas de entrada: **HTTP (80)** y **HTTPS (443, TCP y UDP)**
desde *Any*, y cambia la regla de **SSH (22)** para que el origen sea **«Mi dirección IP»**.

> La IP pública estática y el disco se descuentan del crédito de estudiante (unos pocos dólares al mes). Revisa
> *Administración de costos* a la semana para confirmar el consumo.

## 2. Apuntar el dominio a la IP

- **Namecheap**: *Domain List → Manage → Advanced DNS*: registro **A**, host `@`, valor = IP pública de la VM.
- **DuckDNS**: escribe la IP en el campo *current ip* del subdominio y pulsa *update ip*.

Comprueba desde tu computador (puede tardar de minutos a pocas horas): `dig +short TU-DOMINIO` debe mostrar la IP.

## 3. Preparar el servidor

```bash
ssh centinela@IP-DE-LA-VM
git clone https://github.com/TU-USUARIO/TU-REPO.git /tmp/c && bash /tmp/c/despliegue/preparar_servidor.sh
exit   # vuelve a entrar para que el grupo «docker» tome efecto
```

Para un repositorio privado, en la VM crea una llave de solo lectura (`ssh-keygen -t ed25519 -f ~/.ssh/deploy`),
agrégala en GitHub → *Settings → Deploy keys* (sin permiso de escritura) y clona con
`GIT_SSH_COMMAND="ssh -i ~/.ssh/deploy" git clone git@github.com:TU-USUARIO/TU-REPO.git`.

## 4. Descargar el proyecto y configurar

```bash
ssh centinela@IP-DE-LA-VM
git clone git@github.com:TU-USUARIO/TU-REPO.git /opt/centinela   # (con la deploy key, ver arriba)
cd /opt/centinela
cp despliegue/env.ejemplo .env
cp despliegue/env.app.ejemplo .env.app
chmod 600 .env .env.app
python3 -c "import secrets; [print(secrets.token_hex(24)) for _ in range(4)]"   # 4 contraseñas para .env
python3 -c "import secrets; print(secrets.token_urlsafe(48))"                   # CENTINELA_JWT_SECRETO
nano .env        # dominio, correo TLS y las 4 contraseñas
nano .env.app    # JWT, responsable (nombre y correo de contacto); Gmail, push y Gemini pueden esperar
```

Guarda una copia de `CENTINELA_CLAVE_RESPALDOS` **fuera del servidor** (por ejemplo, en tu gestor de contraseñas):
sin ella los respaldos no se pueden abrir.

## 5. Construir y arrancar

```bash
docker compose -f docker-compose.prod.yml build                         # 5-10 min la primera vez
docker compose -f docker-compose.prod.yml run --rm --no-deps api \
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # → CENTINELA_LLAVE_CIFRADO
nano .env.app
docker compose -f docker-compose.prod.yml run --rm --no-deps api centinela verificar-config
docker compose -f docker-compose.prod.yml up -d
docker compose -f docker-compose.prod.yml ps                            # todo «running»/«healthy»; migrar «exited (0)»
curl https://TU-DOMINIO/api/salud                                       # {"estado":"ok","base_de_datos":"ok"}
```

Si la construcción se queda sin memoria en la VM de 1 GB, constrúyela en tu Mac y envíala:
`docker buildx build --platform linux/amd64 -t centinela:latest --load . && docker save centinela:latest | gzip | ssh centinela@IP 'gunzip | docker load'`
(usa `linux/arm64` si elegiste un tamaño ARM como B2pts v2).

## 6. Modelos y administrador

```bash
C="docker compose -f docker-compose.prod.yml exec api centinela"
$C modelos registrar modelos/contenido/v2.1-corpus-combinado --activar
$C modelos registrar modelos/enlaces/v3-prototipo --activar
docker compose -f docker-compose.prod.yml exec -it api centinela crear-admin --correo TU-CORREO --nombre "Tu nombre"
```

Entra a `https://TU-DOMINIO`, configura el doble factor y guarda los códigos de recuperación.

## 7. Google Cloud: Gmail

En https://console.cloud.google.com (un proyecto nuevo, p. ej. «Centinela»):

1. *APIs y servicios → Biblioteca*: habilita **Gmail API**.
2. *Pantalla de consentimiento de OAuth* (Google Auth Platform):
   - Tipo **Externo**; nombre «Centinela»; correo de asistencia; logotipo opcional.
   - Página principal: `https://TU-DOMINIO/ingreso` · Política de privacidad: `https://TU-DOMINIO/privacidad` ·
     Términos: `https://TU-DOMINIO/terminos` · Dominio autorizado: `TU-DOMINIO`.
   - Acceso a datos (alcances): agrega `https://www.googleapis.com/auth/gmail.modify`.
   - Público: deja la app en **Prueba** y agrega como **usuarios de prueba** cada Gmail que se va a proteger (máx. 100).
3. *Clientes* → *Crear cliente* → **Aplicación web**: URI de redirección autorizado
   `https://TU-DOMINIO/api/gmail/callback`. Copia el ID y el secreto a `.env.app`.
4. `docker compose -f docker-compose.prod.yml up -d` (recrea api y worker con la configuración nueva).

En modo Prueba, Google muestra «Google no verificó esta app» (pulsa *Continuar*) y el permiso vence cada 7 días: el
buzón queda «Desconectado» y se reconecta con un clic. Publicar la app exige la verificación de Google y una auditoría
de seguridad anual de pago; no hace falta para la tesis.

## 8. Notificaciones push, asistente y tiempo real

```bash
docker compose -f docker-compose.prod.yml run --rm --no-deps api centinela generar-vapid --contacto mailto:TU-CORREO
```

Copia las dos líneas a `.env.app`. Para el asistente, crea una clave en https://aistudio.google.com/apikey y ponla en
`CENTINELA_GEMINI_CLAVE`. Para Gmail en tiempo real sigue `docs/guia_tiempo_real_gmail.md` (Pub/Sub pide vincular
una cuenta de facturación; con el uso de Centinela queda dentro de la cuota gratuita). Después:
`docker compose -f docker-compose.prod.yml up -d` y `... exec api centinela verificar-config`.

## 9. Respaldos

- Se hace uno al arrancar y luego cada día a las 3:00 a. m. (Colombia), en `/opt/centinela/respaldos`, cifrados.
  Se conservan 14 días. Para hacer uno ya: `docker compose -f docker-compose.prod.yml exec respaldo sh /scripts/respaldo.sh --una-vez`.
- **Prueba de restauración** (hazla al menos una vez): restaura en una base aparte y revisa los conteos.
  ```bash
  ls respaldos/
  docker compose -f docker-compose.prod.yml exec respaldo sh /scripts/restaurar.sh centinela-AAAAMMDDTHHMMSSZ.dump.enc
  ```
- **Copia fuera del servidor (recomendada)**: crea una *Cuenta de almacenamiento* en el mismo grupo de recursos y,
  dentro, un contenedor `respaldos`. Genera una **SAS** del contenedor con permisos de crear/escribir/listar y
  vencimiento largo, ponla en `CENTINELA_BLOB_SAS_URL` de `.env` y activa:
  `docker compose -f docker-compose.prod.yml --profile nube up -d`.
- **Desastre** (la base de producción se dañó): `docker compose -f docker-compose.prod.yml stop api worker`, restaura
  con `... restaurar.sh ARCHIVO --produccion` y vuelve a `up -d`.

## 10. Monitoreo

- https://uptimerobot.com (gratis): monitor HTTP(S) de `https://TU-DOMINIO/api/salud` cada 5 min con aviso a tu correo.
- Registros: `docker compose -f docker-compose.prod.yml logs -f --tail 100 worker` (o `api`, `caddy`, `respaldo`).
- Uso de recursos: `docker stats --no-stream` y `free -h`.

## 11. Actualizar a una versión nueva

```bash
cd /opt/centinela && git pull
docker compose -f docker-compose.prod.yml up -d --build    # «migrar» aplica las migraciones nuevas antes de arrancar
```

Un modelo de ML nuevo no necesita reconstruir: `git pull` y `... exec api centinela modelos registrar modelos/... --activar`.

## Problemas frecuentes

| Síntoma | Causa probable |
|---|---|
| Caddy no obtiene el certificado | el DNS aún no apunta a la IP, o faltan las reglas 80/443 en Azure |
| La API no arranca: «Configuración insegura para producción» | corre `centinela verificar-config` y corrige lo que liste |
| `redirect_uri_mismatch` al conectar Gmail | el URI en Google Cloud no es exactamente `https://TU-DOMINIO/api/gmail/callback` |
| «Acceso bloqueado: la app no completó la verificación» | ese Gmail no está en los usuarios de prueba |
| El buzón aparece «Desconectado» cada semana | normal en modo Prueba: reconéctalo |
| El worker dice «Gmail no está configurado» | faltan el ID y el secreto en `.env.app` (y `up -d` después de ponerlos) |
