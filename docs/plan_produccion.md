# Plan para llevar Centinela a producción

Estado al 2026-10-20 (commit `2e8504c`). Se avanza paso a paso; marca cada casilla al terminarla.
Prioridad acordada: **gastar lo menos posible** (ver «Opción sin costo» al final).

## 1. Verificado hasta ahora

| Prueba | Resultado |
|---|---|
| Backend: 191 pruebas (unitarias + integración con PostgreSQL real), linter | ✅ |
| Panel: 21 pruebas, tipos y compilación | ✅ |
| Recorrido en Chrome fases 1–4 (registro, ingreso, 2FA del admin, aprobación, casos, liberar, .eml, celular, modo oscuro) | ✅ |
| Fase 5: push real por Google FCM, asistente, borrado de la suscripción al salir | ✅ |
| Adjuntos/QR/fraude (5 de 5 en riesgo alto), reportes PDF/Excel, tiempo real (~0,2 s) | ✅ |
| API en modo producción (HSTS, cabeceras, cookies Secure/HttpOnly/SameSite, docs ocultos, CSP, CORS) | ✅ 13/13 |
| Rendimiento: ~1,4 ms por correo (máx. 5 ms), ~130 MB de memoria | ✅ |
| Dependencias sin vulnerabilidades conocidas (pip-audit, npm audit) | ✅ |

Sin probar todavía: Gmail real, Gemini real, Pub/Sub real y celulares físicos. El `backend/.env` local aún no tiene
Gmail, push, Gemini ni Pub/Sub, y la base `centinela` no tiene usuarios (sí los 4 modelos registrados).

## 2. Código que falta — hecho; guía de despliegue en `despliegue/README.md`

- [x] **Contenedores**: `Dockerfile` en dos etapas (Node compila el panel; Python con `uv`, sin root) y
      `docker-compose.prod.yml` con `caddy` (HTTPS automático), `api`, `worker`, `migrar`, `bd` (sin puerto público) y
      `respaldo`; healthchecks, reinicio automático y modelos de ML en un volumen. Imagen compatible con ARM y x86.
- [x] **Arranque seguro**: en producción la API no inicia con secretos débiles o de ejemplo ni con URL sin `https://`.
- [x] **Ley 1581**: casilla de autorización de datos en el registro (versión y fecha, migración 0005), páginas públicas
      de Política de privacidad y Términos (Google también las exige), y «Eliminar mi cuenta y mis datos».
- [x] **Tarea de retención** diaria en el worker (30 días riesgo bajo, 365 casos cerrados, ya configurados).
- [x] **Recuperación de contraseña**: el administrador genera una clave temporal que obliga a cambiarla al entrar.
- [x] **Límite de intentos por IP** en ingreso y registro.
- [x] **Integración continua** (GitHub Actions): pruebas con PostgreSQL de servicio y construcción de la imagen.
- [x] **Respaldos**: `pg_dump` nocturno cifrado hacia almacenamiento externo, 30 días, con script de restauración.

## 3. Cuentas y datos que solo tú puedes crear

- [ ] **Servidor**: Azure for Students (decidido).
- [ ] **Dominio**: `.me` gratis del GitHub Student Developer Pack (Namecheap); DuckDNS como alternativa inmediata.
- [ ] **Google Cloud** (un solo proyecto):
  - [ ] Habilitar Gmail API (y Pub/Sub API solo si se usa el tiempo real).
  - [ ] Pantalla de consentimiento OAuth: «Externo», modo **Prueba**, nombre, correo de soporte, dominio autorizado,
        URL de inicio y de la política de privacidad, alcance `gmail.modify`, usuarios de prueba (máx. 100).
  - [ ] Credencial OAuth «Aplicación web» con redirección `https://TU-DOMINIO/api/gmail/callback`.
  - [ ] (Opcional) Pub/Sub según `docs/guia_tiempo_real_gmail.md`.
  - ⚠️ Modo Prueba: aviso «Google no verificó esta app» y el permiso vence cada 7 días (reconectar con un clic).
    Publicarla exige verificación de Google y auditoría CASA anual de pago: no se hace para la tesis.
- [ ] **Clave de Gemini** (opcional; sin ella el asistente responde en modo básico).
- [ ] **Correo de contacto** para las notificaciones push (`mailto:...`).
- [ ] **Repositorio privado en GitHub**.

## 4. Despliegue (juntos)

1. [ ] Crear la VM Ubuntu 24.04 con IP pública fija; abrir solo 22 (desde tu IP), 80 y 443.
2. [ ] Asegurar: usuario no root, SSH con llave, `ufw`, `unattended-upgrades`, `fail2ban`.
3. [ ] Instalar Docker y el plugin de Compose.
4. [ ] DNS: apuntar el dominio a la IP y esperar la propagación.
5. [ ] Clonar el repositorio en la VM.
6. [ ] `.env` de producción en el servidor (permisos `600`, nunca en git): `ENTORNO=produccion`, URL con el dominio
       (`URL_PANEL`, `GMAIL_REDIRECT_URI`, `ORIGENES_CORS`), secretos nuevos (JWT, Fernet, contraseñas de la BD),
       Gmail, Gemini y Pub/Sub.
7. [ ] `docker compose run --rm api centinela generar-vapid --contacto mailto:...` y copiar al `.env`.
8. [ ] `docker compose -f docker-compose.prod.yml up -d`; verificar `https://TU-DOMINIO/api/salud`.
9. [ ] Registrar los modelos en la BD nueva:
       `centinela modelos registrar modelos/contenido/v2.1-corpus-combinado --activar` y
       `centinela modelos registrar modelos/enlaces/v3-prototipo --activar`.
10. [ ] `centinela crear-admin --correo ... --nombre ...`, entrar y configurar el 2FA (guardar los códigos).
11. [ ] Activar respaldos y **probar una restauración** en una base aparte.
12. [ ] Monitoreo: UptimeRobot sobre `/api/salud`; `docker compose logs -f worker`.

## 5. Aceptación en producción (Gmail real)

1. [ ] Registrar a una persona de prueba, aprobarla y entrar desde el celular.
2. [ ] Conectar su Gmail: «Protegido» (y «Tiempo real» si hay Pub/Sub).
3. [ ] Enviarle desde otra cuenta: phishing con enlace, con QR, con .zip (archivo inofensivo renombrado), «favor
       urgente» de tarjetas de regalo y un correo legítimo.
4. [ ] Verificar cuarentena sin borrado, máximo 3 razones, aviso en la bandeja, push en Android y en iPhone (agregado
       a inicio) y el tiempo hasta el aviso.
5. [ ] Liberar un caso: vuelve a la bandeja.
6. [ ] Asistente con Gemini real (conjunto de preguntas de prueba).
7. [ ] Reportes personal y de la organización.
8. [ ] Apagar y encender la VM: todo vuelve solo.
9. [ ] Restaurar un respaldo.

## 6. En paralelo: modelo con datos colombianos

- [ ] Reunir correos según `ml/GUIA_DATOS_COLOMBIA.md` (mín. 200 legítimos y 100 de phishing).
- [ ] Verificar los dominios «POR VERIFICAR» del catálogo.
- [ ] Evaluar, corregir falsos positivos, reentrenar y registrar (`modelos registrar --activar`, sin redesplegar).

---

## Opción sin costo (investigada el 2026-10-20)

La estructura no cambia: **un solo servidor con Docker Compose** (Caddy + API + worker + PostgreSQL). Lo que cambia es
de dónde sale cada pieza gratis. Los planes gratuitos cambian a menudo: confirma las condiciones al crear cada cuenta.

| Pieza | Opción gratuita | Notas |
|---|---|---|
| Servidor | **Azure for Students** (USD 100 por 12 meses, sin tarjeta, con correo institucional) o **Oracle Cloud Always Free** (VM ARM, gratis indefinidamente) | Oracle pide tarjeta solo para verificar, a veces no hay capacidad, recortó el límite en 2026 a ~2 OCPU / 12 GB y puede recuperar VMs inactivas. Cualquiera de los dos sobra para Centinela. |
| Dominio | **DuckDNS** (`algo.duckdns.org`, gratis) o un dominio del **GitHub Student Developer Pack** (.me/.tech gratis 1 año) | `duckdns.org` está en la Public Suffix List: Google lo acepta para OAuth. |
| HTTPS | Let's Encrypt vía Caddy | Gratis. |
| Base de datos | PostgreSQL en la misma VM | Gratis; evita los límites de Neon/Supabase. |
| Gmail API / OAuth en modo Prueba | Google | Gratis (hasta 100 usuarios de prueba). |
| Push | Web Push (servicios de Google, Apple, Mozilla, Microsoft) | Gratis. |
| Asistente | Gemini nivel gratuito o modo básico | Gratis (en el nivel gratuito Google puede usar las consultas; ya van anonimizadas). |
| Tiempo real | Pub/Sub (10 GiB/mes gratis) | Puede pedir una cuenta de facturación con tarjeta aunque no cobre; si no, se queda la revisión cada 30 s. |
| Respaldos | Almacenamiento del mismo proveedor (crédito de Azure / Object Storage de Oracle) o Backblaze B2 (10 GB gratis) | |
| Monitoreo | UptimeRobot | Gratis. |
| Repositorio e integración continua | GitHub (privado) + GitHub Actions | Gratis dentro de los minutos mensuales. |

**Descartados para este proyecto:** Vercel (funciones sin servidor de máx. 300 s: no sirve para el worker ni para
PostgreSQL), Render gratis (se duerme a los 15 min y la BD gratis se borra a los 30 días), Koyeb gratis (no admite
workers y se duerme), Fly.io (ya no tiene plan gratis).

**Solo de pago, y no se necesita para la tesis:** verificación de Google y auditoría CASA (abrir Gmail al público),
renovar un dominio propio después del primer año (o seguir con DuckDNS), y más servidor si se agota el crédito o la
cuota gratuita.
