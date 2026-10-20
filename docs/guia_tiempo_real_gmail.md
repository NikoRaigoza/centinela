# Avisos de Gmail en tiempo real (Google Cloud Pub/Sub)

Sin esta configuración, el `worker` pregunta a Gmail cada 30 segundos si llegaron correos. Con ella, Gmail **avisa a
Centinela apenas llega un correo** y el worker lo revisa en menos de un segundo; la revisión periódica queda solo de
respaldo (cada 5 minutos, `analisis.intervalo_respaldo_s`).

```
Correo nuevo → Gmail publica en un tema de Pub/Sub → Pub/Sub llama a POST /api/gmail/notificaciones (firmado por Google)
            → la API marca el buzón y hace NOTIFY en PostgreSQL → el worker despierta y lo revisa al instante
```

**Requisito:** la API debe estar publicada en internet con **HTTPS** (Pub/Sub no entrega a `localhost`). En desarrollo
se usa la revisión cada 30 s; también se puede probar con un túnel HTTPS (por ejemplo, Cloudflare Tunnel).

## Pasos en Google Cloud (mismo proyecto del OAuth de Gmail)

1. **Activa la API de Pub/Sub**: *APIs y servicios → Biblioteca → Cloud Pub/Sub API → Habilitar*.
2. **Crea el tema**: *Pub/Sub → Temas → Crear tema*, por ejemplo `gmail-centinela`. Su nombre completo queda como
   `projects/<tu-proyecto>/topics/gmail-centinela`.
3. **Deja que Gmail publique en el tema**: en el tema, *Permisos → Agregar principal*:
   `gmail-api-push@system.gserviceaccount.com` con el rol **Publicador de Pub/Sub**.
4. **Crea una cuenta de servicio** para firmar las entregas: *IAM → Cuentas de servicio → Crear*, por ejemplo
   `pubsub-push-centinela` (no necesita roles ni llaves).
5. **Crea la suscripción push**: *Pub/Sub → Suscripciones → Crear*:
   - Tema: el del paso 2. Tipo de entrega: **Push**.
   - Extremo: `https://TU-DOMINIO/api/gmail/notificaciones`
   - **Habilitar autenticación**: cuenta de servicio del paso 4; audiencia: la misma URL del extremo.
   - Vencimiento: nunca. Reintentos: «Reintentar después de una demora exponencial».
6. **Configura Centinela** en `backend/.env` y reinicia la API y el worker:

   ```
   CENTINELA_PUBSUB_TEMA=projects/<tu-proyecto>/topics/gmail-centinela
   CENTINELA_PUBSUB_AUDIENCIA=https://TU-DOMINIO/api/gmail/notificaciones
   CENTINELA_PUBSUB_CUENTA_SERVICIO=pubsub-push-centinela@<tu-proyecto>.iam.gserviceaccount.com
   ```

El worker pide los avisos (`users.watch`) a cada buzón activo al minuto de arrancar y los renueva una vez al día
(Gmail los da por 7 días). En **Mis buzones** cada buzón muestra la insignia **«Tiempo real»** cuando ya están activos.
Si Gmail los rechaza (por ejemplo, porque falta el permiso del paso 3), el worker lo registra en su bitácora, sigue
revisando cada 30 s y lo reintenta a los 15 minutos.

## Seguridad

- La API solo acepta notificaciones con un token OIDC **firmado por Google** (se verifica con sus llaves públicas), para
  la audiencia configurada y emitido para la cuenta de servicio del paso 4. Cualquier otra petición recibe `401`.
- La notificación solo trae la dirección del buzón y un número de historial: nunca el contenido del correo. Centinela
  la usa únicamente para saber que debe revisar ese buzón.
- Si la notificación es de un buzón desconocido, pausado o desconectado, se responde `204` y se ignora (así Pub/Sub no
  la reintenta indefinidamente).
