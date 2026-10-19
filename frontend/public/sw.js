// Service worker de Centinela: SOLO muestra las notificaciones push. No guarda páginas ni datos en caché.
"use strict";

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (evento) => evento.waitUntil(self.clients.claim()));

self.addEventListener("push", (evento) => {
  let datos = {};
  try {
    datos = evento.data ? evento.data.json() : {};
  } catch {
    datos = {};
  }
  const titulo = typeof datos.titulo === "string" ? datos.titulo : "Centinela";
  evento.waitUntil(
    self.registration.showNotification(titulo, {
      body: typeof datos.cuerpo === "string" ? datos.cuerpo : "Tienes un aviso nuevo en Centinela.",
      icon: "/icono-192.png",       // Android no muestra íconos SVG en las notificaciones
      badge: "/insignia-96.png",    // silueta para la barra de estado de Android
      tag: typeof datos.etiqueta === "string" ? datos.etiqueta : "centinela",
      renotify: true,
      requireInteraction: true,
      data: { url: rutaSegura(datos.url) },
    }),
  );
});

// Solo se abren rutas del propio panel: el aviso nunca lleva a otro sitio
function rutaSegura(url) {
  return typeof url === "string" && url.startsWith("/") && !url.startsWith("//") && !url.startsWith("/\\") ? url : "/";
}

self.addEventListener("notificationclick", (evento) => {
  evento.notification.close();
  const destino = new URL(rutaSegura(evento.notification.data && evento.notification.data.url), self.location.origin).href;
  evento.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((ventanas) => {
      for (const v of ventanas) {
        if (new URL(v.url).origin === self.location.origin && "focus" in v) {
          return v.focus().then(() => ("navigate" in v ? v.navigate(destino) : undefined));
        }
      }
      return self.clients.openWindow(destino);
    }),
  );
});
