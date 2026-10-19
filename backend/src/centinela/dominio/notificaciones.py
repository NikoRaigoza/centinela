"""Reglas de las notificaciones push: a qué servicios se puede enviar y cómo se nombra cada dispositivo."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from centinela.dominio.errores import DatoInvalido

# Servicios push de los navegadores. El servidor hace peticiones a la dirección que manda el navegador: sin esta
# lista, alguien podría registrar una dirección interna (p. ej. http://169.254.169.254) y usar a Centinela para
# alcanzarla (SSRF).
SERVICIOS_PUSH = (
    "fcm.googleapis.com",              # Chrome, Edge (Android), Opera, Brave
    ".push.services.mozilla.com",      # Firefox
    ".notify.windows.com",             # Edge en Windows
    ".push.apple.com",                 # Safari (macOS e iOS)
)


def validar_endpoint(endpoint: str) -> str:
    partes = urlsplit(endpoint.strip())
    host = (partes.hostname or "").lower()
    permitido = any(host == s or (s.startswith(".") and host.endswith(s)) for s in SERVICIOS_PUSH)
    if partes.scheme != "https" or partes.port not in (None, 443) or partes.username or not permitido \
            or len(endpoint) > 1024:
        raise DatoInvalido("Este navegador usa un servicio de notificaciones que Centinela no reconoce.")
    return endpoint.strip()


_NAVEGADORES = (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"),
                ("Safari/", "Safari"))
_SISTEMAS = (("Android", "Android"), ("iPhone", "iPhone"), ("iPad", "iPad"), ("Windows", "Windows"),
             ("Mac OS X", "macOS"), ("CrOS", "ChromeOS"), ("Linux", "Linux"))


def nombre_dispositivo(agente: str | None) -> str:
    """«Chrome en Windows», a partir del User-Agent. Solo sirve para que la persona reconozca sus dispositivos."""
    a = agente or ""
    navegador = next((n for marca, n in _NAVEGADORES if marca in a), "Navegador")
    sistema = next((s for marca, s in _SISTEMAS if re.search(re.escape(marca), a)), None)
    return f"{navegador} en {sistema}" if sistema else navegador
