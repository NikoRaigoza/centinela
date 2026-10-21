"""Límite de peticiones por dirección IP en las rutas sensibles (ingreso, doble factor, registro).

Complementa el bloqueo por cuenta (5 intentos): evita que alguien pruebe muchas cuentas distintas desde la misma IP o
llene la base de solicitudes de registro. Ventana deslizante en memoria: basta con un solo proceso de la API, que es
como corre en producción (el análisis tarda milisegundos). Detrás de Caddy, la IP real llega en X-Forwarded-For.
"""
from __future__ import annotations

import threading
import time
from collections import deque

# ruta → (máximo de peticiones, ventana en segundos)
LIMITES: dict[str, tuple[int, int]] = {
    "/api/auth/inicio": (20, 300),
    "/api/auth/2fa/verificacion": (20, 300),
    "/api/auth/clave-temporal": (10, 300),
    "/api/auth/registro": (5, 3600),
    "/api/usuarios/yo/eliminacion": (5, 3600),
}


class LimitadorIP:
    def __init__(self, limites: dict[str, tuple[int, int]] | None = None, reloj=time.monotonic):
        self._limites = limites or LIMITES
        self._reloj = reloj
        self._golpes: dict[tuple[str, str], deque[float]] = {}
        self._candado = threading.Lock()

    def aplica(self, ruta: str) -> bool:
        return ruta in self._limites

    def permitir(self, ruta: str, ip: str) -> int | None:
        """None si se permite; si no, los segundos que faltan para poder intentarlo de nuevo."""
        maximo, ventana = self._limites[ruta]
        ahora = self._reloj()
        with self._candado:
            golpes = self._golpes.setdefault((ruta, ip), deque())
            while golpes and golpes[0] <= ahora - ventana:
                golpes.popleft()
            if len(golpes) >= maximo:
                return max(1, int(golpes[0] + ventana - ahora) + 1)
            golpes.append(ahora)
            if len(self._golpes) > 50_000:             # memoria acotada ante un barrido de IPs
                self._golpes = {k: v for k, v in self._golpes.items() if v and v[-1] > ahora - 3600}
            return None
