"""Despertador del worker: escucha el canal LISTEN/NOTIFY de PostgreSQL.

Cuando la API recibe un aviso de Gmail, marca el buzón y hace NOTIFY en la misma transacción. Este hilo lo oye y
despierta al worker, que revisa el buzón al instante en vez de esperar al siguiente ciclo. Si la conexión se cae,
reintenta; mientras tanto el worker sigue funcionando con su ciclo normal (nada se pierde: la marca queda en la BD).
"""
from __future__ import annotations

import logging
import threading

import psycopg
from sqlalchemy.engine import make_url

from centinela.adaptadores.salida.postgres.repositorios import CANAL_REVISION

log = logging.getLogger(__name__)


def url_libpq(url_sqlalchemy: str) -> str:
    """postgresql+psycopg://u:c@h/bd → postgresql://u:c@h/bd (lo que entiende psycopg directamente)."""
    return make_url(url_sqlalchemy).set(drivername="postgresql").render_as_string(hide_password=False)


class Despertador:
    def __init__(self, url_bd: str, despertar: threading.Event, parar: threading.Event, canal: str = CANAL_REVISION):
        self._url, self._despertar, self._parar, self._canal = url_libpq(url_bd), despertar, parar, canal
        self.escuchando = threading.Event()
        self._hilo = threading.Thread(target=self._correr, name="despertador", daemon=True)

    def iniciar(self) -> Despertador:
        self._hilo.start()
        return self

    def _correr(self) -> None:
        espera = 1.0
        while not self._parar.is_set():
            try:
                with psycopg.connect(self._url, autocommit=True, connect_timeout=10) as conexion:
                    conexion.execute(f"LISTEN {self._canal}")
                    self.escuchando.set()
                    espera = 1.0
                    while not self._parar.is_set():
                        for _ in conexion.notifies(timeout=1.0):
                            self._despertar.set()
            except psycopg.Error as e:
                self.escuchando.clear()
                log.warning("El despertador perdió la conexión con PostgreSQL (%s); reintenta en %.0f s",
                            type(e).__name__, espera)
                self._parar.wait(espera)
                espera = min(espera * 2, 60.0)
