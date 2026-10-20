"""Avisos de Gmail en tiempo real (Gmail API + Google Cloud Pub/Sub).

Sin esto, el worker pregunta a Gmail cada 30 s si hay correos nuevos. Con esto:
  1. El worker pide a Gmail, por cada buzón, que avise de los cambios en la bandeja (users.watch). El permiso dura
     7 días; se renueva cada día.
  2. Cuando llega un correo, Gmail publica en un tema de Pub/Sub y Pub/Sub lo entrega a la API de Centinela
     (POST /api/gmail/notificaciones), firmado por Google.
  3. La API marca el buzón y despierta al worker (LISTEN/NOTIFY de PostgreSQL), que lo revisa en ese instante.
La revisión periódica sigue existiendo como respaldo (cada 5 min), por si una notificación se pierde.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta

from centinela.aplicacion.casos_uso.comun import CasoDeUso
from centinela.aplicacion.puertos import (
    AccesoCorreoRevocado,
    AvisoNoAutentico,
    Cifrador,
    ErrorProveedorCorreo,
    FabricaUnidadDeTrabajo,
    ProveedorCorreo,
    Reloj,
    VerificadorAvisosGmail,
)
from centinela.dominio.errores import CredencialesInvalidas, ServicioNoDisponible

log = logging.getLogger(__name__)

RENOVAR_SI_VENCE_EN = timedelta(days=6)     # el permiso dura 7 días: así se renueva una vez al día
ESPERA_TRAS_FALLO = timedelta(minutes=15)


class RecibirAvisoGmail(CasoDeUso):
    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, verificador: VerificadorAvisosGmail | None):
        super().__init__(uow, reloj)
        self._verificador = verificador

    def ejecutar(self, token: str | None, correo: str | None) -> bool:
        """True si había un buzón activo con esa dirección y quedó pedida su revisión."""
        if self._verificador is None:
            raise ServicioNoDisponible("Los avisos de Gmail en tiempo real no están configurados en este servidor.")
        try:
            if not token:
                raise AvisoNoAutentico("Falta el token.")
            self._verificador.verificar(token)
        except AvisoNoAutentico as e:
            log.warning("Notificación de Gmail rechazada: %s", e)
            raise CredencialesInvalidas("La notificación no viene de Google.") from None
        if not correo:
            return False
        with self._uow() as uow:
            buzon = uow.buzones.por_correo(correo.strip().lower())
            if buzon is None or not buzon.revisable:
                return False                      # buzón desconectado o pausado: se acepta y se ignora
            uow.buzones.solicitar_revision(buzon.id, self._reloj.ahora())
            uow.confirmar()
        return True


class RenovarVigilancias(CasoDeUso):
    """Lo ejecuta el worker cada minuto: pide los avisos en tiempo real a los buzones que aún no los tienen o cuyo
    permiso vence en menos de 6 días."""

    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, proveedor: ProveedorCorreo | None, cifrador: Cifrador,
                 tema: str | None):
        super().__init__(uow, reloj)
        self._proveedor, self._cifrador, self._tema = proveedor, cifrador, tema
        self._esperar_hasta: dict[int, datetime] = {}

    @property
    def activo(self) -> bool:
        return bool(self._tema and self._proveedor)

    def ejecutar(self, limite: int = 20) -> int:
        if not self.activo:
            return 0
        ahora = self._reloj.ahora()
        with self._uow() as uow:
            buzones = [b for b in uow.buzones.por_vigilar(ahora + RENOVAR_SI_VENCE_EN, limite * 2)
                       if self._esperar_hasta.get(b.id, ahora) <= ahora][:limite]
        renovados = 0
        for b in buzones:
            try:
                cliente = self._proveedor.abrir(self._cifrador.descifrar(b.refresh_token_cifrado))
                vigilancia = cliente.vigilar(self._tema)
            except AccesoCorreoRevocado:
                continue                          # la próxima revisión del buzón lo marca como desconectado
            except ErrorProveedorCorreo as e:
                log.warning("Buzón %s sin avisos en tiempo real: %s", b.id, e)
                self._esperar_hasta[b.id] = ahora + ESPERA_TRAS_FALLO
                continue
            self._esperar_hasta.pop(b.id, None)
            with self._uow() as uow:
                actual = uow.buzones.por_id(b.id)
                if actual is not None and actual.revisable:
                    actual.registrar_vigilancia(vigilancia.expira_en)
                    uow.buzones.guardar(actual)
                    uow.confirmar()
                    renovados += 1
        return renovados
