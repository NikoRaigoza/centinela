"""Verificación de las notificaciones de Gmail que entrega Google Cloud Pub/Sub (suscripción de tipo «push»).

Pub/Sub firma cada entrega con un token OIDC (JWT RS256) emitido por Google para una cuenta de servicio nuestra.
Se acepta solo si:
  * la firma es válida con las llaves públicas de Google (https://www.googleapis.com/oauth2/v3/certs),
  * lo emitió accounts.google.com, no ha vencido y su audiencia es la configurada en la suscripción,
  * corresponde a la cuenta de servicio configurada (claim `email`, verificado).
Así nadie más puede hacer que Centinela revise buzones a su antojo.
Referencia: https://cloud.google.com/pubsub/docs/authenticate-push-subscriptions
"""
from __future__ import annotations

import threading
import time

import httpx
import jwt

from centinela.aplicacion.puertos import AvisoNoAutentico

URL_LLAVES_GOOGLE = "https://www.googleapis.com/oauth2/v3/certs"
EMISORES_GOOGLE = ("https://accounts.google.com", "accounts.google.com")
CACHE_LLAVES_S = 3600
MIN_ENTRE_DESCARGAS_S = 60      # una llave desconocida no provoca descargas sin fin


class VerificadorOidcGoogle:
    def __init__(self, audiencia: str, cuenta_servicio: str, http: httpx.Client, url_llaves: str = URL_LLAVES_GOOGLE):
        self._audiencia, self._cuenta, self._http, self._url = audiencia, cuenta_servicio.lower(), http, url_llaves
        self._llaves: dict[str, object] = {}
        self._descargadas_en = float("-inf")
        self._candado = threading.Lock()

    def _descargar(self) -> None:
        r = self._http.get(self._url)
        r.raise_for_status()
        self._llaves = {k["kid"]: jwt.PyJWK(k).key for k in r.json().get("keys", []) if k.get("kid")}
        self._descargadas_en = time.monotonic()

    def _llave(self, kid: str):
        with self._candado:
            vencidas = time.monotonic() - self._descargadas_en > CACHE_LLAVES_S
            puede = time.monotonic() - self._descargadas_en > MIN_ENTRE_DESCARGAS_S
            if vencidas or (kid not in self._llaves and puede):
                try:
                    self._descargar()
                except (httpx.HTTPError, ValueError, KeyError, jwt.PyJWKError) as e:
                    if kid not in self._llaves:
                        raise AvisoNoAutentico("No se pudieron obtener las llaves públicas de Google.") from e
            return self._llaves.get(kid)

    def verificar(self, token: str) -> None:
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except jwt.PyJWTError as e:
            raise AvisoNoAutentico("Token mal formado.") from e
        llave = self._llave(kid) if kid else None
        if llave is None:
            raise AvisoNoAutentico("El token no lo firmó Google.")
        try:
            reclamos = jwt.decode(token, llave, algorithms=["RS256"], audience=self._audiencia, leeway=60,
                                  options={"require": ["exp", "iat", "iss", "aud"]})
        except jwt.PyJWTError as e:
            raise AvisoNoAutentico(f"Token inválido: {type(e).__name__}.") from e
        if reclamos.get("iss") not in EMISORES_GOOGLE:
            raise AvisoNoAutentico("El token no lo emitió Google.")
        if str(reclamos.get("email", "")).lower() != self._cuenta or reclamos.get("email_verified") is not True:
            raise AvisoNoAutentico("El token no es de la cuenta de servicio configurada.")
