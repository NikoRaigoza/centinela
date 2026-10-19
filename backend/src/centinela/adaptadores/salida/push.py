"""Notificaciones Web Push (estándar del W3C, sin depender de Firebase ni de otro tercero).

- Cifrado de punta a punta (RFC 8291, «aes128gcm» del RFC 8188): el servicio push del navegador (Google, Mozilla,
  Apple o Microsoft) transporta el aviso pero no puede leerlo.
- Identificación del servidor con VAPID (RFC 8292): una llave P-256 propia. Las suscripciones quedan ligadas a
  esa llave, así que nadie más puede enviar avisos a nombre de Centinela aunque conozca la suscripción.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import struct
from datetime import timedelta
from urllib.parse import urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from centinela.aplicacion.puertos import DatosAviso, Reloj, ResultadoPush, SuscripcionPush

log = logging.getLogger(__name__)

TAMANO_REGISTRO = 4096
VIGENCIA_VAPID = timedelta(hours=12)       # el estándar permite hasta 24 h
TTL_S = 24 * 3600                          # si el dispositivo está apagado, el servicio guarda el aviso un día


def b64(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode()


def desde_b64(texto: str) -> bytes:
    return base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4))


def _hmac(llave: bytes, datos: bytes) -> bytes:
    return hmac.new(llave, datos, hashlib.sha256).digest()


def _publica_cruda(llave: ec.EllipticCurvePrivateKey) -> bytes:
    return llave.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def generar_llaves_vapid() -> tuple[str, str]:
    """(privada, pública) en base64url, el formato que usan los navegadores y las librerías de Web Push."""
    llave = ec.generate_private_key(ec.SECP256R1())
    return b64(llave.private_numbers().private_value.to_bytes(32, "big")), b64(_publica_cruda(llave))


def cifrar(carga: bytes, p256dh: str, auth: str, *, sal: bytes | None = None,
           efimera: ec.EllipticCurvePrivateKey | None = None) -> bytes:
    """Cifra el aviso para UNA suscripción (RFC 8291). `sal` y `efimera` solo se fijan en las pruebas."""
    pub_navegador = desde_b64(p256dh)
    secreto_auth = desde_b64(auth)
    if len(pub_navegador) != 65 or len(secreto_auth) != 16:
        raise ValueError("Suscripción push con llaves inválidas")
    if len(carga) > TAMANO_REGISTRO - 17:                  # 16 de la etiqueta GCM + 1 del delimitador
        raise ValueError("El aviso push es demasiado grande")
    efimera = efimera or ec.generate_private_key(ec.SECP256R1())
    sal = sal or os.urandom(16)
    pub_servidor = _publica_cruda(efimera)
    punto = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_navegador)
    compartido = efimera.exchange(ec.ECDH(), punto)

    prk_llave = _hmac(secreto_auth, compartido)
    ikm = _hmac(prk_llave, b"WebPush: info\x00" + pub_navegador + pub_servidor + b"\x01")
    prk = _hmac(sal, ikm)
    cek = _hmac(prk, b"Content-Encoding: aes128gcm\x00\x01")[:16]
    nonce = _hmac(prk, b"Content-Encoding: nonce\x00\x01")[:12]
    cifrado = AESGCM(cek).encrypt(nonce, carga + b"\x02", None)     # \x02 = último (y único) registro
    return sal + struct.pack("!IB", TAMANO_REGISTRO, len(pub_servidor)) + pub_servidor + cifrado


def carga_de_aviso(d: DatosAviso) -> dict:
    """Lo que muestra la notificación. A propósito NO incluye el asunto ni el remitente: los escribió el atacante y
    se verían con la marca de Centinela en la pantalla bloqueada. El detalle está en el panel."""
    nivel = "alto" if d.nivel == "alto" else "medio"
    return {
        "titulo": "Centinela detuvo un correo peligroso" if nivel == "alto" else "Centinela marcó un correo sospechoso",
        "cuerpo": f"Riesgo {nivel}. " + ("Lo movimos a cuarentena (no se borró)." if d.en_cuarentena
                                         else "Sigue en tu bandeja, marcado como sospechoso.") + " Toca para ver por qué.",
        "url": f"/casos/{d.caso_id}" if d.caso_id else "/casos",
        "etiqueta": f"caso-{d.caso_id}" if d.caso_id else "centinela",
    }


class EnviadorWebPush:
    def __init__(self, clave_privada: str, contacto: str, http: httpx.Client, reloj: Reloj):
        valor = int.from_bytes(desde_b64(clave_privada), "big")
        self._llave = ec.derive_private_key(valor, ec.SECP256R1())
        self.clave_publica = b64(_publica_cruda(self._llave))
        self._contacto = contacto
        self._http = http
        self._reloj = reloj

    def _vapid(self, endpoint: str) -> str:
        partes = urlsplit(endpoint)
        reclamos = {"aud": f"{partes.scheme}://{partes.netloc}", "sub": self._contacto,
                    "exp": int((self._reloj.ahora() + VIGENCIA_VAPID).timestamp())}
        token = jwt.encode(reclamos, self._llave, algorithm="ES256")
        return f"vapid t={token}, k={self.clave_publica}"

    def enviar(self, s: SuscripcionPush, carga: dict) -> ResultadoPush:
        cuerpo = cifrar(json.dumps(carga, ensure_ascii=False).encode(), s.p256dh, s.auth)
        try:
            r = self._http.post(s.endpoint, content=cuerpo, headers={
                "Authorization": self._vapid(s.endpoint), "Content-Encoding": "aes128gcm",
                "Content-Type": "application/octet-stream", "TTL": str(TTL_S), "Urgency": "high"})
        except httpx.HTTPError:
            return ResultadoPush.ERROR
        if r.status_code in (200, 201, 202):
            return ResultadoPush.ENTREGADO
        # Solo el servicio y la respuesta: la dirección completa identifica al dispositivo
        log.warning("El servicio push %s respondió %s: %s", urlsplit(s.endpoint).hostname, r.status_code, r.text[:200])
        if r.status_code in (404, 410):          # el usuario desinstaló, bloqueó o la suscripción caducó
            return ResultadoPush.VENCIDA
        return ResultadoPush.ERROR
