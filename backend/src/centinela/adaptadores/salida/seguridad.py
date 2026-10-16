"""Adaptadores criptográficos: argon2id para contraseñas, TOTP (RFC 6238) y cifrado Fernet para secretos."""
from __future__ import annotations

from datetime import UTC, datetime

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet, InvalidToken

EMISOR_TOTP = "Centinela"


class RelojSistema:
    def ahora(self) -> datetime:
        return datetime.now(UTC)


class HasherArgon2:
    """argon2id con los parámetros recomendados por la librería (RFC 9106)."""

    def __init__(self, hasher: PasswordHasher | None = None):
        self._ph = hasher or PasswordHasher()

    def hashear(self, clave: str) -> str:
        return self._ph.hash(clave)

    def verificar(self, clave: str, hash_guardado: str) -> bool:
        try:
            return self._ph.verify(hash_guardado, clave)
        except (VerificationError, InvalidHashError):
            return False

    def necesita_rehash(self, hash_guardado: str) -> bool:
        return self._ph.check_needs_rehash(hash_guardado)


class CifradorFernet:
    """Cifrado autenticado (AES-128-CBC + HMAC-SHA256). La llave vive fuera de la base de datos."""

    def __init__(self, llave: str):
        self._f = Fernet(llave.encode())

    def cifrar(self, texto: str) -> bytes:
        return self._f.encrypt(texto.encode())

    def descifrar(self, datos: bytes) -> str:
        try:
            return self._f.decrypt(bytes(datos)).decode()
        except InvalidToken as e:
            raise ValueError("No se pudo descifrar: la llave de cifrado no corresponde.") from e


class ServicioTotpPyotp:
    """Códigos de 6 dígitos cada 30 s. Acepta el código anterior y el siguiente por desfase de reloj."""

    def __init__(self, ventana: int = 1):
        self._ventana = ventana

    def generar_secreto(self) -> str:
        return pyotp.random_base32()

    def uri_aprovisionamiento(self, secreto: str, cuenta: str) -> str:
        return pyotp.TOTP(secreto).provisioning_uri(name=cuenta, issuer_name=EMISOR_TOTP)

    def verificar(self, secreto: str, codigo: str, ahora: datetime) -> int | None:
        if not (codigo.isdigit() and len(codigo) == 6):
            return None
        totp = pyotp.TOTP(secreto)
        paso_actual = totp.timecode(ahora)
        for delta in range(-self._ventana, self._ventana + 1):
            paso = paso_actual + delta
            if pyotp.utils.strings_equal(totp.generate_otp(paso), codigo):
                return paso
        return None
