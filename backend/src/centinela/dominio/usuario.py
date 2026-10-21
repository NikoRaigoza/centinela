"""Usuario de Centinela: roles, ciclo de vida de la cuenta, bloqueo por intentos y doble factor."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from centinela.dominio.errores import AccesoDenegado, Conflicto, CredencialesInvalidas, DatoInvalido, TransicionInvalida

_RE_CORREO = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CLAVE_MIN = 10
CLAVE_MAX = 128
# Versión vigente de la Política de tratamiento de datos (frontend/src/paginas/Legal.tsx). Si cambia el texto en algo
# sustancial, se sube la versión: queda registrado qué aceptó cada persona.
VERSION_POLITICA = "2026-10-20"


class Rol(StrEnum):
    ADMINISTRADOR = "administrador"
    USUARIO = "usuario"


class EstadoCuenta(StrEnum):
    PENDIENTE = "pendiente"
    ACTIVO = "activo"
    RECHAZADO = "rechazado"
    DESACTIVADO = "desactivado"


def normalizar_correo(correo: str) -> str:
    c = (correo or "").strip().lower()
    if len(c) > 254 or not _RE_CORREO.fullmatch(c):
        raise DatoInvalido("El correo no es válido.")
    return c


def normalizar_nombre(nombre: str) -> str:
    n = " ".join((nombre or "").split())
    if not 2 <= len(n) <= 120:
        raise DatoInvalido("El nombre debe tener entre 2 y 120 caracteres.")
    return n


def validar_clave(clave: str, correo: str | None = None) -> None:
    if len(clave) < CLAVE_MIN:
        raise DatoInvalido(f"La contraseña debe tener al menos {CLAVE_MIN} caracteres.")
    if len(clave) > CLAVE_MAX:
        raise DatoInvalido(f"La contraseña no puede tener más de {CLAVE_MAX} caracteres.")
    if not re.search(r"[^\W\d_]", clave) or not re.search(r"\d", clave):
        raise DatoInvalido("La contraseña debe combinar letras y números.")
    if correo:
        local = correo.split("@")[0]
        if len(local) >= 4 and local in clave.lower():
            raise DatoInvalido("La contraseña no debe contener tu correo.")


@dataclass
class Usuario:
    correo: str
    nombre: str
    clave_hash: str
    rol: Rol = Rol.USUARIO
    estado: EstadoCuenta = EstadoCuenta.PENDIENTE
    id: int | None = None
    totp_secreto_cifrado: bytes | None = None
    totp_activo: bool = False
    totp_ultimo_paso: int | None = None
    intentos_fallidos: int = 0
    bloqueado_hasta: datetime | None = None
    aprobado_por: int | None = None
    aprobado_en: datetime | None = None
    ultimo_acceso: datetime | None = None
    creado_en: datetime | None = None
    consentimiento_version: str | None = None    # Política de tratamiento de datos aceptada (Ley 1581)
    consentimiento_en: datetime | None = None
    debe_cambiar_clave: bool = False             # tiene una contraseña temporal asignada por el administrador

    # ------------------------------------------------------------------ creación
    @classmethod
    def solicitar(cls, correo: str, nombre: str, clave_hash: str, acepta_politica: bool = False,
                  ahora: datetime | None = None) -> Usuario:
        """Registro público: sin la autorización expresa del tratamiento de datos no se crea la cuenta (Ley 1581)."""
        if not acepta_politica or ahora is None:
            raise DatoInvalido("Para crear tu cuenta debes autorizar el tratamiento de tus datos personales.")
        return cls(correo=normalizar_correo(correo), nombre=normalizar_nombre(nombre), clave_hash=clave_hash,
                   consentimiento_version=VERSION_POLITICA, consentimiento_en=ahora)

    @classmethod
    def administrador_inicial(cls, correo: str, nombre: str, clave_hash: str, ahora: datetime) -> Usuario:
        return cls(correo=normalizar_correo(correo), nombre=normalizar_nombre(nombre), clave_hash=clave_hash,
                   rol=Rol.ADMINISTRADOR, estado=EstadoCuenta.ACTIVO, aprobado_en=ahora)

    # ------------------------------------------------------------------ consultas
    @property
    def es_admin(self) -> bool:
        return self.rol is Rol.ADMINISTRADOR

    @property
    def debe_configurar_2fa(self) -> bool:
        """El administrador está obligado a usar doble factor."""
        return self.es_admin and not self.totp_activo

    def esta_bloqueado(self, ahora: datetime) -> bool:
        return self.bloqueado_hasta is not None and self.bloqueado_hasta > ahora

    def verificar_puede_ingresar(self) -> None:
        if self.estado is EstadoCuenta.PENDIENTE:
            raise AccesoDenegado("Tu solicitud sigue en revisión. Un administrador debe aprobarla.")
        if self.estado is EstadoCuenta.RECHAZADO:
            raise AccesoDenegado("Tu solicitud de registro fue rechazada.")
        if self.estado is EstadoCuenta.DESACTIVADO:
            raise AccesoDenegado("Tu cuenta está desactivada. Contacta al administrador.")

    # ------------------------------------------------------------------ intentos de acceso
    def registrar_fallo(self, ahora: datetime, max_intentos: int, minutos_bloqueo: int) -> bool:
        """Suma un intento fallido. Devuelve True si la cuenta queda bloqueada con este intento."""
        self.intentos_fallidos += 1
        if self.intentos_fallidos >= max_intentos:
            self.bloqueado_hasta = ahora + timedelta(minutes=minutos_bloqueo)
            self.intentos_fallidos = 0
            return True
        return False

    def registrar_acceso(self, ahora: datetime) -> None:
        self.intentos_fallidos = 0
        self.bloqueado_hasta = None
        self.ultimo_acceso = ahora

    # ------------------------------------------------------------------ administración de cuentas
    def _exigir_admin(self, admin: Usuario) -> None:
        if not admin.es_admin or admin.estado is not EstadoCuenta.ACTIVO:
            raise AccesoDenegado("Solo un administrador activo puede hacer esto.")
        if admin.id == self.id:
            raise AccesoDenegado("No puedes cambiar el estado de tu propia cuenta.")

    def _cambiar_estado(self, admin: Usuario, desde: EstadoCuenta, hacia: EstadoCuenta) -> None:
        self._exigir_admin(admin)
        if self.estado is not desde:
            raise TransicionInvalida(f"La cuenta está «{self.estado.value}» y no puede pasar a «{hacia.value}».")
        self.estado = hacia

    def aprobar(self, admin: Usuario, ahora: datetime) -> None:
        self._cambiar_estado(admin, EstadoCuenta.PENDIENTE, EstadoCuenta.ACTIVO)
        self.aprobado_por, self.aprobado_en = admin.id, ahora

    def rechazar(self, admin: Usuario) -> None:
        self._cambiar_estado(admin, EstadoCuenta.PENDIENTE, EstadoCuenta.RECHAZADO)

    def desactivar(self, admin: Usuario) -> None:
        self._cambiar_estado(admin, EstadoCuenta.ACTIVO, EstadoCuenta.DESACTIVADO)

    def reactivar(self, admin: Usuario) -> None:
        self._cambiar_estado(admin, EstadoCuenta.DESACTIVADO, EstadoCuenta.ACTIVO)

    def asignar_clave_temporal(self, admin: Usuario, clave_hash: str) -> None:
        """El administrador restablece el acceso de alguien que olvidó su contraseña. La cuenta se desbloquea y la
        persona deberá cambiarla al entrar. No toca el doble factor: si lo tiene activo, lo seguirá necesitando."""
        self._exigir_admin(admin)
        if self.estado is not EstadoCuenta.ACTIVO:
            raise TransicionInvalida("Solo se puede restablecer la contraseña de una cuenta activa.")
        self.clave_hash = clave_hash
        self.debe_cambiar_clave = True
        self.intentos_fallidos, self.bloqueado_hasta = 0, None

    def cambiar_clave(self, clave_hash: str) -> None:
        self.clave_hash = clave_hash
        self.debe_cambiar_clave = False

    # ------------------------------------------------------------------ doble factor (TOTP)
    def preparar_2fa(self, secreto_cifrado: bytes) -> None:
        if self.totp_activo:
            raise Conflicto("El doble factor ya está activo en esta cuenta.")
        self.totp_secreto_cifrado = secreto_cifrado

    def activar_2fa(self, paso: int) -> None:
        if self.totp_secreto_cifrado is None:
            raise Conflicto("Primero inicia la configuración del doble factor.")
        self.totp_activo = True
        self.totp_ultimo_paso = paso

    def consumir_paso_totp(self, paso: int) -> None:
        """Un código TOTP solo sirve una vez: protege contra la reutilización de un código interceptado."""
        if self.totp_ultimo_paso is not None and paso <= self.totp_ultimo_paso:
            raise CredencialesInvalidas("Este código ya fue usado. Espera el siguiente.")
        self.totp_ultimo_paso = paso
