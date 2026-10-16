"""Tokens JWT del panel. Son un detalle del adaptador HTTP, no de la aplicación.

  * acceso:          15 min, viaja en el encabezado Authorization (vive en memoria del navegador).
  * verificar_2fa /
    configurar_2fa:  5 min, prueba que la contraseña ya fue correcta y solo sirve para el paso de doble factor.
El token de renovación NO es JWT: es aleatorio, va en cookie httpOnly y su hash está en la tabla `sesion`.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

import jwt

from centinela.aplicacion.puertos import Reloj
from centinela.dominio.errores import CredencialesInvalidas
from centinela.dominio.usuario import Usuario

ALGORITMO = "HS256"
EMISOR = "centinela"
ACCESO = "acceso"
VERIFICAR_2FA = "verificar_2fa"
CONFIGURAR_2FA = "configurar_2fa"


@dataclass(frozen=True)
class Reclamos:
    usuario_id: int
    tipo: str
    rol: str | None


class EmisorTokens:
    def __init__(self, secreto: str, minutos_acceso: int, minutos_desafio: int, reloj: Reloj):
        self._secreto = secreto
        self._acceso = timedelta(minutes=minutos_acceso)
        self._desafio = timedelta(minutes=minutos_desafio)
        self._reloj = reloj

    def _emitir(self, usuario_id: int, tipo: str, duracion: timedelta, **extra) -> str:
        ahora = self._reloj.ahora()
        return jwt.encode({"iss": EMISOR, "sub": str(usuario_id), "tipo": tipo, "iat": ahora,
                           "exp": ahora + duracion, **extra}, self._secreto, algorithm=ALGORITMO)

    def acceso(self, usuario: Usuario) -> str:
        return self._emitir(usuario.id, ACCESO, self._acceso, rol=usuario.rol.value)

    def desafio(self, usuario: Usuario, tipo: str) -> str:
        return self._emitir(usuario.id, tipo, self._desafio)

    @property
    def segundos_acceso(self) -> int:
        return int(self._acceso.total_seconds())

    def leer(self, token: str, tipos: set[str]) -> Reclamos:
        try:
            datos = jwt.decode(token, self._secreto, algorithms=[ALGORITMO], issuer=EMISOR,
                               options={"require": ["exp", "sub", "iss"]})
        except jwt.ExpiredSignatureError:
            raise CredencialesInvalidas("Tu sesión expiró. Inicia sesión de nuevo.") from None
        except jwt.InvalidTokenError:
            raise CredencialesInvalidas("Credenciales no válidas.") from None
        if datos.get("tipo") not in tipos:
            raise CredencialesInvalidas("Credenciales no válidas para esta operación.")
        return Reclamos(usuario_id=int(datos["sub"]), tipo=datos["tipo"], rol=datos.get("rol"))
