"""Dependencias de FastAPI: contenedor, contexto de la petición y usuario autenticado."""
from __future__ import annotations

import ipaddress
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from centinela.adaptadores.entrada.api import tokens as t
from centinela.aplicacion.casos_uso.acceso import Contexto
from centinela.contenedor import Contenedor
from centinela.dominio.errores import AccesoDenegado, CredencialesInvalidas

_bearer = HTTPBearer(auto_error=False)


def contenedor(request: Request) -> Contenedor:
    return request.app.state.contenedor


def _ip_valida(valor: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address(valor)) if valor else None
    except ValueError:
        return None


def contexto(request: Request) -> Contexto:
    ip = _ip_valida(request.client.host if request.client else None)
    return Contexto(ip=ip, agente=request.headers.get("user-agent"))


def _reclamos(cred: HTTPAuthorizationCredentials | None, c: Contenedor, tipos: set[str]) -> t.Reclamos:
    if cred is None or cred.scheme.lower() != "bearer":
        raise CredencialesInvalidas("Debes iniciar sesión.")
    return c.tokens.leer(cred.credentials, tipos)


Cont = Annotated[Contenedor, Depends(contenedor)]
Ctx = Annotated[Contexto, Depends(contexto)]
Credenciales = Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]


def usuario_actual(cred: Credenciales, c: Cont) -> t.Reclamos:
    return _reclamos(cred, c, {t.ACCESO})


def desafio_verificar(cred: Credenciales, c: Cont) -> t.Reclamos:
    return _reclamos(cred, c, {t.VERIFICAR_2FA})


def desafio_o_acceso_configurar(cred: Credenciales, c: Cont) -> t.Reclamos:
    """Configurar 2FA: durante el inicio de sesión (admin obligado) o desde Ajustes ya autenticado."""
    return _reclamos(cred, c, {t.CONFIGURAR_2FA, t.ACCESO})


def administrador(r: Annotated[t.Reclamos, Depends(usuario_actual)]) -> t.Reclamos:
    if r.rol != "administrador":
        raise AccesoDenegado("Esta acción es solo para administradores.")
    return r


Actual = Annotated[t.Reclamos, Depends(usuario_actual)]
Admin = Annotated[t.Reclamos, Depends(administrador)]
