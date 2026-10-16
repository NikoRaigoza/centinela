"""Adaptadores en memoria para probar los casos de uso sin base de datos (la ventaja de los puertos)."""
from __future__ import annotations

import copy
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from centinela.aplicacion.puertos import EventoAuditoria
from centinela.dominio.sesion import Sesion
from centinela.dominio.usuario import EstadoCuenta, Usuario


class RelojFijo:
    def __init__(self, inicio: datetime | None = None):
        self.t = inicio or datetime(2026, 10, 16, 12, 0, tzinfo=UTC)

    def ahora(self) -> datetime:
        return self.t

    def avanzar(self, **kw) -> None:
        self.t += timedelta(**kw)


class HasherFalso:
    def hashear(self, clave: str) -> str:
        return "h:" + clave

    def verificar(self, clave: str, hash_guardado: str) -> bool:
        return hash_guardado == "h:" + clave

    def necesita_rehash(self, hash_guardado: str) -> bool:
        return False


class CifradorFalso:
    def cifrar(self, texto: str) -> bytes:
        return texto.encode()[::-1]

    def descifrar(self, datos: bytes) -> str:
        return bytes(datos)[::-1].decode()


@dataclass
class Almacen:
    usuarios: dict[int, Usuario] = field(default_factory=dict)
    sesiones: dict[uuid.UUID, Sesion] = field(default_factory=dict)
    codigos: dict[int, dict[str, datetime | None]] = field(default_factory=dict)
    configuracion: dict[str, Any] = field(default_factory=dict)
    auditoria: list[EventoAuditoria] = field(default_factory=list)


class _RepoUsuarios:
    def __init__(self, a: Almacen):
        self.a = a

    def por_id(self, i):
        u = self.a.usuarios.get(i)
        return copy.deepcopy(u) if u else None

    def por_correo(self, c):
        return next((copy.deepcopy(u) for u in self.a.usuarios.values() if u.correo == c), None)

    def agregar(self, u):
        u.id = len(self.a.usuarios) + 1
        self.a.usuarios[u.id] = copy.deepcopy(u)
        return u

    def guardar(self, u):
        self.a.usuarios[u.id] = copy.deepcopy(u)

    def listar(self, estado: EstadoCuenta | None = None):
        return [copy.deepcopy(u) for u in self.a.usuarios.values() if estado is None or u.estado is estado]


class _RepoSesiones:
    def __init__(self, a: Almacen):
        self.a = a

    def agregar(self, s):
        s.id = uuid.uuid4()
        self.a.sesiones[s.id] = copy.deepcopy(s)
        return s

    def por_hash(self, h):
        return next((copy.deepcopy(s) for s in self.a.sesiones.values() if s.token_hash == h), None)

    def guardar(self, s):
        self.a.sesiones[s.id] = copy.deepcopy(s)

    def revocar_de_usuario(self, usuario_id, ahora):
        n = 0
        for s in self.a.sesiones.values():
            if s.usuario_id == usuario_id and s.revocada_en is None:
                s.revocada_en, n = ahora, n + 1
        return n


class _RepoCodigos:
    def __init__(self, a: Almacen):
        self.a = a

    def reemplazar(self, usuario_id, hashes):
        self.a.codigos[usuario_id] = dict.fromkeys(hashes)

    def consumir(self, usuario_id, h, ahora):
        codigos = self.a.codigos.get(usuario_id, {})
        if h in codigos and codigos[h] is None:
            codigos[h] = ahora
            return True
        return False


class _RepoConfiguracion:
    def __init__(self, a: Almacen):
        self.a = a

    def obtener(self, clave, defecto):
        return self.a.configuracion.get(clave, defecto)


class _Auditoria:
    def __init__(self, a: Almacen):
        self.a = a

    def registrar(self, e):
        self.a.auditoria.append(e)


class UnidadDeTrabajoFalsa:
    def __init__(self, a: Almacen):
        self.usuarios = _RepoUsuarios(a)
        self.sesiones = _RepoSesiones(a)
        self.codigos_recuperacion = _RepoCodigos(a)
        self.configuracion = _RepoConfiguracion(a)
        self.auditoria = _Auditoria(a)
        self.confirmaciones = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def confirmar(self):
        self.confirmaciones += 1

    def revertir(self):
        pass


class FabricaFalsa:
    def __init__(self):
        self.almacen = Almacen()

    def __call__(self):
        return UnidadDeTrabajoFalsa(self.almacen)
