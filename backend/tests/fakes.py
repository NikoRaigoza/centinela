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
    buzones: dict[int, Any] = field(default_factory=dict)
    mensajes: dict[tuple[int, str], Any] = field(default_factory=dict)
    revision_solicitada: set[int] = field(default_factory=set)


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
        self.buzones = _RepoBuzones(a)
        self.mensajes = _RepoMensajes(a)
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


# ---------------------------------------------------------------------- buzones y mensajes en memoria
class _RepoBuzones:
    def __init__(self, a: Almacen):
        self.a = a

    def por_id(self, i):
        b = self.a.buzones.get(i)
        return copy.deepcopy(b) if b else None

    def por_correo(self, c):
        return next((copy.deepcopy(b) for b in self.a.buzones.values() if b.correo_gmail == c), None)

    def de_usuario(self, usuario_id):
        return [copy.deepcopy(b) for b in self.a.buzones.values() if b.usuario_id == usuario_id]

    def todos(self):
        return [copy.deepcopy(b) for b in self.a.buzones.values()]

    def agregar(self, b):
        b.id = len(self.a.buzones) + 1
        self.a.buzones[b.id] = copy.deepcopy(b)
        return b

    def guardar(self, b):
        self.a.buzones[b.id] = copy.deepcopy(b)

    def reclamar_pendientes(self, antes_de, ahora, limite, respaldo_antes_de=None, reintento_antes_de=None):
        def toca(b):
            if b.estado.value == "error":
                return b.refresh_token_cifrado is not None and (
                    b.id in self.a.revision_solicitada or b.ultima_revision_en is None
                    or b.ultima_revision_en < (reintento_antes_de or antes_de))
            if b.id in self.a.revision_solicitada or b.ultima_revision_en is None:
                return True
            vigilado = b.vigilancia_expira_en is not None and b.vigilancia_expira_en > ahora
            return b.ultima_revision_en < ((respaldo_antes_de or antes_de) if vigilado else antes_de)

        ids = [b.id for b in self.a.buzones.values() if b.estado.value in ("activo", "error") and toca(b)][:limite]
        for i in ids:
            self.a.buzones[i].ultima_revision_en = ahora
            self.a.revision_solicitada.discard(i)
        return ids

    def solicitar_revision(self, buzon_id, ahora):
        self.a.revision_solicitada.add(buzon_id)

    def por_vigilar(self, renovar_antes_de, limite):
        return [copy.deepcopy(b) for b in self.a.buzones.values() if b.revisable
                and (b.vigilancia_expira_en is None or b.vigilancia_expira_en < renovar_antes_de)][:limite]


class _RepoMensajes:
    def __init__(self, a: Almacen):
        self.a = a

    def existe(self, buzon_id, gmail_id):
        return (buzon_id, gmail_id) in self.a.mensajes

    def agregar(self, m, idioma="es"):
        if (m.buzon_id, m.gmail_id) in self.a.mensajes:
            return None
        m.id = len(self.a.mensajes) + 1
        self.a.mensajes[(m.buzon_id, m.gmail_id)] = copy.deepcopy(m)
        return m.id

    def recientes(self, buzon_id, limite):
        return [m for (b, _), m in self.a.mensajes.items() if b == buzon_id][:limite]

    def remitente_conocido(self, buzon_id, remitente_correo):
        return any(b == buzon_id and m.correo and m.correo.remitente_correo == remitente_correo.lower()
                   for (b, _), m in self.a.mensajes.items())

