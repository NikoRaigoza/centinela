"""Repositorios PostgreSQL: traducen entre las filas (SQLAlchemy) y las entidades del dominio."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from centinela.adaptadores.salida.postgres.tablas import (
    AdjuntoAnalizadoFila,
    AuditoriaFila,
    BuzonFila,
    CodigoRecuperacionFila,
    ConfiguracionFila,
    MensajeAnalizadoFila,
    SesionFila,
    UsuarioFila,
)
from centinela.aplicacion.puertos import EventoAuditoria
from centinela.dominio.buzon import Buzon, EstadoBuzon, ModoCuarentena
from centinela.dominio.correo import Mensaje, ResultadoAuth, ResumenMensaje
from centinela.dominio.sesion import Sesion
from centinela.dominio.usuario import EstadoCuenta, Rol, Usuario

_CAMPOS_USUARIO = ("correo", "nombre", "clave_hash", "totp_secreto_cifrado", "totp_activo", "totp_ultimo_paso",
                   "intentos_fallidos", "bloqueado_hasta", "aprobado_por", "aprobado_en", "ultimo_acceso")


def _a_usuario(f: UsuarioFila) -> Usuario:
    return Usuario(id=f.id, rol=Rol(f.rol), estado=EstadoCuenta(f.estado), creado_en=f.creado_en,
                   **{c: getattr(f, c) for c in _CAMPOS_USUARIO})


def _volcar_usuario(u: Usuario, f: UsuarioFila) -> None:
    for c in _CAMPOS_USUARIO:
        setattr(f, c, getattr(u, c))
    f.rol, f.estado = u.rol.value, u.estado.value


class RepoUsuariosSql:
    def __init__(self, s: Session):
        self._s = s

    def por_id(self, usuario_id: int) -> Usuario | None:
        f = self._s.get(UsuarioFila, usuario_id)
        return _a_usuario(f) if f else None

    def por_correo(self, correo: str) -> Usuario | None:
        f = self._s.scalar(select(UsuarioFila).where(UsuarioFila.correo == correo))
        return _a_usuario(f) if f else None

    def agregar(self, usuario: Usuario) -> Usuario:
        f = UsuarioFila()
        _volcar_usuario(usuario, f)
        self._s.add(f)
        self._s.flush()
        usuario.id, usuario.creado_en = f.id, f.creado_en
        return usuario

    def guardar(self, usuario: Usuario) -> None:
        f = self._s.get(UsuarioFila, usuario.id)
        _volcar_usuario(usuario, f)
        self._s.flush()

    def listar(self, estado: EstadoCuenta | None = None) -> list[Usuario]:
        q = select(UsuarioFila).order_by(UsuarioFila.creado_en.desc())
        if estado is not None:
            q = q.where(UsuarioFila.estado == estado.value)
        return [_a_usuario(f) for f in self._s.scalars(q)]


def _a_sesion(f: SesionFila) -> Sesion:
    return Sesion(id=f.id, usuario_id=f.usuario_id, token_hash=bytes(f.token_hash), creada_en=f.creada_en,
                  expira_en=f.expira_en, ip=str(f.ip) if f.ip else None, agente=f.agente, revocada_en=f.revocada_en)


class RepoSesionesSql:
    def __init__(self, s: Session):
        self._s = s

    def agregar(self, sesion: Sesion) -> Sesion:
        f = SesionFila(usuario_id=sesion.usuario_id, token_hash=sesion.token_hash, ip=sesion.ip, agente=sesion.agente,
                       creada_en=sesion.creada_en, expira_en=sesion.expira_en)
        self._s.add(f)
        self._s.flush()
        sesion.id = f.id
        return sesion

    def por_hash(self, token_hash: bytes) -> Sesion | None:
        f = self._s.scalar(select(SesionFila).where(SesionFila.token_hash == token_hash))
        return _a_sesion(f) if f else None

    def guardar(self, sesion: Sesion) -> None:
        f = self._s.get(SesionFila, sesion.id)
        f.revocada_en = sesion.revocada_en
        self._s.flush()

    def revocar_de_usuario(self, usuario_id: int, ahora: datetime) -> int:
        r = self._s.execute(update(SesionFila)
                            .where(SesionFila.usuario_id == usuario_id, SesionFila.revocada_en.is_(None))
                            .values(revocada_en=ahora))
        return r.rowcount


class RepoCodigosRecuperacionSql:
    def __init__(self, s: Session):
        self._s = s

    def reemplazar(self, usuario_id: int, hashes: list[str]) -> None:
        self._s.query(CodigoRecuperacionFila).filter_by(usuario_id=usuario_id).delete()
        self._s.add_all(CodigoRecuperacionFila(usuario_id=usuario_id, codigo_hash=h) for h in hashes)
        self._s.flush()

    def consumir(self, usuario_id: int, codigo_hash: str, ahora: datetime) -> bool:
        r = self._s.execute(update(CodigoRecuperacionFila)
                            .where(CodigoRecuperacionFila.usuario_id == usuario_id,
                                   CodigoRecuperacionFila.codigo_hash == codigo_hash,
                                   CodigoRecuperacionFila.usado_en.is_(None))
                            .values(usado_en=ahora))
        return r.rowcount == 1


class RepoConfiguracionSql:
    def __init__(self, s: Session):
        self._s = s

    def obtener(self, clave: str, defecto: Any) -> Any:
        valor = self._s.scalar(select(ConfiguracionFila.valor).where(ConfiguracionFila.clave == clave))
        return defecto if valor is None else valor


class RegistroAuditoriaSql:
    def __init__(self, s: Session):
        self._s = s

    def registrar(self, evento: EventoAuditoria) -> None:
        self._s.add(AuditoriaFila(usuario_id=evento.usuario_id, accion=evento.accion, objeto_tipo=evento.objeto_tipo,
                                  objeto_id=evento.objeto_id, exito=evento.exito, ip=evento.ip,
                                  detalle=evento.detalle or {}))
        self._s.flush()


# ---------------------------------------------------------------------- buzones y mensajes
_CAMPOS_BUZON = ("usuario_id", "correo_gmail", "refresh_token_cifrado", "avisar_por_correo", "etiqueta_cuarentena_id",
                 "etiqueta_sospechoso_id", "ultima_revision_en", "errores_consecutivos", "ultimo_error", "conectado_en",
                 "desconectado_en")


def _a_buzon(f: BuzonFila) -> Buzon:
    return Buzon(id=f.id, alcances=list(f.alcances or []), estado=EstadoBuzon(f.estado), modo=ModoCuarentena(f.modo),
                 ultimo_history_id=int(f.ultimo_history_id) if f.ultimo_history_id is not None else None,
                 **{c: getattr(f, c) for c in _CAMPOS_BUZON})


def _volcar_buzon(b: Buzon, f: BuzonFila) -> None:
    for c in _CAMPOS_BUZON:
        setattr(f, c, getattr(b, c))
    f.alcances, f.estado, f.modo = list(b.alcances), b.estado.value, b.modo.value
    f.ultimo_history_id = b.ultimo_history_id


class RepoBuzonesSql:
    def __init__(self, s: Session):
        self._s = s

    def por_id(self, buzon_id: int) -> Buzon | None:
        f = self._s.get(BuzonFila, buzon_id)
        return _a_buzon(f) if f else None

    def por_correo(self, correo_gmail: str) -> Buzon | None:
        f = self._s.scalar(select(BuzonFila).where(BuzonFila.correo_gmail == correo_gmail))
        return _a_buzon(f) if f else None

    def de_usuario(self, usuario_id: int) -> list[Buzon]:
        q = select(BuzonFila).where(BuzonFila.usuario_id == usuario_id).order_by(BuzonFila.conectado_en.desc())
        return [_a_buzon(f) for f in self._s.scalars(q)]

    def todos(self) -> list[Buzon]:
        return [_a_buzon(f) for f in self._s.scalars(select(BuzonFila).order_by(BuzonFila.id))]

    def agregar(self, buzon: Buzon) -> Buzon:
        f = BuzonFila()
        _volcar_buzon(buzon, f)
        self._s.add(f)
        self._s.flush()
        buzon.id = f.id
        return buzon

    def guardar(self, buzon: Buzon) -> None:
        f = self._s.get(BuzonFila, buzon.id)
        _volcar_buzon(buzon, f)
        self._s.flush()

    def reclamar_pendientes(self, revisados_antes_de: datetime, ahora: datetime, limite: int) -> list[int]:
        pendientes = (select(BuzonFila.id)
                      .where(BuzonFila.estado == EstadoBuzon.ACTIVO.value,
                             or_(BuzonFila.ultima_revision_en.is_(None), BuzonFila.ultima_revision_en < revisados_antes_de))
                      .order_by(BuzonFila.ultima_revision_en.asc().nulls_first())
                      .limit(limite)
                      .with_for_update(skip_locked=True))
        r = self._s.execute(update(BuzonFila).where(BuzonFila.id.in_(pendientes.scalar_subquery()))
                            .values(ultima_revision_en=ahora).returning(BuzonFila.id))
        return [fila[0] for fila in r]


class RepoMensajesSql:
    def __init__(self, s: Session):
        self._s = s

    def existe(self, buzon_id: int, gmail_id: str) -> bool:
        return self._s.scalar(select(MensajeAnalizadoFila.id).where(
            MensajeAnalizadoFila.buzon_id == buzon_id, MensajeAnalizadoFila.gmail_id == gmail_id)) is not None

    def agregar(self, mensaje: Mensaje, idioma: str = "es") -> int | None:
        c = mensaje.correo
        auth = c.autenticacion if c and c.autenticacion.confiable else None    # solo lo que certificó Google
        valores = {
            "buzon_id": mensaje.buzon_id, "gmail_id": mensaje.gmail_id, "gmail_hilo_id": mensaje.gmail_hilo_id,
            "recibido_en": mensaje.recibido_en, "tamano_bytes": mensaje.tamano_bytes,
            "message_id_rfc": c.message_id if c else None,
            "remitente_correo": c.remitente_correo or None if c else None,
            "remitente_nombre": c.remitente_nombre or None if c else None,
            "remitente_dominio": c.remitente_dominio or None if c else None,
            "responder_a_dominio": c.responder_a_dominio if c else None,
            "asunto": c.asunto if c else None,
            "idioma": idioma if idioma in ("es", "en") else "otro",
            "n_enlaces": min(len(c.enlaces), 32767) if c else 0,
            "n_adjuntos": min(len(c.adjuntos), 32767) if c else 0,
            "spf": auth.spf.value if auth and auth.spf else None,
            "dkim": auth.dkim.value if auth and auth.dkim else None,
            "dmarc": auth.dmarc.value if auth and auth.dmarc else None,
        }
        nuevo_id = self._s.scalar(pg_insert(MensajeAnalizadoFila).values(**valores)
                                  .on_conflict_do_nothing(constraint="mensaje_unico_por_buzon")
                                  .returning(MensajeAnalizadoFila.id))
        if nuevo_id is None:
            return None
        if c:
            self._s.add_all(AdjuntoAnalizadoFila(mensaje_id=nuevo_id, nombre=a.nombre, extension=a.extension,
                                                 tipo_mime=a.tipo_mime, tamano_bytes=a.tamano_bytes, sha256=a.sha256)
                            for a in c.adjuntos)
        self._s.flush()
        mensaje.id = nuevo_id
        return nuevo_id

    def recientes(self, buzon_id: int, limite: int) -> list[ResumenMensaje]:
        q = (select(MensajeAnalizadoFila).where(MensajeAnalizadoFila.buzon_id == buzon_id)
             .order_by(MensajeAnalizadoFila.recibido_en.desc()).limit(limite))
        return [ResumenMensaje(id=f.id, gmail_id=f.gmail_id, recibido_en=f.recibido_en, remitente_nombre=f.remitente_nombre,
                               remitente_correo=f.remitente_correo, asunto=f.asunto, n_enlaces=f.n_enlaces,
                               n_adjuntos=f.n_adjuntos, spf=ResultadoAuth.interpretar(f.spf),
                               dkim=ResultadoAuth.interpretar(f.dkim), dmarc=ResultadoAuth.interpretar(f.dmarc))
                for f in self._s.scalars(q)]
