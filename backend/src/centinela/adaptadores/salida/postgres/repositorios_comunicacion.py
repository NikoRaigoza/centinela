"""Repositorios de la comunicación con la persona: suscripciones push y conversaciones con el asistente."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from centinela.adaptadores.salida.postgres.tablas import (
    CasoFila,
    ConversacionFila,
    SuscripcionPushFila,
    TurnoChatFila,
)
from centinela.aplicacion.puertos import Conversacion, SuscripcionPush, TurnoChat


class RepoSuscripcionesPushSql:
    def __init__(self, s: Session):
        self._s = s

    def guardar(self, usuario_id: int, endpoint: str, p256dh: str, auth: str, dispositivo: str | None) -> None:
        valores = {"usuario_id": usuario_id, "p256dh": p256dh, "auth": auth, "dispositivo": dispositivo}
        self._s.execute(pg_insert(SuscripcionPushFila).values(endpoint=endpoint, **valores)
                        .on_conflict_do_update(constraint="suscripcion_endpoint_unico", set_=valores))

    def de_usuario(self, usuario_id: int) -> list[SuscripcionPush]:
        filas = self._s.scalars(select(SuscripcionPushFila).where(SuscripcionPushFila.usuario_id == usuario_id)
                                .order_by(SuscripcionPushFila.creado_en))
        return [SuscripcionPush(f.id, f.usuario_id, f.endpoint, f.p256dh, f.auth, f.dispositivo, f.creado_en,
                                f.ultimo_envio_en) for f in filas]

    def eliminar(self, usuario_id: int, suscripcion_id: int | None = None, endpoint: str | None = None) -> bool:
        q = delete(SuscripcionPushFila).where(SuscripcionPushFila.usuario_id == usuario_id)
        if suscripcion_id is not None:
            q = q.where(SuscripcionPushFila.id == suscripcion_id)
        if endpoint is not None:
            q = q.where(SuscripcionPushFila.endpoint == endpoint)
        return self._s.execute(q).rowcount > 0

    def eliminar_vencida(self, suscripcion_id: int) -> None:
        self._s.execute(delete(SuscripcionPushFila).where(SuscripcionPushFila.id == suscripcion_id))

    def marcar_envio(self, suscripcion_id: int, ahora: datetime) -> None:
        self._s.execute(update(SuscripcionPushFila).where(SuscripcionPushFila.id == suscripcion_id)
                        .values(ultimo_envio_en=ahora))


class RepoConversacionesSql:
    def __init__(self, s: Session):
        self._s = s

    def _consulta(self):
        return (select(ConversacionFila, CasoFila.id)
                .outerjoin(CasoFila, CasoFila.mensaje_id == ConversacionFila.mensaje_id))

    @staticmethod
    def _a_conversacion(f: ConversacionFila, caso_id: int | None) -> Conversacion:
        return Conversacion(f.id, f.usuario_id, f.titulo, f.mensaje_id, caso_id, f.creado_en, f.actualizado_en)

    def crear(self, usuario_id: int, mensaje_id: int | None, titulo: str) -> int:
        fila = ConversacionFila(usuario_id=usuario_id, mensaje_id=mensaje_id, titulo=titulo)
        self._s.add(fila)
        self._s.flush()
        return fila.id

    def por_id(self, conversacion_id: int) -> Conversacion | None:
        r = self._s.execute(self._consulta().where(ConversacionFila.id == conversacion_id)).first()
        return self._a_conversacion(*r) if r else None

    def de_usuario(self, usuario_id: int, limite: int) -> list[Conversacion]:
        filas = self._s.execute(self._consulta().where(ConversacionFila.usuario_id == usuario_id)
                                .order_by(ConversacionFila.actualizado_en.desc(), ConversacionFila.id.desc())
                                .limit(limite)).all()
        return [self._a_conversacion(f, c) for f, c in filas]

    def turnos(self, conversacion_id: int, ultimos: int | None = None) -> list[TurnoChat]:
        q = (select(TurnoChatFila).where(TurnoChatFila.conversacion_id == conversacion_id)
             .order_by(TurnoChatFila.creado_en.desc(), TurnoChatFila.id.desc()))
        if ultimos is not None:
            q = q.limit(ultimos)
        filas = list(self._s.scalars(q))[::-1]
        return [TurnoChat(f.rol, f.contenido, f.proveedor, f.creado_en) for f in filas]

    def agregar_turno(self, conversacion_id: int, rol: str, contenido: str, proveedor: str | None) -> None:
        self._s.add(TurnoChatFila(conversacion_id=conversacion_id, rol=rol, contenido=contenido, proveedor=proveedor))
        # El trigger de la tabla actualiza `actualizado_en`: la conversación sube al inicio de la lista
        self._s.execute(update(ConversacionFila).where(ConversacionFila.id == conversacion_id)
                        .values(titulo=ConversacionFila.titulo))
        self._s.flush()

    def eliminar(self, conversacion_id: int) -> None:
        self._s.execute(delete(ConversacionFila).where(ConversacionFila.id == conversacion_id))

    def _contar(self, usuario_id: int, desde: datetime, *condiciones) -> int:
        return self._s.scalar(
            select(func.count()).select_from(TurnoChatFila)
            .join(ConversacionFila, ConversacionFila.id == TurnoChatFila.conversacion_id)
            .where(ConversacionFila.usuario_id == usuario_id, TurnoChatFila.creado_en >= desde, *condiciones)) or 0

    def respuestas_ia_desde(self, usuario_id: int, desde: datetime) -> int:
        return self._contar(usuario_id, desde, TurnoChatFila.proveedor.is_not(None), TurnoChatFila.proveedor != "local")

    def preguntas_desde(self, usuario_id: int, desde: datetime) -> int:
        return self._contar(usuario_id, desde, TurnoChatFila.rol == "usuario")
