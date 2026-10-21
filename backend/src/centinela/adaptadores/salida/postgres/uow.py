"""Unidad de trabajo sobre SQLAlchemy: una sesión de BD = una transacción por caso de uso."""
from __future__ import annotations

from typing import Self

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from centinela.adaptadores.salida.postgres.repositorios import (
    RegistroAuditoriaSql,
    RepoBuzonesSql,
    RepoCodigosRecuperacionSql,
    RepoConfiguracionSql,
    RepoMensajesSql,
    RepoSesionesSql,
    RepoUsuariosSql,
)
from centinela.adaptadores.salida.postgres.repositorios_analisis import (
    RepoAnalisisSql,
    RepoAvisosSql,
    RepoCasosSql,
    RepoEntidadesSql,
    RepoEstadisticasSql,
    RepoModelosSql,
    RepoRetencionSql,
    RepoRetroalimentacionSql,
)
from centinela.adaptadores.salida.postgres.repositorios_comunicacion import (
    RepoConversacionesSql,
    RepoSuscripcionesPushSql,
)


def crear_motor(url: str) -> Engine:
    return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=10)


class UnidadDeTrabajoSql:
    def __init__(self, fabrica_sesiones: sessionmaker[Session]):
        self._fabrica = fabrica_sesiones

    def __enter__(self) -> Self:
        self._s = self._fabrica()
        self.usuarios = RepoUsuariosSql(self._s)
        self.sesiones = RepoSesionesSql(self._s)
        self.codigos_recuperacion = RepoCodigosRecuperacionSql(self._s)
        self.buzones = RepoBuzonesSql(self._s)
        self.mensajes = RepoMensajesSql(self._s)
        self.modelos = RepoModelosSql(self._s)
        self.entidades = RepoEntidadesSql(self._s)
        self.analisis = RepoAnalisisSql(self._s)
        self.casos = RepoCasosSql(self._s)
        self.avisos = RepoAvisosSql(self._s)
        self.retroalimentacion = RepoRetroalimentacionSql(self._s)
        self.configuracion = RepoConfiguracionSql(self._s)
        self.estadisticas = RepoEstadisticasSql(self._s)
        self.suscripciones_push = RepoSuscripcionesPushSql(self._s)
        self.conversaciones = RepoConversacionesSql(self._s)
        self.retencion = RepoRetencionSql(self._s)
        self.auditoria = RegistroAuditoriaSql(self._s)
        return self

    def __exit__(self, *exc: object) -> None:
        self.revertir()          # si ya se confirmó, no hace nada
        self._s.close()

    def confirmar(self) -> None:
        self._s.commit()

    def revertir(self) -> None:
        self._s.rollback()


class FabricaUnidadDeTrabajoSql:
    def __init__(self, motor: Engine):
        self._fabrica = sessionmaker(bind=motor, expire_on_commit=False)

    def __call__(self) -> UnidadDeTrabajoSql:
        return UnidadDeTrabajoSql(self._fabrica)
