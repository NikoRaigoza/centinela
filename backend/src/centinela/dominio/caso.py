"""Caso: el seguimiento de un correo de riesgo medio o alto, con su máquina de estados e historial."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from centinela.dominio.errores import DatoInvalido, TransicionInvalida


class EstadoCaso(StrEnum):
    NUEVO = "nuevo"
    EN_CUARENTENA = "en_cuarentena"
    LIBERADO = "liberado"
    CONFIRMADO = "confirmado"
    FALSO_POSITIVO = "falso_positivo"


class TipoEvento(StrEnum):
    CREADO = "creado"
    CUARENTENA = "cuarentena"
    AVISO = "aviso"
    LIBERADO = "liberado"
    CONFIRMADO = "confirmado"
    FALSO_POSITIVO = "falso_positivo"
    REABIERTO = "reabierto"
    NOTA = "nota"


ABIERTOS = frozenset({EstadoCaso.NUEVO, EstadoCaso.EN_CUARENTENA})

# Transiciones permitidas. Un caso cerrado solo puede reabrirse (vuelve a NUEVO).
TRANSICIONES: dict[EstadoCaso, frozenset[EstadoCaso]] = {
    EstadoCaso.NUEVO: frozenset({EstadoCaso.EN_CUARENTENA, EstadoCaso.CONFIRMADO, EstadoCaso.FALSO_POSITIVO}),
    EstadoCaso.EN_CUARENTENA: frozenset({EstadoCaso.LIBERADO, EstadoCaso.CONFIRMADO}),
    EstadoCaso.LIBERADO: frozenset({EstadoCaso.NUEVO}),
    EstadoCaso.CONFIRMADO: frozenset({EstadoCaso.NUEVO}),
    EstadoCaso.FALSO_POSITIVO: frozenset({EstadoCaso.NUEVO}),
}

_EVENTO_DE = {
    EstadoCaso.EN_CUARENTENA: TipoEvento.CUARENTENA,
    EstadoCaso.LIBERADO: TipoEvento.LIBERADO,
    EstadoCaso.CONFIRMADO: TipoEvento.CONFIRMADO,
    EstadoCaso.FALSO_POSITIVO: TipoEvento.FALSO_POSITIVO,
    EstadoCaso.NUEVO: TipoEvento.REABIERTO,
}


@dataclass(frozen=True)
class EventoCaso:
    tipo: TipoEvento
    creado_en: datetime
    autor_id: int | None = None           # None = lo hizo el sistema
    estado_anterior: EstadoCaso | None = None
    estado_nuevo: EstadoCaso | None = None
    detalle: str | None = None


@dataclass
class Caso:
    mensaje_id: int
    creado_en: datetime
    estado: EstadoCaso = EstadoCaso.NUEVO
    cerrado_en: datetime | None = None
    id: int | None = None
    eventos_nuevos: list[EventoCaso] = field(default_factory=list)   # eventos aún no guardados

    @classmethod
    def abrir(cls, mensaje_id: int, ahora: datetime) -> Caso:
        caso = cls(mensaje_id=mensaje_id, creado_en=ahora)
        caso.eventos_nuevos.append(EventoCaso(TipoEvento.CREADO, ahora, estado_nuevo=EstadoCaso.NUEVO))
        return caso

    @property
    def abierto(self) -> bool:
        return self.estado in ABIERTOS

    @property
    def puede_liberarse(self) -> bool:
        return self.estado is EstadoCaso.EN_CUARENTENA

    def transicionar(self, nuevo: EstadoCaso, ahora: datetime, autor_id: int | None = None,
                     detalle: str | None = None) -> None:
        if nuevo not in TRANSICIONES[self.estado]:
            raise TransicionInvalida(f"Un caso «{self.estado.value}» no puede pasar a «{nuevo.value}».")
        anterior, self.estado = self.estado, nuevo
        self.cerrado_en = None if nuevo in ABIERTOS else ahora
        self.eventos_nuevos.append(EventoCaso(_EVENTO_DE[nuevo], ahora, autor_id, anterior, nuevo, detalle))

    def agregar_nota(self, texto: str, autor_id: int, ahora: datetime) -> None:
        texto = (texto or "").strip()
        if not texto:
            raise DatoInvalido("La nota no puede estar vacía.")
        self.eventos_nuevos.append(EventoCaso(TipoEvento.NOTA, ahora, autor_id, detalle=texto[:2000]))
