"""Nivel de riesgo, razones y veredicto de un correo.

Promesa del producto: el usuario ve como máximo tres razones, claras y de áreas distintas,
ordenadas por cuánto pesaron en la decisión.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from centinela.dominio.errores import DatoInvalido

MAX_RAZONES_VISIBLES = 3


class NivelRiesgo(StrEnum):
    BAJO = "bajo"
    MEDIO = "medio"
    ALTO = "alto"

    @classmethod
    def desde_probabilidad(cls, p: float, umbral_medio: float, umbral_alto: float) -> NivelRiesgo:
        if not 0 < umbral_medio < umbral_alto < 1:
            raise DatoInvalido("Los umbrales deben cumplir 0 < medio < alto < 1.")
        if p >= umbral_alto:
            return cls.ALTO
        return cls.MEDIO if p >= umbral_medio else cls.BAJO


class Area(StrEnum):
    REMITENTE = "remitente"
    AUTENTICACION = "autenticacion"
    SUPLANTACION = "suplantacion"
    CONTENIDO = "contenido"
    ENLACE = "enlace"
    ADJUNTO = "adjunto"


class Gravedad(StrEnum):
    BAJA = "baja"
    MEDIA = "media"
    ALTA = "alta"

    @property
    def peso(self) -> int:
        return {"baja": 1, "media": 2, "alta": 3}[self.value]


@dataclass(frozen=True)
class Razon:
    area: Area
    gravedad: Gravedad
    texto: str
    aporte: float | None = None          # contribución al riesgo final (puede venir del modelo)
    entidad_id: int | None = None        # entidad colombiana suplantada, si aplica


def seleccionar_razones(razones: list[Razon], maximo: int = MAX_RAZONES_VISIBLES) -> list[Razon]:
    """Elige las razones que verá el usuario: las de mayor gravedad y aporte, una por área."""
    ordenadas = sorted(razones, key=lambda r: (r.gravedad.peso, r.aporte if r.aporte is not None else 0.0),
                       reverse=True)
    elegidas, areas = [], set()
    for r in ordenadas:
        if r.area in areas:
            continue
        elegidas.append(r)
        areas.add(r.area)
        if len(elegidas) == maximo:
            break
    return elegidas


def _validar_p(nombre: str, p: float | None) -> None:
    if p is not None and not 0.0 <= p <= 1.0:
        raise DatoInvalido(f"La probabilidad {nombre} debe estar entre 0 y 1.")


@dataclass
class Veredicto:
    p_final: float
    nivel: NivelRiesgo
    resumen: str
    razones: list[Razon] = field(default_factory=list)
    p_contenido: float | None = None
    p_enlaces: float | None = None
    p_tecnico: float | None = None
    tiempo_ms: int | None = None

    def __post_init__(self) -> None:
        for nombre in ("p_final", "p_contenido", "p_enlaces", "p_tecnico"):
            _validar_p(nombre, getattr(self, nombre))
        if self.nivel is not NivelRiesgo.BAJO and not self.razones:
            raise DatoInvalido("Un veredicto de riesgo medio o alto debe explicar al menos una razón.")

    @property
    def razones_visibles(self) -> list[Razon]:
        return seleccionar_razones(self.razones)

    @property
    def amerita_caso(self) -> bool:
        return self.nivel in (NivelRiesgo.MEDIO, NivelRiesgo.ALTO)
