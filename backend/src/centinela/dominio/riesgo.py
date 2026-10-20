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
    FRAUDE = "fraude"            # pide dinero o datos sin enlaces: suplantación de jefe o proveedor, extorsión


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
        """Lo que ve el usuario: hasta 3 razones. Un correo de riesgo BAJO no muestra razones (no alarma sin motivo)."""
        return [] if self.nivel is NivelRiesgo.BAJO else seleccionar_razones(self.razones)

    @property
    def amerita_caso(self) -> bool:
        return self.nivel in (NivelRiesgo.MEDIO, NivelRiesgo.ALTO)


# ---------------------------------------------------------------------- combinación del riesgo
UMBRAL_MEDIO = 0.30
UMBRAL_ALTO = 0.70
PESO_GRAVEDAD = {Gravedad.ALTA: 0.45, Gravedad.MEDIA: 0.20, Gravedad.BAJA: 0.07}
PESO_ENLACES = 0.6        # los enlaces apoyan pero no mandan: solos llegan a riesgo MEDIO, no a ALTO
BONO_CONCORDANCIA = 0.05  # cada componente adicional que también ve riesgo suma un poco
TOPE = 0.99
FACTOR_REMITENTE_VERIFICADO = 0.5   # remitente oficial de una entidad del catálogo, verificado por DMARC


def a_escala_comun(p: float, umbral_medio_modelo: float, umbral_alto_modelo: float) -> float:
    """Lleva la probabilidad de un modelo a la escala común del sistema, por tramos lineales:
    su umbral MEDIO (≤5 % de falsos positivos en validación) cae en 0,30 y su umbral ALTO (≤1 %) en 0,70.
    Así cada versión del modelo trae sus propios puntos de operación y el resto del sistema no cambia."""
    um, ua = umbral_medio_modelo, umbral_alto_modelo
    if not 0 < um < ua < 1:
        raise DatoInvalido("Los umbrales del modelo deben cumplir 0 < medio < alto < 1.")
    if p < um:
        return UMBRAL_MEDIO * p / um
    if p < ua:
        return UMBRAL_MEDIO + (UMBRAL_ALTO - UMBRAL_MEDIO) * (p - um) / (ua - um)
    return min(TOPE, UMBRAL_ALTO + (TOPE - UMBRAL_ALTO) * (p - ua) / (1 - ua))


@dataclass(frozen=True)
class RiesgoCombinado:
    p_final: float
    p_tecnico: float | None


def combinar_riesgo(p_contenido: float | None, p_enlaces: float | None, razones_tecnicas: list[Razon],
                    remitente_verificado: bool = False) -> RiesgoCombinado:
    """Combina tres fuentes independientes. Regla documentada en la tesis (criterio experto, no aprendida):

    * técnico = 1 - ∏(1 - peso de cada señal) → varias señales medias suman, sin pasar de 1. El peso es el que fija
      su gravedad (0.45 / 0.20 / 0.07), salvo que la regla traiga uno propio (el detector de fraude sin enlaces).
    * final = máximo de (contenido, 0.6·enlaces, técnico) + 0.05 por cada fuente extra que supera 0.5.
    Las razones de CONTENIDO no entran al técnico: el riesgo del texto lo estima el modelo.
    * Si el remitente es un dominio oficial de una entidad del catálogo verificado por DMARC y no hay ninguna
      señal técnica en contra, el riesgo se multiplica por 0.5: el texto solo no basta para acusar a la DIAN
      real de phishing. Un texto muy sospechoso (≥ 0.6) sigue quedando al menos en riesgo MEDIO.
    """
    tecnicas = [r for r in razones_tecnicas if r.area is not Area.CONTENIDO]
    p_tec = None
    if tecnicas:
        producto = 1.0
        for r in tecnicas:
            producto *= 1.0 - (r.aporte if r.aporte is not None else PESO_GRAVEDAD[r.gravedad])
        p_tec = 1.0 - producto
    componentes = [p for p in (p_contenido, PESO_ENLACES * p_enlaces if p_enlaces is not None else None, p_tec)
                   if p is not None]
    if not componentes:
        return RiesgoCombinado(0.0, None)
    concordancia = sum(1 for p in componentes if p >= 0.5)
    final = min(TOPE, max(componentes) + BONO_CONCORDANCIA * max(0, concordancia - 1))
    if remitente_verificado and p_tec is None:
        final *= FACTOR_REMITENTE_VERIFICADO
    return RiesgoCombinado(round(final, 4), round(p_tec, 4) if p_tec is not None else None)


def redactar_resumen(nivel: NivelRiesgo, razones_visibles: list[Razon], nombre_entidad: str | None = None) -> str:
    if nivel is NivelRiesgo.ALTO:
        base = "Este correo tiene señales claras de phishing"
        return base + (f": suplanta a {nombre_entidad}." if nombre_entidad else ".")
    if nivel is NivelRiesgo.MEDIO:
        return "Este correo tiene algunas señales de riesgo. Revísalo con cuidado antes de abrir enlaces o adjuntos."
    return "No encontramos señales de riesgo importantes."
