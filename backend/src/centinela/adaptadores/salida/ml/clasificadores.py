"""Clasificadores concretos detrás de los puertos ClasificadorContenido y ClasificadorEnlaces.

* ClasificadorEnlacesXgb: XGBoost sobre 57 características léxicas de la URL (no visita el sitio).
* ClasificadorContenidoLineal: TF-IDF + regresión logística exportada a JSON (solo necesita numpy);
  su explicación es exacta: el aporte de cada palabra al resultado.
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path

import numpy as np
import xgboost as xgb

from centinela.adaptadores.salida.ml import caracteristicas_url as cu
from centinela.adaptadores.salida.ml.texto import normalizar
from centinela.aplicacion.puertos import EvaluacionContenido, EvaluacionEnlace
from centinela.dominio.dominios import ACORTADORES, dominio_registrado, host_de_url
from centinela.dominio.entidades import sin_acentos
from centinela.dominio.idioma import detectar_idioma
from centinela.dominio.riesgo import UMBRAL_ALTO, Area, Gravedad, Razon

_VACIAS = frozenset("el la los las un una de del en y o que es su sus con para por al lo se no si mi tu le les nos "
                    "ha han he has sido fue son era esta este estos estas ese esa usted ud sr sra muy mas ya hay "
                    "the and you your is are to of for with this that has have been was".split())


_MARCADORES = frozenset({"zurl", "znum", "zcorreo", "ztelefono", "zident"})   # los pone texto.normalizar


class ClasificadorEnlacesXgb:
    def __init__(self, ruta_modelo: Path, modelo_id: int | None = None):
        self.modelo_id = modelo_id
        self._booster = xgb.Booster()
        self._booster.load_model(str(ruta_modelo))
        if self._booster.num_features() != len(cu.NOMBRES):
            raise ValueError("El modelo de enlaces no coincide con las características actuales.")

    def evaluar(self, urls: list[str]) -> list[EvaluacionEnlace]:
        salida, a_puntuar = [], []
        for url in urls:
            dominio = dominio_registrado(host_de_url(url))
            salida.append(EvaluacionEnlace(url=url, dominio=dominio, probabilidad=None))
            if dominio not in ACORTADORES:          # un acortador no dice nada del destino real
                a_puntuar.append(len(salida) - 1)
        if a_puntuar:
            x = np.array([cu.vector(salida[i].url) for i in a_puntuar], dtype=np.float32)
            probs = self._booster.predict(xgb.DMatrix(x))
            for i, p in zip(a_puntuar, probs, strict=True):
                e = salida[i]
                salida[i] = EvaluacionEnlace(url=e.url, dominio=e.dominio, probabilidad=round(float(p), 4))
        return salida


class ModeloTextoLineal:
    """TF-IDF sublineal (norma L2) + regresión logística exportados a JSON: vocabulario, idf, coeficientes, intercepto.

    Campos opcionales (formato v2): "normalizacion" (versión de texto.normalizar que se aplica antes) y
    "calibracion" (tabla isotónica x→y que convierte el puntaje en una probabilidad bien calibrada).
    """

    def __init__(self, ruta: Path):
        d = json.loads(ruta.read_text(encoding="utf-8"))
        self.vocab: dict[str, int] = d["vocab"]
        self.idf = np.array(d["idf"], dtype=np.float64)
        self.coef = np.array(d["coef"], dtype=np.float64)
        self.intercepto = float(d["intercepto"])
        self.normalizacion: str | None = d.get("normalizacion")
        cal = d.get("calibracion")
        self._cal = (np.array(cal["x"], dtype=np.float64), np.array(cal["y"], dtype=np.float64)) if cal else None
        self._inv: dict[int, str] | None = None

    def preparar(self, asunto: str, cuerpo: str) -> str:
        return normalizar(asunto, cuerpo) if self.normalizacion else f"{asunto} {cuerpo}"

    def probabilidad_sin_calibrar(self, texto: str) -> float:
        z = self.intercepto + sum(self.coef[j] * x for j, x in self._vector(texto).items())
        return 1.0 / (1.0 + math.exp(-max(min(z, 30.0), -30.0)))

    @staticmethod
    def _tokens(texto: str) -> list[str]:
        palabras = re.findall(r"(?u)\b\w\w+\b", sin_acentos(texto.lower()))
        return palabras + [f"{palabras[i]} {palabras[i + 1]}" for i in range(len(palabras) - 1)]

    def _vector(self, texto: str) -> dict[int, float]:
        cuenta: dict[int, int] = {}
        for t in self._tokens(texto[:20000]):
            j = self.vocab.get(t)
            if j is not None:
                cuenta[j] = cuenta.get(j, 0) + 1
        if not cuenta:
            return {}
        v = {j: (1.0 + math.log(c)) * self.idf[j] for j, c in cuenta.items()}
        norma = math.sqrt(sum(x * x for x in v.values()))
        return {j: x / norma for j, x in v.items()}

    def probabilidad(self, texto: str) -> float:
        p = self.probabilidad_sin_calibrar(texto)
        return float(np.interp(p, *self._cal)) if self._cal is not None else p

    def palabras_clave(self, texto: str, n: int = 3) -> list[str]:
        """Expresiones que más empujan hacia phishing (aporte exacto de un modelo lineal)."""
        if self._inv is None:
            self._inv = {j: t for t, j in self.vocab.items()}
        aportes = sorted(((self.coef[j] * x, self._inv[j]) for j, x in self._vector(texto).items()), reverse=True)
        elegidas: list[str] = []
        for c, w in aportes:
            if c <= 0.02 or any(p in _VACIAS or p.isdigit() or len(p) < 3 or p in _MARCADORES for p in w.split()):
                continue
            if any(w in e or e in w for e in elegidas):        # evita «cuenta» si ya está «su cuenta»
                continue
            elegidas.append(w)
            if len(elegidas) == n:
                break
        return elegidas


class ClasificadorContenidoLineal:
    def __init__(self, modelos: dict[str, ModeloTextoLineal], modelo_id: int | None = None,
                 umbral_medio: float = 0.3, umbral_alto: float = UMBRAL_ALTO):
        self.modelo_id = modelo_id
        self._modelos = modelos
        self._umbral_medio = umbral_medio
        self._umbral_alto = umbral_alto

    def evaluar(self, asunto: str, cuerpo: str) -> EvaluacionContenido | None:
        idioma = detectar_idioma(f"{asunto} {cuerpo}")
        modelo = self._modelos.get(idioma)
        if modelo is None:
            return None
        texto = modelo.preparar(asunto, cuerpo)
        p = modelo.probabilidad(texto)
        razones = []
        if p >= self._umbral_medio:
            palabras = modelo.palabras_clave(texto)
            detalle = (": usa expresiones como " + ", ".join(f"«{w}»" for w in palabras)) if palabras else ""
            gravedad = Gravedad.ALTA if p >= self._umbral_alto else Gravedad.MEDIA
            razones.append(Razon(Area.CONTENIDO, gravedad,
                                 f"El texto se parece a correos de phishing conocidos{detalle}.", aporte=round(p, 4)))
        return EvaluacionContenido(probabilidad=p, razones=razones, idioma=idioma,
                                   umbral_medio=self._umbral_medio, umbral_alto=self._umbral_alto)
