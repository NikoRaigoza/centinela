"""Registro de modelos: cada versión vive en una carpeta con un manifest.json que lista sus archivos y sus SHA-256.

    modelos/<tipo>/<version>/manifest.json
    {"tipo": "enlaces", "formato": "xgboost-url-v3", "nombre": "...", "version": "...", "dataset": "...",
     "umbral_medio": 0.3, "umbral_alto": 0.7, "metricas": {...}, "archivos": {"modelo.json": "<sha256>"}}

La tabla modelo_ml guarda la ruta y el SHA-256 del manifest. Antes de usar un modelo se verifica todo:
si un archivo fue alterado, el modelo NO se carga (integridad de la cadena de ML).
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path

from centinela.adaptadores.salida.ml.clasificadores import (
    ClasificadorContenidoLineal,
    ClasificadorEnlacesXgb,
    ModeloTextoLineal,
)
from centinela.aplicacion.puertos import FabricaUnidadDeTrabajo, ModeloRegistrado

log = logging.getLogger(__name__)
MANIFIESTO = "manifest.json"
SEGUNDOS_CACHE = 60


class ModeloAlterado(Exception):
    pass


def sha256_archivo(ruta: Path) -> str:
    h = hashlib.sha256()
    with ruta.open("rb") as f:
        for bloque in iter(lambda: f.read(1 << 20), b""):
            h.update(bloque)
    return h.hexdigest()


def leer_manifiesto(carpeta: Path) -> dict:
    return json.loads((carpeta / MANIFIESTO).read_text(encoding="utf-8"))


def verificar(carpeta: Path, sha256_esperado: str) -> dict:
    if sha256_archivo(carpeta / MANIFIESTO) != sha256_esperado:
        raise ModeloAlterado(f"El manifiesto de {carpeta} no coincide con el registrado.")
    manifiesto = leer_manifiesto(carpeta)
    for nombre, esperado in manifiesto["archivos"].items():
        if Path(nombre).name != nombre or sha256_archivo(carpeta / nombre) != esperado:
            raise ModeloAlterado(f"El archivo {nombre} de {carpeta} fue modificado.")
    return manifiesto


def crear_manifiesto(carpeta: Path, datos: dict) -> Path:
    """Escribe manifest.json con el SHA-256 de cada archivo de la carpeta (menos el propio manifiesto)."""
    archivos = {p.name: sha256_archivo(p) for p in sorted(carpeta.iterdir()) if p.is_file() and p.name != MANIFIESTO}
    ruta = carpeta / MANIFIESTO
    ruta.write_text(json.dumps({**datos, "archivos": archivos}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return ruta


def construir_clasificador(carpeta: Path, manifiesto: dict, modelo_id: int | None):
    formato = manifiesto["formato"]
    if formato == "xgboost-url-v3":
        return ClasificadorEnlacesXgb(carpeta / "modelo.json", modelo_id)
    if formato == "texto-lineal-v1":
        modelos = {Path(n).stem: ModeloTextoLineal(carpeta / n) for n in manifiesto["archivos"] if n.endswith(".json")}
        return ClasificadorContenidoLineal(modelos, modelo_id)
    raise ValueError(f"Formato de modelo desconocido: {formato}")


class ProveedorModelosRegistrados:
    """Implementa el puerto ProveedorModelos. Si se activa una versión nueva, la toma sin reiniciar el worker."""

    def __init__(self, uow: FabricaUnidadDeTrabajo, dir_modelos: Path):
        self._uow = uow
        self._dir = dir_modelos
        self._cargados: dict[str, tuple[int, object]] = {}
        self._consultado: dict[str, tuple[float, ModeloRegistrado | None]] = {}

    def _activo(self, tipo: str) -> ModeloRegistrado | None:
        ahora = time.monotonic()
        guardado = self._consultado.get(tipo)
        if guardado and ahora - guardado[0] < SEGUNDOS_CACHE:
            return guardado[1]
        with self._uow() as uow:
            registro = uow.modelos.activo(tipo)
        self._consultado[tipo] = (ahora, registro)
        return registro

    def _cargar(self, tipo: str):
        registro = self._activo(tipo)
        if registro is None:
            return None
        if tipo in self._cargados and self._cargados[tipo][0] == registro.id:
            return self._cargados[tipo][1]
        carpeta = (self._dir / registro.ruta).resolve()
        try:
            manifiesto = verificar(carpeta, registro.sha256)
            clasificador = construir_clasificador(carpeta, manifiesto, registro.id)
        except (ModeloAlterado, OSError, ValueError, KeyError):
            log.exception("No se cargó el modelo %s %s: se analiza sin él", tipo, registro.version)
            self._cargados.pop(tipo, None)
            return None
        self._cargados[tipo] = (registro.id, clasificador)
        log.info("Modelo de %s cargado: %s %s", tipo, registro.nombre, registro.version)
        return clasificador

    def contenido(self):
        return self._cargar("contenido")

    def enlaces(self):
        return self._cargar("enlaces")
