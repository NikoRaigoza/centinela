"""Catálogo de entidades que más se suplantan en Colombia (DIAN, Bancolombia, Nequi...). Vive en la BD."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from centinela.dominio.dominios import pertenece


def sin_acentos(texto: str) -> str:
    n = unicodedata.normalize("NFKD", texto)
    return "".join(c for c in n if not unicodedata.combining(c))


@dataclass(frozen=True)
class Entidad:
    id: int
    nombre: str
    categoria: str
    alias: tuple[str, ...]
    dominios: tuple[str, ...]

    def es_oficial(self, dominio: str | None) -> bool:
        return bool(dominio) and any(pertenece(dominio, d) for d in self.dominios)


class CatalogoEntidades:
    def __init__(self, entidades: list[Entidad]):
        self.entidades = entidades
        self._patrones = [
            (e, re.compile(r"(?<![a-z0-9])(" + "|".join(re.escape(sin_acentos(a.lower()))
                                                         for a in sorted({e.nombre, *e.alias}, key=len, reverse=True))
                           + r")(?![a-z0-9])"))
            for e in entidades
        ]

    def mencionada_en(self, texto: str) -> Entidad | None:
        """Primera entidad del catálogo que aparece como palabra completa en el texto (sin importar tildes)."""
        t = sin_acentos((texto or "").lower())
        for entidad, patron in self._patrones:
            if patron.search(t):
                return entidad
        return None

    def duena_de(self, dominio: str | None) -> Entidad | None:
        """Entidad a la que pertenece oficialmente un dominio."""
        return next((e for e in self.entidades if e.es_oficial(dominio)), None) if dominio else None
