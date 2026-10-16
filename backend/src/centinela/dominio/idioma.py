"""Detección simple de idioma (español / inglés) por palabras frecuentes. Portada del prototipo."""
from __future__ import annotations

import re

_ES = frozenset("el los las una es su sus con para por muy también usted cuenta favor hacer clic correo estimado "
                "cliente gracias saludos sobre pero porque desde hasta cuando donde nuestro nuestra tiene debe puede "
                "ser está son han fue como más este esta ese esa".split())
_EN = frozenset("the and you your is are to of for with this that account click please we our from have not on by "
                "will be can has was as at it if or".split())


def detectar_idioma(texto: str) -> str:
    """'es', 'en' u 'otro'."""
    t = texto.lower()[:6000]
    palabras = re.findall(r"[a-záéíóúñü]+", t)
    if len(palabras) < 8:
        return "es" if any(c in t for c in "ñ¿¡áéíóú") else "otro"
    es = sum(p in _ES for p in palabras) + 3 * min(sum(t.count(c) for c in "ñ¿¡"), 5)
    en = sum(p in _EN for p in palabras)
    if max(es, en) < 3:
        return "otro"
    return "es" if es >= en else "en"
