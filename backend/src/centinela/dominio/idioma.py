"""Detección simple de idioma (español / inglés) por palabras funcionales. Sin dependencias.

La versión del prototipo usaba listas cortas y exigía muchas coincidencias: con correos breves devolvía
"otro idioma" y el modelo de texto no se ejecutaba. Ante la duda se asume español (Centinela es para Colombia).
"""
from __future__ import annotations

import re

_ES = frozenset("""de la que el en y a los se del las un por con no una su para es al lo como mas pero sus le ya o este
si porque esta entre cuando muy sin sobre tambien me hasta hay donde quien desde todo nos durante todos uno les ni
contra otros ese eso ante ellos esto antes algunos unos yo otro otras otra tanto esa estos mucho quienes nada
muchos cual poco ella estar estas algunas algo nosotros mi mis tu te ti tus usted ustedes hola gracias favor
necesito hoy aqui ahora tiene puede debe son fue han hace estoy estamos""".split())
_EN = frozenset("""the of and to in is you that it he was for on are as with his they at be this have from or one had
by but not what all were we when your can said there use an each which she do how their if will up other about out
many then them these so some her would make like him into time has look two more write go see no way could people
my than first been call who its now find long down day did get come made may part please thanks hello hi dear
account click here our""".split())
_RE_PALABRA = re.compile(r"[a-zñü]+")


def _sin_tildes(t: str) -> str:
    return t.translate(str.maketrans("áéíóúàèìòù", "aeiouaeiou"))


def detectar_idioma(texto: str) -> str:
    """'es', 'en' u 'otro' (solo si no hay ninguna palabra reconocible)."""
    t = texto.lower()[:6000]
    palabras = _RE_PALABRA.findall(_sin_tildes(t))
    es = sum(p in _ES for p in palabras) + 2 * sum(t.count(c) for c in "ñ¿¡")
    en = sum(p in _EN for p in palabras)
    if es == 0 and en == 0:
        return "otro"
    return "en" if en > es * 1.5 else "es"
