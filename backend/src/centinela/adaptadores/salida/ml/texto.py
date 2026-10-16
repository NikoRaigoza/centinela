"""Normalización del texto y rasgos del modelo de contenido. FUENTE ÚNICA para entrenamiento y producción.

Por qué normalizar así (ver ml/hallazgos_calidad_datos.md):
  * Los datasets sanitizan distinto según la clase (URLs con "[.]", "<EMAIL>", saludos insertados). Si el modelo
    viera esas marcas aprendería atajos. Por eso toda URL, correo, teléfono y número largo se reemplaza por el
    mismo marcador, venga del dataset o de un correo real, y se quita la línea de saludo inicial.
  * Cambiar este archivo exige reentrenar y registrar una versión nueva del modelo (VERSION_NORMALIZACION).
"""
from __future__ import annotations

import math
import re
import unicodedata

VERSION_NORMALIZACION = "1"

_URL = re.compile(r"(?i)\b(?:h(?:tt|xx)ps?://|www\.|www\[\.\])\S+|\b[\w-]+(?:\[\.\]|\.)(?:com|net|org|info|co|mx|io|"
                  r"xyz|top|online|site|me|ly|gl|es|edu|gob|gov)(?:\.[a-z]{2})?(?:/\S*)?")
_CORREO = re.compile(r"(?i)<email>|[\w.+-]+\s*(?:@|\[at\])\s*[\w-]+(?:\.|\[\.\])[\w.\[\]-]+")
_TELEFONO = re.compile(r"(?i)<telefono>|\+?\d[\d\s().-]{6,}\d")
_IDENTIFICADOR = re.compile(r"(?i)<rfc>|<clabe>|<nit>|<cedula>")
_NUMERO = re.compile(r"\d+")
_SALUDO = re.compile(r"(?i)^\s*(?:hola|estimad[oa]s?(?:/[oa])?|querid[oa]s?|buen[oa]s?\s+(?:d[ií]as|tardes|noches)|"
                     r"apreciad[oa]s?|se[ñn]or(?:a)?|dear|hello|hi)\b[^\n]{0,80}?(?:[,:!]|\n)")
_ESPACIOS = re.compile(r"\s+")

LEXICOS = {
    "urgencia": re.compile(r"\b(urgente|inmediat\w*|de inmediato|ultimo aviso|accion requerida|plazo|vence\w*|expira\w*|"
                           r"suspend\w*|bloque\w*|cancelad\w*|horas)\b"),
    "credenciales": re.compile(r"\b(contrasena\w*|clave\w*|usuario|credencial\w*|verifi\w*|confirm\w*|valid\w*|"
                               r"actualic\w*|actualiz\w*|inicia\w* sesion|ingres\w*)\b"),
    "dinero": re.compile(r"\b(pago\w*|cobro\w*|factura\w*|deuda\w*|saldo\w*|transferencia\w*|tarjeta\w*|banco\w*|"
                         r"cuenta\w*|reembolso\w*|devolucion\w*|cargo\w*|multa\w*|embargo\w*)\b"),
    "premio": re.compile(r"\b(premio\w*|ganador\w*|ganaste|sorteo\w*|regalo\w*|gratis|felicidades|herencia|beneficio\w*)\b"),
    "amenaza": re.compile(r"\b(sancion\w*|demanda\w*|juridic\w*|judicial\w*|policia|denuncia\w*|penaliz\w*|"
                          r"perdera\w*|cierre)\b"),
    "accion": re.compile(r"\b(clic|click|haga|haz|presione|descargue|descarga|abra|abre|siguiente enlace|aqui)\b"),
}

NOMBRES_RASGOS = ["log_largo", "n_url", "n_correo", "n_telefono", "ratio_mayusculas", "exclamaciones",
                  "interrogaciones", *[f"lex_{k}" for k in LEXICOS]]


def sin_acentos(texto: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", texto) if not unicodedata.combining(c))


def normalizar(asunto: str, cuerpo: str) -> str:
    """Texto que ve el modelo: sin saludo inicial y con marcadores uniformes, en minúsculas y sin tildes."""
    cuerpo = _SALUDO.sub("", cuerpo or "", count=1)
    texto = f"{asunto or ''}\n{cuerpo}"
    texto = _CORREO.sub(" zcorreo ", texto)
    texto = _URL.sub(" zurl ", texto)
    texto = _TELEFONO.sub(" ztelefono ", texto)
    texto = _IDENTIFICADOR.sub(" zident ", texto)
    texto = _NUMERO.sub(" znum ", texto)
    return _ESPACIOS.sub(" ", sin_acentos(texto.lower())).strip()


def rasgos(asunto: str, cuerpo: str) -> list[float]:
    """Rasgos de estilo e ingeniería social, calculados sobre el texto normalizado (mismo orden que NOMBRES_RASGOS)."""
    norm = normalizar(asunto, cuerpo)
    original = f"{asunto or ''} {_SALUDO.sub('', cuerpo or '', count=1)}"
    for rx in (_CORREO, _URL, _TELEFONO, _IDENTIFICADOR):         # los marcadores no cuentan como estilo
        original = rx.sub(" ", original)
    letras = [c for c in original if c.isalpha()]
    palabras = max(1, len(norm.split()))
    valores = [
        math.log1p(len(norm)),
        float(norm.count("zurl")),
        float(norm.count("zcorreo")),
        float(norm.count("ztelefono")),
        sum(c.isupper() for c in letras) / max(1, len(letras)),
        float(min(original.count("!") + original.count("¡"), 20)),
        float(min(original.count("?") + original.count("¿"), 20)),
    ]
    valores += [100.0 * len(rx.findall(norm)) / palabras for rx in LEXICOS.values()]
    return valores
