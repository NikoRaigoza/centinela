"""Conocimiento sobre dominios de internet que usan las reglas (sin red: solo el texto del dominio)."""
from __future__ import annotations

import re

# Segundos niveles comunes: en "banco.com.co" el dominio registrado es "banco.com.co", no "com.co".
SLD_COMUNES = frozenset({"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "gob", "mil", "nom"})

ACORTADORES = frozenset({"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
                         "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy"})

# Terminaciones con abuso frecuente (lista curada, fija; no se aprende de los datos para no heredar sesgos
# geográficos como que ".co" parezca riesgoso). Debe revisarse periódicamente.
TLDS_ABUSO = frozenset({"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "icu", "buzz", "cyou", "rest", "monster",
                        "sbs", "cfd", "bond", "quest", "online", "site", "shop", "live", "link", "work", "support", "fit"})

CORREO_GRATUITO = frozenset({"gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "live.com", "icloud.com",
                             "proton.me", "protonmail.com", "aol.com", "gmx.com", "mail.com", "yahoo.es",
                             "hotmail.es", "outlook.es"})

_RE_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_RE_DOMINIO = re.compile(r"(?i)\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b")


def host_de_url(url: str) -> str:
    u = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", str(url).strip())
    host = u.split("#", 1)[0].split("/", 1)[0].split("?", 1)[0]
    host = host.rsplit("@", 1)[-1]
    if ":" in host and not host.startswith("["):
        h, _, p = host.rpartition(":")
        host = h if p.isdigit() else host
    return host.lower().strip(".")


def dominio_registrado(host: str) -> str:
    etiquetas = [e for e in host.lower().split(".") if e]
    if len(etiquetas) <= 2 or _RE_IPV4.match(host):
        return host.lower()
    if len(etiquetas[-1]) == 2 and etiquetas[-2] in SLD_COMUNES:
        return ".".join(etiquetas[-3:])
    return ".".join(etiquetas[-2:])


def es_ip(host: str) -> bool:
    return bool(_RE_IPV4.match(host))


def tld(dominio: str) -> str:
    return dominio.rsplit(".", 1)[-1] if "." in dominio else ""


def pertenece(dominio: str, oficial: str) -> bool:
    """True si `dominio` es el oficial o un subdominio suyo (correo.bancolombia.com ∈ bancolombia.com)."""
    dominio, oficial = dominio.lower(), oficial.lower()
    return dominio == oficial or dominio.endswith("." + oficial)


def dominio_en_texto(texto: str) -> str | None:
    """Primer dominio escrito en un texto visible (p. ej. «www.bancolombia.com» en el texto de un enlace)."""
    m = _RE_DOMINIO.search(texto or "")
    return dominio_registrado(m.group(1)) if m else None


def dominio_enganoso(url: str, texto_visible: str) -> str | None:
    """Si el texto del enlace muestra un dominio distinto al real, devuelve el dominio que se muestra."""
    host = host_de_url(url)
    if not host or es_ip(host):
        return None
    real, visible = dominio_registrado(host), dominio_en_texto(texto_visible)
    return visible if visible and real and visible != real else None
