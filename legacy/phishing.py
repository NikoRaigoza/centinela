"""
Detector de phishing por enlace (URL) para Centinela.

Solo usa caracteristicas del propio texto del enlace (lexicas): no consulta internet,
no abre el sitio y no envia el enlace a ningun servicio externo.
Version 3 (sin sesgo por terminacion de pais). Este mismo archivo lo usan el entrenamiento (cuaderno) y la pagina, para que las dos
calculen exactamente lo mismo.
"""
import math
import re

PALABRAS_SOSPECHOSAS = [
    "login", "signin", "sign-in", "logon", "verify", "verification", "secure", "security", "account",
    "update", "confirm", "banking", "bank", "password", "passwd", "credential", "webscr", "support",
    "billing", "invoice", "wallet", "suspend", "unlock", "recover", "validate", "authenticate",
]
MARCAS = {
    "paypal": ["paypal.com"], "ebay": ["ebay.com"], "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "windows.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazonaws.com"], "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com"], "instagram": ["instagram.com"],
    "google": ["google.com", "gmail.com", "googleusercontent.com", "goo.gl"], "gmail": ["gmail.com", "google.com"],
    "outlook": ["outlook.com", "live.com", "office.com"], "dropbox": ["dropbox.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"], "linkedin": ["linkedin.com"], "twitter": ["twitter.com", "x.com"],
    "adobe": ["adobe.com"], "docusign": ["docusign.com", "docusign.net"],
    "bancolombia": ["bancolombia.com", "grupobancolombia.com"], "davivienda": ["davivienda.com"],
    "nequi": ["nequi.com.co", "nequi.com"], "bbva": ["bbva.com", "bbva.com.co", "bbva.es"],
    "santander": ["santander.com", "santander.com.br"], "citibank": ["citibank.com", "citi.com"],
    "wellsfargo": ["wellsfargo.com"], "chase": ["chase.com"], "hsbc": ["hsbc.com"],
    "dhl": ["dhl.com"], "fedex": ["fedex.com"],
}
ACORTADORES = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
               "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy"}
SLD_COMUNES = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "gob", "mil", "nom"}
# Terminaciones de dominio con abuso frecuente (lista curada a mano, fija: NO se aprende de los datos,
# para no heredar sesgos geograficos como que ".co" parezca riesgoso). Debe revisarse periodicamente.
TLDS_ABUSO = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "icu", "buzz", "cyou", "rest", "monster", "sbs", "cfd",
              "bond", "quest", "online", "site", "shop", "live", "link", "work", "support", "fit"}
EXT_PELIGROSAS = {"exe", "zip", "rar", "scr", "apk", "bat", "msi", "jar", "js"}
RE_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
RE_IP_RARA = re.compile(r"^(0x[0-9a-f]+|\d{8,12})$")
RE_DOMINIO_EN_RUTA = re.compile(r"/[a-z0-9-]+\.(com|net|org|info|co|biz|gov|edu)(\.[a-z]{2})?(/|$|\?)")
RE_REDIRECT = re.compile(r"[?&](url|redirect|redirect_uri|next|goto|continue|return|dest|destination|link)=", re.I)

NOMBRES = [
    "len_url", "len_host", "len_ruta", "len_query", "puntos_host", "puntos_url", "guiones_host", "guiones_url",
    "guion_bajo", "barras", "digitos_url", "ratio_digitos_url", "digitos_host", "ratio_digitos_host",
    "arrobas", "interrogaciones", "iguales", "ampersands", "porcentajes", "tildes", "especiales",
    "host_es_ip", "puerto_raro", "subdominios", "entropia_host", "entropia_ruta", "entropia_url",
    "tld_abuso", "sufijo_restringido", "profundidad_ruta", "token_mas_largo", "n_tokens", "token_promedio",
    "ext_php", "ext_html", "ext_peligrosa", "wordpress", "n_palabras_sospechosas", "kw_login", "kw_secure",
    "kw_verify", "kw_account", "kw_update", "kw_bank", "marca_en_url", "marca_suplantada", "es_acortador",
    "punycode", "etiquetas_mezcla", "racha_digitos", "ratio_mayusculas_ruta", "doble_barra_ruta",
    "n_parametros", "redirige", "dominio_en_ruta", "www_en_ruta", "len_dominio_registrado",
]


def _entropia(texto):
    if not texto:
        return 0.0
    n = len(texto)
    conteo = {}
    for c in texto:
        conteo[c] = conteo.get(c, 0) + 1
    return -sum((v / n) * math.log2(v / n) for v in conteo.values())


def limpiar(url):
    """Quita el esquema (http://, https://) para que el modelo no lo use como 'truco'."""
    u = str(url).strip()
    u = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", u)
    return u


def partir(url):
    """Separa host, puerto, ruta y query de forma tolerante a URLs mal formadas."""
    u = limpiar(url)
    u = u.split("#", 1)[0]
    host_port, _, resto = u.partition("/")
    arroba = "@" in host_port
    if arroba:
        host_port = host_port.rsplit("@", 1)[1]
    host, puerto = host_port, ""
    if ":" in host_port and not host_port.startswith("["):
        h, _, p = host_port.rpartition(":")
        if p.isdigit():
            host, puerto = h, p
    ruta, _, query = resto.partition("?")
    return host.lower().strip("."), puerto, "/" + ruta, query, arroba


def dominio_registrado(host):
    etiquetas = [e for e in host.split(".") if e]
    if len(etiquetas) <= 2:
        return host
    if len(etiquetas[-1]) == 2 and etiquetas[-2] in SLD_COMUNES:
        return ".".join(etiquetas[-3:])
    return ".".join(etiquetas[-2:])


def restringido(host):
    """Terminaciones que solo pueden registrar entidades verificadas (gobierno, educacion, militar)."""
    e = [x for x in host.split(".") if x]
    if not e:
        return False
    if e[-1] in ("gov", "edu", "mil", "int"):
        return True
    return len(e) >= 2 and e[-2] in ("gov", "gob", "edu", "mil", "ac") and len(e[-1]) == 2


def tld_de(host):
    etiquetas = [e for e in host.split(".") if e]
    return etiquetas[-1] if etiquetas else ""


def extraer(url):
    """Devuelve un diccionario {nombre: numero} con todas las caracteristicas del enlace."""
    original = limpiar(url)
    low = original.lower()
    host, puerto, ruta, query, arroba = partir(url)
    reg = dominio_registrado(host)
    tld = tld_de(host)
    host_sin_reg = host[: -len(reg)].strip(".") if host.endswith(reg) else host
    subdominios = len([e for e in host_sin_reg.split(".") if e])
    etiquetas_host = [e for e in host.split(".") if e]
    tokens = [t for t in re.split(r"[^a-z0-9]+", low) if t]
    nombre_archivo = ruta.rstrip("/").rsplit("/", 1)[-1].lower()
    extension = nombre_archivo.rsplit(".", 1)[-1] if "." in nombre_archivo else ""
    n_digitos = sum(c.isdigit() for c in low)
    n_dig_host = sum(c.isdigit() for c in host)
    ruta_letras = [c for c in ruta if c.isalpha()]
    rachas = re.findall(r"\d+", low)
    marca_en_url = [m for m in MARCAS if m in low]
    suplantada = 0
    for m in marca_en_url:
        if not any(reg == oficial or reg.endswith("." + oficial) for oficial in MARCAS[m]):
            suplantada = 1
            break
    palabras = [p for p in PALABRAS_SOSPECHOSAS if p in low]

    f = {
        "len_url": len(original), "len_host": len(host), "len_ruta": len(ruta), "len_query": len(query),
        "puntos_host": host.count("."), "puntos_url": original.count("."),
        "guiones_host": host.count("-"), "guiones_url": original.count("-"), "guion_bajo": original.count("_"),
        "barras": original.count("/"), "digitos_url": n_digitos,
        "ratio_digitos_url": n_digitos / max(len(original), 1), "digitos_host": n_dig_host,
        "ratio_digitos_host": n_dig_host / max(len(host), 1),
        "arrobas": original.count("@") + (1 if arroba else 0), "interrogaciones": original.count("?"),
        "iguales": original.count("="), "ampersands": original.count("&"), "porcentajes": original.count("%"),
        "tildes": original.count("~"),
        "especiales": sum(1 for c in original if not (c.isalnum() or c in "./-_")),
        "host_es_ip": 1 if (RE_IPV4.match(host) or RE_IP_RARA.match(host)) else 0,
        "puerto_raro": 1 if puerto not in ("", "80", "443") else 0,
        "subdominios": subdominios,
        "entropia_host": _entropia(host), "entropia_ruta": _entropia(ruta), "entropia_url": _entropia(low),
        "tld_abuso": 1 if tld in TLDS_ABUSO else 0, "sufijo_restringido": 1 if restringido(host) else 0,
        "profundidad_ruta": len([s for s in ruta.split("/") if s]),
        "token_mas_largo": max((len(t) for t in tokens), default=0), "n_tokens": len(tokens),
        "token_promedio": (sum(len(t) for t in tokens) / len(tokens)) if tokens else 0,
        "ext_php": 1 if extension in ("php", "php3", "asp", "aspx", "jsp", "cgi") else 0,
        "ext_html": 1 if extension in ("html", "htm", "shtml") else 0,
        "ext_peligrosa": 1 if extension in EXT_PELIGROSAS else 0,
        "wordpress": 1 if re.search(r"wp-(content|includes|admin|json)", low) else 0,
        "n_palabras_sospechosas": len(palabras),
        "kw_login": 1 if ("login" in low or "signin" in low or "sign-in" in low or "logon" in low) else 0,
        "kw_secure": 1 if ("secure" in low or "security" in low) else 0,
        "kw_verify": 1 if ("verify" in low or "verification" in low or "validate" in low) else 0,
        "kw_account": 1 if "account" in low else 0,
        "kw_update": 1 if "update" in low else 0,
        "kw_bank": 1 if "bank" in low else 0,
        "marca_en_url": len(marca_en_url), "marca_suplantada": suplantada,
        "es_acortador": 1 if reg in ACORTADORES else 0,
        "punycode": 1 if "xn--" in host else 0,
        "etiquetas_mezcla": sum(1 for e in etiquetas_host if any(c.isdigit() for c in e) and any(c.isalpha() for c in e)),
        "racha_digitos": max((len(r) for r in rachas), default=0),
        "ratio_mayusculas_ruta": (sum(c.isupper() for c in ruta_letras) / len(ruta_letras)) if ruta_letras else 0,
        "doble_barra_ruta": 1 if "//" in ruta else 0,
        "n_parametros": len([p for p in query.split("&") if p]) if query else 0,
        "redirige": 1 if RE_REDIRECT.search("?" + query) else 0,
        "dominio_en_ruta": 1 if RE_DOMINIO_EN_RUTA.search(ruta.lower() + "/") else 0,
        "www_en_ruta": 1 if "www." in (ruta + "?" + query).lower() else 0,
        "len_dominio_registrado": len(reg),
    }
    return f


def vector(url):
    f = extraer(url)
    return [float(f[n]) for n in NOMBRES]


# ---------------------------------------------------------------------
# Reglas explicables (las usa el motor hibrido y las razones que ve el usuario)
# ---------------------------------------------------------------------
def razones(url):
    """Lista de (gravedad, texto) con las senales de riesgo que se ven a simple vista en el enlace."""
    f = extraer(url)
    r = []
    if f["host_es_ip"]:
        r.append(("alta", "El enlace usa una dirección IP en lugar de un nombre de sitio."))
    if f["arrobas"]:
        r.append(("alta", "Contiene el símbolo @, que puede esconder el verdadero destino del enlace."))
    if f["marca_suplantada"]:
        r.append(("alta", "Menciona una marca conocida pero el sitio no es el oficial de esa marca."))
    if f["punycode"]:
        r.append(("alta", "Usa caracteres internacionales que pueden imitar letras de otro sitio (punycode)."))
    if f["es_acortador"]:
        r.append(("media", "Es un enlace acortado: no se ve a dónde lleva realmente."))
    if f["subdominios"] >= 3:
        r.append(("media", "Tiene demasiados subdominios, una forma común de camuflar sitios falsos."))
    if f["n_palabras_sospechosas"] >= 2:
        r.append(("media", "Incluye varias palabras típicas de engaños (login, verify, account, secure...)."))
    if f["dominio_en_ruta"] or f["www_en_ruta"]:
        r.append(("media", "Dentro de la ruta aparece otro sitio web, una táctica usada para aparentar legitimidad."))
    if f["redirige"]:
        r.append(("media", "Trae un parámetro de redirección hacia otra dirección."))
    if f["puerto_raro"]:
        r.append(("media", "Usa un puerto poco habitual."))
    if f["tld_abuso"]:
        r.append(("media", "Usa una terminación de dominio muy frecuente en sitios fraudulentos."))
    if f["len_url"] > 100:
        r.append(("baja", "El enlace es muy largo, algo frecuente en enlaces de engaño."))
    if f["etiquetas_mezcla"]:
        r.append(("baja", "Mezcla letras y números en el nombre del sitio (por ejemplo paypa1)."))
    if f["ext_peligrosa"]:
        r.append(("alta", "Apunta directamente a un archivo ejecutable o comprimido."))
    return r
