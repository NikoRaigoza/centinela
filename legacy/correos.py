"""
Analizador de correos de Centinela (version 1).

Revisa un correo (.eml o texto pegado) y estima la probabilidad de phishing combinando:
  1. Texto: modelo lineal (TF-IDF + regresion logistica) en espanol o ingles, exportado a JSON
     (solo necesita numpy; las explicaciones son exactas: aporte de cada palabra).
  2. Enlaces: el modelo de enlaces de Centinela (phishing.py), que se le pasa desde la app.
  3. Senales tecnicas: autenticacion (SPF, DKIM, DMARC), remitente, enlaces enganosos y adjuntos.
Todo ocurre en este equipo: no se envia nada a servicios externos.
Los pesos de las senales tecnicas son criterio de experto (no aprendidos): ver la tesis.
"""
import json
import math
import re
import unicodedata
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser

import numpy as np

import phishing as ph

UMBRAL_MEDIO = 0.30
UMBRAL_ALTO = 0.70
PESO = {"alta": 0.45, "media": 0.20, "baja": 0.07}
MAX_ENLACES = 15
PESO_ENLACES = 0.6   # los enlaces apoyan pero no mandan: solos pueden llegar a riesgo MEDIO, no ALTO (ver evaluacion estricta por dominio)

CORREO_GRATIS = {"gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "live.com", "icloud.com", "proton.me",
                 "protonmail.com", "aol.com", "gmx.com", "mail.com", "yahoo.es", "hotmail.es", "outlook.es"}
ENTIDADES_CO = {
    "dian": ["dian.gov.co"], "registraduria": ["registraduria.gov.co"], "policia nacional": ["policia.gov.co"],
    "fiscalia": ["fiscalia.gov.co"], "servientrega": ["servientrega.com"], "interrapidisimo": ["interrapidisimo.com"],
    "coordinadora": ["coordinadora.com"], "colpensiones": ["colpensiones.gov.co"], "sena": ["sena.edu.co"],
    "mintic": ["mintic.gov.co"], "superintendencia": ["sic.gov.co", "superfinanciera.gov.co"], "epm": ["epm.com.co"],
    "mercado libre": ["mercadolibre.com", "mercadolibre.com.co"], "rappi": ["rappi.com", "rappi.com.co"],
    "davivienda": ["davivienda.com"], "bancolombia": ["bancolombia.com", "grupobancolombia.com"], "nequi": ["nequi.com.co", "nequi.com"],
}
EXT_PELIGROSAS = {"exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "msi", "jar", "hta", "lnk", "ps1", "iso", "img", "dll", "com", "pif", "wsf"}
EXT_MACROS = {"docm", "xlsm", "pptm", "xlsb", "xlam"}
EXT_COMPRIMIDOS = {"zip", "rar", "7z", "ace", "gz", "tar"}
EXT_WEB = {"html", "htm", "shtml", "xhtml"}

_ES = set("el los las una es su sus con para por muy también usted cuenta favor hacer clic correo estimado cliente gracias saludos sobre pero porque desde hasta cuando donde nuestro nuestra tiene debe puede ser está son han fue como más este esta ese esa".split())
_EN = set("the and you your is are to of for with this that account click please we our from have not on by will be can has was as at it if or".split())
_PT = set("não você vocês uma são está mais seu sua obrigado clique conta pagamento também então já pelo pela foi tem nos dos das ao em um".split())


def _sin_acentos(s):
    n = unicodedata.normalize("NFKD", s)
    return n if n == s else "".join(c for c in n if not unicodedata.combining(c))


def detectar_idioma(texto):
    t = texto.lower()[:6000]
    palabras = re.findall(r"[a-záéíóúñãõçüàèê]+", t)
    if len(palabras) < 12:
        return "?"
    es = sum(p in _ES for p in palabras) + 3 * min(sum(t.count(c) for c in ("ñ", "¿", "¡")), 5)
    en = sum(p in _EN for p in palabras)
    pt = sum(p in _PT for p in palabras) + sum(t.count(c) for c in ("ã", "õ", "ç")) * 0.8
    mejor = max((es, "es"), (en, "en"), (pt, "pt"))
    otros = sorted([es, en, pt], reverse=True)
    if mejor[0] < 3 or mejor[0] < otros[1] * 1.25:
        return "?"
    return mejor[1]


# ---------------------------------------------------------------------
# Modelo de texto (TF-IDF + regresion logistica, exportado a JSON)
# ---------------------------------------------------------------------
class ModeloTexto:
    def __init__(self, ruta_json):
        with open(ruta_json, encoding="utf-8") as f:
            d = json.load(f)
        self.nombre = d["nombre"]
        self.vocab = d["vocab"]
        self.idf = np.array(d["idf"], dtype=np.float64)
        self.coef = np.array(d["coef"], dtype=np.float64)
        self.intercepto = float(d["intercepto"])
        self.meta = d.get("meta", {})
        self._inv = None

    def _tokens(self, texto):
        s = _sin_acentos(texto.lower())
        palabras = re.findall(r"(?u)\b\w\w+\b", s)
        return palabras + [palabras[i] + " " + palabras[i + 1] for i in range(len(palabras) - 1)]

    def _vector(self, texto):
        cuenta = {}
        for t in self._tokens(texto[:20000]):
            j = self.vocab.get(t)
            if j is not None:
                cuenta[j] = cuenta.get(j, 0) + 1
        if not cuenta:
            return {}
        v = {j: (1.0 + math.log(c)) * self.idf[j] for j, c in cuenta.items()}
        norma = math.sqrt(sum(x * x for x in v.values()))
        return {j: x / norma for j, x in v.items()}

    def probabilidad(self, texto):
        v = self._vector(texto)
        z = self.intercepto + sum(self.coef[j] * x for j, x in v.items())
        return 1.0 / (1.0 + math.exp(-max(min(z, 30), -30)))

    def aportes(self, texto, n=5):
        """Palabras que mas empujan hacia phishing (aporte exacto en un modelo lineal)."""
        if self._inv is None:
            self._inv = {j: t for t, j in self.vocab.items()}
        v = self._vector(texto)
        lista = sorted(((self.coef[j] * x, self._inv[j]) for j, x in v.items()), reverse=True)
        vacias = _ES | _EN | _PT

        def util(w):
            return not all((p in vacias) or p.isdigit() or len(p) < 3 for p in w.split())
        return [(w, round(float(c), 3)) for c, w in lista if c > 0.02 and util(w)][:n]


# ---------------------------------------------------------------------
# Lectura del correo
# ---------------------------------------------------------------------
class _ExtractorHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.texto, self.enlaces = [], []
        self._href, self._ancla, self._ignorar = None, [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._ignorar += 1
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._ancla = []
        if tag in ("br", "p", "div", "tr", "li", "h1", "h2", "h3"):
            self.texto.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._ignorar:
            self._ignorar -= 1
        if tag == "a" and self._href is not None:
            self.enlaces.append((self._href.strip(), " ".join("".join(self._ancla).split())))
            self._href = None

    def handle_data(self, data):
        if self._ignorar:
            return
        self.texto.append(data)
        if self._href is not None:
            self._ancla.append(data)


def _contenido(part):
    try:
        return part.get_content()
    except Exception:
        try:
            return (part.get_payload(decode=True) or b"").decode("utf-8", "ignore")
        except Exception:
            return ""


def _dominio(correo):
    return correo.split("@")[-1].lower().strip(" >") if "@" in correo else ""


def _auth(msg):
    res = {"spf": None, "dkim": None, "dmarc": None}
    for h in msg.get_all("Authentication-Results") or []:
        h = str(h)
        for clave in res:
            if res[clave] is None:
                m = re.search(r"\b" + clave + r"\s*=\s*([a-z]+)", h, re.I)
                if m:
                    res[clave] = m.group(1).lower()
    if res["spf"] is None:
        for h in msg.get_all("Received-SPF") or []:
            m = re.match(r"\s*([A-Za-z]+)", str(h))
            if m:
                res["spf"] = m.group(1).lower()
                break
    return res


def leer_correo(datos):
    if isinstance(datos, str):
        datos = datos.encode("utf-8", "ignore")
    msg = BytesParser(policy=policy.default).parsebytes(datos)
    nombre, correo = parseaddr(str(msg["From"] or ""))
    _, reply = parseaddr(str(msg["Reply-To"] or ""))
    _, retorno = parseaddr(str(msg["Return-Path"] or ""))
    texto_plano, html_partes, adjuntos = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ct, disp, fname = part.get_content_type(), part.get_content_disposition(), part.get_filename()
        if ct.startswith("image/") and disp != "attachment" and not fname:
            continue
        if ct.startswith("image/") and disp == "inline":
            continue
        if disp == "attachment" or fname or (ct not in ("text/plain", "text/html")):
            try:
                tam = len(part.get_payload(decode=True) or b"")
            except Exception:
                tam = 0
            if ct in ("text/plain",) and not fname and disp != "attachment":
                continue
            adjuntos.append({"nombre": fname or "(sin nombre)", "tipo": ct, "bytes": tam})
            continue
        contenido = _contenido(part)
        if ct == "text/plain":
            texto_plano.append(contenido)
        elif ct == "text/html":
            html_partes.append(contenido)
    # adjuntos que ya fueron retirados por seguridad (paquete de pruebas)
    for h in msg.get_all("X-Centinela-Adjuntos") or []:
        for item in str(h).split("; "):
            p = item.split("|")
            if len(p) >= 3:
                adjuntos.append({"nombre": p[0], "tipo": p[1], "bytes": int(p[2]) if p[2].isdigit() else 0})
    enlaces_html, texto_html = [], ""
    for h in html_partes:
        ex = _ExtractorHTML()
        try:
            ex.feed(h)
            ex.close()
        except Exception:
            pass
        enlaces_html += ex.enlaces
        texto_html += " ".join("".join(ex.texto).split(" "))
    cuerpo = "\n".join(texto_plano).strip()
    if len(cuerpo) < 30:
        cuerpo = texto_html.strip()
    cuerpo = "\n".join(l for l in cuerpo.splitlines() if not l.startswith("[adjunto eliminado por seguridad"))
    enlaces, vistos = [], set()
    for href, ancla in enlaces_html:
        if href and href not in vistos:
            vistos.add(href)
            enlaces.append({"url": href, "ancla": ancla})
    for m in re.finditer(r"(?i)\b((?:https?://|www\.)[^\s<>\"'()\[\]{}]+)", cuerpo):
        u = m.group(1).rstrip(".,;:!?)")
        if u not in vistos:
            vistos.add(u)
            enlaces.append({"url": u, "ancla": ""})
    dkim_dom = ""
    m = re.search(r"\bd=([^;\s]+)", str(msg["DKIM-Signature"] or ""))
    if m:
        dkim_dom = m.group(1).lower()
    auth = _auth(msg)
    return {
        "de_nombre": nombre, "de_correo": correo.lower(), "de_dominio": _dominio(correo),
        "reply_dominio": _dominio(reply), "retorno_dominio": _dominio(retorno), "dkim_dominio": dkim_dom,
        "asunto": str(msg["Subject"] or "").replace("\n", " ").strip(), "fecha": str(msg["Date"] or ""), "mensaje_id": str(msg["Message-ID"] or "").strip(),
        "auth": auth, "tiene_auth": any(auth.values()), "saltos": len(msg.get_all("Received") or []),
        "cuerpo": cuerpo, "enlaces": enlaces, "adjuntos": adjuntos,
    }


# ---------------------------------------------------------------------
# Senales tecnicas (reglas explicables)
# ---------------------------------------------------------------------
def _marca_en(texto):
    t = _sin_acentos(texto.lower())
    for m, oficiales in list(ph.MARCAS.items()) + list(ENTIDADES_CO.items()):
        if re.search(r"(?<![a-z0-9])" + re.escape(m) + r"(?![a-z0-9])", t):
            return m, oficiales
    return None, None


def _es_oficial(reg, oficiales):
    return any(reg == o or reg.endswith("." + o) for o in oficiales)


def _ext(nombre):
    n = nombre.lower().strip()
    return n.rsplit(".", 1)[-1] if "." in n else ""


def _senales(c):
    s, pos = [], []
    a = c["auth"]
    if c["tiene_auth"]:
        if a["dmarc"] == "fail":
            s.append(("Autenticación", "alta", "Falló DMARC: el dominio del remitente no autoriza este envío (señal clásica de suplantación)."))
        if a["spf"] in ("fail", "permerror"):
            s.append(("Autenticación", "media", "Falló SPF: el servidor que lo envió no está autorizado por el dominio del remitente."))
        elif a["spf"] == "softfail":
            s.append(("Autenticación", "baja", "SPF dudoso (softfail): el servidor de envío no es el habitual del dominio."))
        if a["dkim"] == "fail":
            s.append(("Autenticación", "media", "Falló DKIM: la firma digital del correo no es válida."))
        if a["spf"] == "pass" and a["dkim"] == "pass" and a["dmarc"] in ("pass", "bestguesspass"):
            pos.append("Pasó SPF, DKIM y DMARC (el remitente es quien dice ser, aunque eso no garantiza que el contenido sea seguro).")
        elif a["dkim"] is None and a["spf"] in ("none", None):
            s.append(("Autenticación", "baja", "No hay firma DKIM ni SPF que respalde al remitente."))
    dom = c["de_dominio"]
    reg = ph.dominio_registrado(dom) if dom else ""
    if c["reply_dominio"] and ph.dominio_registrado(c["reply_dominio"]) != reg:
        s.append(("Remitente", "media", "Las respuestas van a otro dominio (" + c["reply_dominio"] + ") distinto al del remitente."))
    marca, oficiales = _marca_en(c["de_nombre"] + " " + c["asunto"])
    if marca and reg and not _es_oficial(reg, oficiales):
        grave = reg in CORREO_GRATIS or (c["tiene_auth"] and c["auth"]["dmarc"] == "fail") or (reg.rsplit(".", 1)[-1] in ph.TLDS_ABUSO)
        s.append(("Remitente", "alta" if grave else "media",
                  "Dice ser o hablar de «" + marca + "», pero el correo viene de " + (reg or "un dominio desconocido") + ", que no es el oficial."))
    if reg:
        f = ph.extraer(reg + "/")
        if f["marca_suplantada"]:
            s.append(("Remitente", "alta", "El dominio del remitente (" + reg + ") imita el nombre de una marca conocida."))
        elif f["tld_abuso"]:
            s.append(("Remitente", "media", "El remitente usa una terminación de dominio muy frecuente en fraudes (." + reg.rsplit('.', 1)[-1] + ")."))
    if c["dkim_dominio"] and reg and ph.dominio_registrado(c["dkim_dominio"]) != reg and c["auth"]["dkim"] == "pass":
        s.append(("Remitente", "baja", "La firma DKIM es de otro dominio (" + c["dkim_dominio"] + ") distinto al remitente."))
    for ad in c["adjuntos"]:
        nombre, e = ad["nombre"], _ext(ad["nombre"])
        partes = nombre.lower().split(".")
        doble = len(partes) >= 3 and partes[-2] in ("pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt") and partes[-1] in (EXT_PELIGROSAS | EXT_WEB | EXT_COMPRIMIDOS)
        if e in EXT_PELIGROSAS or doble:
            s.append(("Adjuntos", "alta", "Adjunto «" + nombre + "»: " + ("doble extensión para disfrazarlo." if doble else "archivo ejecutable o de alto riesgo.")))
        elif e in EXT_MACROS:
            s.append(("Adjuntos", "media", "Adjunto «" + nombre + "» con macros: pueden ejecutar programas al abrirlo."))
        elif e in EXT_WEB:
            s.append(("Adjuntos", "media", "Adjunto «" + nombre + "» es una página web: se usa para robar contraseñas."))
        elif e in EXT_COMPRIMIDOS:
            s.append(("Adjuntos", "media", "Adjunto «" + nombre + "» comprimido: puede esconder archivos peligrosos."))
    return s, pos


_URGENCIA = re.compile(r"(?i)\b(urgente|inmediatamente|de inmediato|últim[oa] aviso|acción requerida|será (suspendid|bloquead|cancelad)|en las próximas \d+ horas|dentro de las \d+ horas|urgent|immediately|action required|will be (suspended|closed|terminated)|within \d+ hours)")
_DATOS = re.compile(r"(?i)\b(contraseña|clave|tarjeta|cvv|número de cuenta|ingrese sus datos|actualice sus datos|verifique su|confirme su|password|credentials|verify your|confirm your|update your)\b")
_PREMIO = re.compile(r"(?i)\b(ganaste|ganador|premio|herencia|regalo|gratis|sorteo|you have won|winner|lottery|inheritance|free gift)\b")


def _senales_texto(c):
    t = c["asunto"] + " " + c["cuerpo"][:6000]
    r = []
    if _URGENCIA.search(t):
        r.append(("Contenido", "baja", "Crea urgencia o amenaza con suspender algo para que actúes sin pensar."))
    if _DATOS.search(t):
        r.append(("Contenido", "baja", "Pide o menciona contraseñas, tarjetas o datos personales."))
    if _PREMIO.search(t):
        r.append(("Contenido", "baja", "Ofrece premios, regalos o dinero fácil."))
    return r


def _dominio_url(u):
    return ph.dominio_registrado(ph.partir(u)[0])


def _analizar_enlaces(c, puntuar_urls):
    s, filas = [], []
    candidatos = []
    for e in c["enlaces"]:
        u = e["url"]
        if not u or u.lower().startswith(("mailto:", "tel:", "#", "cid:", "data:")):
            continue
        if u.lower().startswith("javascript:"):
            s.append(("Enlaces", "alta", "Hay un enlace que ejecuta código (javascript)."))
            continue
        candidatos.append(e)
    candidatos = candidatos[:MAX_ENLACES]
    probas = puntuar_urls([e["url"] for e in candidatos]) if (candidatos and puntuar_urls) else [None] * len(candidatos)
    for e, p in zip(candidatos, probas):
        u = e["url"]
        corto = ph.extraer(u)["es_acortador"]
        fila = {"url": u, "ancla": e["ancla"], "p": None if corto else (float(p) if p is not None else None), "acortado": corto}
        filas.append(fila)
        m = re.search(r"(?i)((?:https?://)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+)", e["ancla"] or "")
        if m and _dominio_url(m.group(1)) and _dominio_url(u) and _dominio_url(m.group(1)) != _dominio_url(u):
            s.append(("Enlaces", "alta", "El enlace dice «" + m.group(1)[:40] + "» pero en realidad lleva a " + _dominio_url(u) + "."))
        if corto:
            s.append(("Enlaces", "media", "Hay un enlace acortado (" + _dominio_url(u) + "): no se ve a dónde lleva."))
    return s, filas


def _nivel(p):
    return "ALTO" if p >= UMBRAL_ALTO else ("MEDIO" if p >= UMBRAL_MEDIO else "BAJO")


def _combinar_enlaces(filas):
    ps = [f["p"] for f in filas if f["p"] is not None]
    return sum(ps) / len(ps) if ps else None   # el promedio fue lo mas estable en la evaluacion


def fabrica_puntuar_urls(modelo_xgb):
    """Devuelve la funcion que puntua enlaces con el modelo de enlaces recalibrado con enlaces de correos."""
    def puntuar(urls):
        if not urls:
            return []
        X = np.array([ph.vector(u) for u in urls], dtype=np.float32)
        return [float(p) for p in modelo_xgb.predict_proba(X)[:, 1]]
    return puntuar


def analizar_correo(datos, modelos):
    """modelos: {'es': ModeloTexto, 'en': ModeloTexto, 'urls': funcion(lista_de_urls) -> lista_de_prob}"""
    c = leer_correo(datos)
    idioma = detectar_idioma(c["asunto"] + " " + c["cuerpo"])
    tecnicas, positivas = _senales(c)
    s_enl, filas = _analizar_enlaces(c, modelos.get("urls"))
    s_txt = _senales_texto(c)
    modelo = modelos.get(idioma) if idioma in ("es", "en") else None
    p_texto = modelo.probabilidad(c["asunto"] + " " + c["cuerpo"]) if modelo and len(c["cuerpo"]) >= 20 else None
    p_enl = _combinar_enlaces(filas)
    todas = tecnicas + s_enl
    p_tec = 1.0 - math.prod(1.0 - PESO[g] for _, g, _ in todas) if todas else 0.0
    comps = [p for p in (p_texto, PESO_ENLACES * p_enl if p_enl is not None else None, p_tec if todas else None) if p is not None]
    base = max(comps) if comps else 0.0
    concordancia = sum(1 for p in comps if p >= 0.5)
    p_final = min(0.99, base + 0.05 * max(0, concordancia - 1)) if comps else 0.0
    razones = [{"area": a, "gravedad": g, "texto": t} for a, g, t in sorted(todas, key=lambda x: {"alta": 0, "media": 1, "baja": 2}[x[1]])]
    razones += [{"area": a, "gravedad": g, "texto": t} for a, g, t in s_txt]
    palabras = modelo.aportes(c["asunto"] + " " + c["cuerpo"]) if (modelo and p_texto is not None and p_texto >= 0.3) else []
    return {
        "de_nombre": c["de_nombre"], "de_correo": c["de_correo"], "de_dominio": c["de_dominio"], "asunto": c["asunto"], "fecha": c["fecha"], "mensaje_id": c["mensaje_id"],
        "idioma": idioma, "modelo_texto": idioma if modelo else None, "auth": c["auth"], "tiene_auth": c["tiene_auth"], "saltos": c["saltos"],
        "enlaces": filas, "adjuntos": c["adjuntos"], "p_texto": p_texto, "p_enlaces": p_enl, "p_tecnico": p_tec if todas else None,
        "p_final": p_final, "nivel": _nivel(p_final), "razones": razones, "positivas": positivas, "palabras": palabras,
        "largo_cuerpo": len(c["cuerpo"]),
    }


# ---------------------------------------------------------------------
# Correos de ejemplo (SINTETICOS, para la demostracion; no son correos reales)
# ---------------------------------------------------------------------
def ejemplos():
    from email.message import EmailMessage
    phishing = EmailMessage()
    phishing["From"] = "DIAN Notificaciones <notificaciones@dian-devolucion-iva.info>"
    phishing["To"] = "gerencia@pyme-ejemplo.co"
    phishing["Reply-To"] = "cobros.dian2026@gmail.com"
    phishing["Subject"] = "URGENTE: devolución de IVA pendiente, verifique sus datos en las próximas 24 horas"
    phishing["Date"] = "Mon, 06 Oct 2026 08:12:44 -0500"
    phishing["Authentication-Results"] = "mx.pyme-ejemplo.co; spf=fail smtp.mailfrom=dian-devolucion-iva.info; dkim=none; dmarc=fail header.from=dian-devolucion-iva.info"
    phishing.set_content("Estimado contribuyente: tiene una devolución de IVA pendiente por $2.480.000. Para recibirla debe confirmar sus datos y su número de cuenta hoy mismo. "
                         "De lo contrario su solicitud será cancelada. Ingrese aquí: http://dian-devolucion-iva.info/formulario/login.php?id=88213")
    phishing.add_alternative('<html><body><p>Estimado contribuyente:</p><p>Tiene una <b>devolución de IVA</b> pendiente por $2.480.000. Para recibirla <b>debe verificar sus datos y su número de cuenta hoy mismo</b>. '
                             'De lo contrario su solicitud será cancelada.</p><p><a href="http://dian-devolucion-iva.info/formulario/login.php?id=88213">www.dian.gov.co/devoluciones</a></p></body></html>', subtype="html")
    phishing.add_attachment(b"<html><form action='http://dian-devolucion-iva.info/captura'></form></html>", maintype="text", subtype="html", filename="Formulario_DIAN.html")
    legitimo = EmailMessage()
    legitimo["From"] = "Biblioteca Universitaria <boletin@universidad-ejemplo.edu.co>"
    legitimo["To"] = "gerencia@pyme-ejemplo.co"
    legitimo["Subject"] = "Boletín de octubre: nuevos recursos y horarios de la biblioteca"
    legitimo["Date"] = "Fri, 03 Oct 2026 10:00:00 -0500"
    legitimo["Authentication-Results"] = "mx.pyme-ejemplo.co; spf=pass smtp.mailfrom=universidad-ejemplo.edu.co; dkim=pass header.d=universidad-ejemplo.edu.co; dmarc=pass header.from=universidad-ejemplo.edu.co"
    legitimo.set_content("Estimada comunidad universitaria: les compartimos el boletín de octubre. Este mes la biblioteca amplía su horario hasta las 8 de la noche y suma nuevas bases de datos "
                         "de consulta para trabajos de grado. Pueden revisar el calendario completo en https://www.universidad-ejemplo.edu.co/biblioteca/horarios. Cordial saludo, equipo de la biblioteca.")
    return {"Phishing falso de la DIAN (ejemplo sintético)": phishing.as_bytes(), "Boletín legítimo de una universidad (ejemplo sintético)": legitimo.as_bytes()}
