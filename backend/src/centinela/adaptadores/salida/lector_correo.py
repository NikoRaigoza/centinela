"""Lector de correos MIME (RFC 5322) con la librería estándar. Portado y endurecido desde el prototipo.

Seguridad:
  * Solo se confía en el encabezado Authentication-Results que agrega Google (authserv-id mx.google.com):
    cualquier remitente puede escribir uno falso con "spf=pass" en su propio correo.
  * Los avisos de Centinela se reconocen por una firma HMAC en X-Centinela-Alerta, no por la mera
    presencia del encabezado (si no, un atacante lo copiaría para evitar el análisis).
"""
from __future__ import annotations

import hashlib
import hmac
import re
from datetime import UTC
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from html.parser import HTMLParser

from centinela.dominio.correo import Adjunto, Autenticacion, CorreoParseado, Enlace, ResultadoAuth

SERVIDOR_CONFIABLE = "mx.google.com"
ENCABEZADO_AVISO = "X-Centinela-Alerta"
MAX_ENLACES = 200
_RE_URL_TEXTO = re.compile(r"(?i)\b((?:https?://|www\.)[^\s<>\"'()\[\]{}]+)")


def firmar_aviso(clave: bytes, message_id: str) -> str:
    """Valor del encabezado X-Centinela-Alerta para un aviso generado por Centinela."""
    return "v1;" + hmac.new(clave, message_id.strip().encode(), hashlib.sha256).hexdigest()


class _ExtractorHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.texto: list[str] = []
        self.enlaces: list[tuple[str, str]] = []
        self._href: str | None = None
        self._ancla: list[str] = []
        self._ignorar = 0

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


def _dominio(direccion: str) -> str:
    return direccion.rsplit("@", 1)[-1].lower().strip(" >") if "@" in direccion else ""


def _contenido(parte) -> str:
    try:
        return parte.get_content()
    except Exception:  # noqa: BLE001 - correos mal formados son normales en phishing
        return (parte.get_payload(decode=True) or b"").decode("utf-8", "ignore")


def _resultado(texto: str, clave: str) -> ResultadoAuth | None:
    m = re.search(r"\b" + clave + r"\s*=\s*([a-z]+)", texto, re.I)
    return ResultadoAuth.interpretar(m.group(1)) if m else None


def _autenticacion(msg: EmailMessage) -> Autenticacion:
    encabezados = [str(h) for h in msg.get_all("Authentication-Results") or []]
    confiables = [h for h in encabezados if h.split(";", 1)[0].strip().lower() == SERVIDOR_CONFIABLE]
    fuente = confiables[0] if confiables else (encabezados[0] if encabezados else "")
    spf = _resultado(fuente, "spf")
    if spf is None and not confiables:
        m = re.match(r"\s*([A-Za-z]+)", str(msg.get("Received-SPF") or ""))
        spf = ResultadoAuth.interpretar(m.group(1)) if m else None
    m = re.search(r"\bd=([^;\s]+)", str(msg.get("DKIM-Signature") or ""))
    return Autenticacion(spf=spf, dkim=_resultado(fuente, "dkim"), dmarc=_resultado(fuente, "dmarc"),
                         dkim_dominio=m.group(1).lower() if m else None, confiable=bool(confiables))


class LectorCorreoMime:
    def __init__(self, clave_avisos: bytes):
        self._clave_avisos = clave_avisos

    def leer(self, crudo: bytes) -> CorreoParseado:
        msg = BytesParser(policy=policy.default).parsebytes(crudo)
        nombre, remitente = parseaddr(str(msg.get("From") or ""))
        _, responder_a = parseaddr(str(msg.get("Reply-To") or ""))
        _, retorno = parseaddr(str(msg.get("Return-Path") or ""))
        texto_plano, partes_html, adjuntos = [], [], []

        for parte in msg.walk():
            if parte.is_multipart():
                continue
            tipo, disposicion, archivo = parte.get_content_type(), parte.get_content_disposition(), parte.get_filename()
            if tipo.startswith("image/") and disposicion != "attachment":
                continue                                   # imágenes del cuerpo (logos, firmas)
            if disposicion == "attachment" or archivo or tipo not in ("text/plain", "text/html"):
                datos = parte.get_payload(decode=True) or b""
                adjuntos.append(Adjunto(nombre=(archivo or "(sin nombre)")[:255], tipo_mime=tipo[:100],
                                        tamano_bytes=len(datos), sha256=hashlib.sha256(datos).hexdigest()))
                continue
            (texto_plano if tipo == "text/plain" else partes_html).append(_contenido(parte))

        enlaces_html, texto_html = [], ""
        for h in partes_html:
            ex = _ExtractorHTML()
            try:
                ex.feed(h)
                ex.close()
            except Exception:  # noqa: BLE001, S110 - HTML roto (común en phishing): se usa lo que alcanzó a leerse
                pass
            enlaces_html += ex.enlaces
            texto_html += " ".join("".join(ex.texto).split(" "))
        cuerpo = "\n".join(texto_plano).strip()
        if len(cuerpo) < 30:
            cuerpo = texto_html.strip()

        enlaces, vistos = [], set()
        candidatos = list(enlaces_html) + [(m.group(1).rstrip(".,;:!?)"), "") for m in _RE_URL_TEXTO.finditer(cuerpo)]
        for url, texto in candidatos:
            if url and url not in vistos and not url.lower().startswith(("mailto:", "tel:", "#")):
                vistos.add(url)
                enlaces.append(Enlace(url=url, texto_visible=texto[:300]))

        message_id = str(msg.get("Message-ID") or "").strip() or None
        return CorreoParseado(
            asunto=" ".join(str(msg.get("Subject") or "").split())[:500],
            remitente_nombre=nombre.strip()[:200],
            remitente_correo=remitente.lower()[:320],
            remitente_dominio=_dominio(remitente),
            cuerpo=cuerpo,
            message_id=message_id[:500] if message_id else None,
            fecha=self._fecha(msg),
            responder_a_dominio=_dominio(responder_a) or None,
            ruta_retorno_dominio=_dominio(retorno) or None,
            autenticacion=_autenticacion(msg),
            saltos=len(msg.get_all("Received") or []),
            enlaces=tuple(enlaces[:MAX_ENLACES]),
            adjuntos=tuple(adjuntos),
            es_aviso_centinela=self._es_aviso(msg, message_id),
        )

    def _es_aviso(self, msg: EmailMessage, message_id: str | None) -> bool:
        firma = str(msg.get(ENCABEZADO_AVISO) or "").strip()
        return bool(firma and message_id) and hmac.compare_digest(firma, firmar_aviso(self._clave_avisos, message_id))

    @staticmethod
    def _fecha(msg: EmailMessage):
        try:
            f = parsedate_to_datetime(str(msg.get("Date") or ""))
        except (TypeError, ValueError, IndexError):
            return None
        return f if f.tzinfo else f.replace(tzinfo=UTC)
