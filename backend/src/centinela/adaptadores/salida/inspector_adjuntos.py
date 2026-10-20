"""Inspección del contenido de los adjuntos y lectura de códigos QR.

Nada de lo que se inspecciona se ejecuta ni se guarda: se leen los primeros bytes (la «firma» del formato), la lista
de archivos de un comprimido (sin descomprimirlo), el texto de los PDF y las imágenes, todo en memoria y con límites
de tamaño y tiempo para que un adjunto malicioso no pueda tumbar al worker (bombas de descompresión, imágenes
gigantes). Solo se conserva el resultado: tipo real, señales y enlaces encontrados.
"""
from __future__ import annotations

import io
import logging
import re
import warnings
import zipfile
import zlib
from dataclasses import dataclass

from centinela.dominio.correo import SenalAdjunto

log = logging.getLogger(__name__)

MAX_BYTES_INSPECCION = 8_000_000          # adjuntos más grandes solo se revisan por su firma
MAX_BYTES_IMAGEN = 5_000_000
MAX_PIXELES_IMAGEN = 25_000_000           # ~5000 x 5000: más grande que eso no es una imagen de correo normal
MAX_IMAGENES_QR = 12
MAX_ARCHIVOS_ZIP = 500
MAX_BYTES_ZIP_INTERNO = 2_000_000         # un comprimido dentro de otro se mira solo si es pequeño
MAX_FLUJOS_PDF = 200
MAX_BYTES_FLUJOS_PDF = 20_000_000         # total descomprimido de un PDF (defensa contra bombas)
MAX_ENLACES_ADJUNTO = 30

EXT_RIESGO_INTERNO = frozenset({"exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "msi", "jar", "hta", "lnk", "ps1",
                                "iso", "img", "dll", "com", "pif", "wsf", "html", "htm", "svg", "xhtml", "url", "reg",
                                "vhd", "vhdx", "msix", "appx", "chm", "cpl"})
EXT_DOCUMENTO = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "txt", "csv",
                           "rtf", "odt", "ods"})
TIPOS_IMAGEN = frozenset({"png", "jpeg", "gif", "bmp", "webp"})

_RE_URL = re.compile(rb"(?i)\b(https?://[^\s<>\"'()\[\]{}\\]{4,2000})")
_RE_URI_PDF = re.compile(rb"/URI\s*\(([^)]{4,2000})\)")
_RE_FLUJO_PDF = re.compile(rb"stream\r?\n")
_RE_JPEG_PDF = re.compile(rb"/Filter\s*/DCTDecode")
_VBA_UTF16 = "_VBA_PROJECT".encode("utf-16-le")
_MACROS_UTF16 = "Macros".encode("utf-16-le")
_CIFRADO_UTF16 = "EncryptedPackage".encode("utf-16-le")


@dataclass(frozen=True)
class Inspeccion:
    tipo_real: str | None = None
    senales: tuple[SenalAdjunto, ...] = ()
    contenido: tuple[str, ...] = ()          # nombres de archivos dentro de un comprimido
    enlaces: tuple[str, ...] = ()            # direcciones escritas dentro del adjunto (PDF o HTML)
    qr: tuple[str, ...] = ()                 # textos leídos de códigos QR


def tipo_por_firma(datos: bytes) -> str | None:
    """El formato real del archivo por sus primeros bytes, sin importar cómo se llame."""
    d = datos[:2048]
    if d.startswith(b"MZ") or d.startswith(b"\x7fELF") or d[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                                                                      b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "ejecutable"
    if d.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if b"%PDF-" in d[:1024]:
        return "pdf"
    if d.startswith(b"PK\x03\x04") or d.startswith(b"PK\x05\x06"):
        return "zip"
    if d.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if d.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if d.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if d.startswith(b"\x1f\x8b"):
        return "gz"
    if d.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if d.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if d.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if d.startswith(b"BM") and len(d) > 26:
        return "bmp"
    if d.startswith(b"RIFF") and d[8:12] == b"WEBP":
        return "webp"
    if len(datos) > 0x8006 and datos[0x8001:0x8006] == b"CD001":
        return "iso"
    inicio = d.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if inicio.startswith((b"<svg", b"<?xml")) and b"<svg" in d.lower():
        return "svg"
    if inicio.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<script", b"<meta", b"<form", b"<iframe")):
        return "html"
    if d.startswith(b"{\\rtf"):
        return "rtf"
    return None


def _es_url(texto: str) -> str | None:
    t = texto.strip()
    if re.match(r"(?i)^https?://[^\s]{3,}$", t):
        return t[:2000]
    if re.match(r"(?i)^www\.[a-z0-9-]+\.[a-z]{2,}", t):
        return "http://" + t[:2000]
    return None


class InspectorAdjuntos:
    """Implementa la inspección con la librería estándar; los QR los lee zxing-cpp (mismo motor que Android)."""

    def __init__(self, leer_qr: bool = True):
        self._leer_qr = leer_qr

    # ------------------------------------------------------------------ QR
    def qr_de_imagen(self, datos: bytes) -> tuple[str, ...]:
        """Direcciones web escritas en códigos QR de una imagen. Otros contenidos (wifi, texto) se ignoran."""
        if not self._leer_qr or not datos or len(datos) > MAX_BYTES_IMAGEN:
            return ()
        try:
            import zxingcpp
            from PIL import Image

            Image.MAX_IMAGE_PIXELS = MAX_PIXELES_IMAGEN
            with warnings.catch_warnings():
                # Una imagen enorme («bomba de descompresión») se rechaza antes de cargarla en memoria
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                img = Image.open(io.BytesIO(datos))
            with img:
                if img.width * img.height > MAX_PIXELES_IMAGEN:
                    return ()
                img.seek(0)                                    # primer cuadro de un GIF animado
                cuadro = img.convert("L")
            resultados = zxingcpp.read_barcodes(cuadro, formats=zxingcpp.BarcodeFormat.QRCode)
        except Exception:  # noqa: BLE001 - una imagen dañada o que no se puede leer no detiene el análisis
            return ()
        urls = [u for r in resultados if (u := _es_url(r.text))]
        return tuple(dict.fromkeys(urls))[:5]

    # ------------------------------------------------------------------ adjuntos
    def inspeccionar(self, nombre: str, tipo_mime: str, datos: bytes) -> Inspeccion:
        tipo = tipo_por_firma(datos)
        ext = nombre.rsplit(".", 1)[-1].lower() if "." in nombre else ""
        senales: list[SenalAdjunto] = []
        contenido: tuple[str, ...] = ()
        enlaces: tuple[str, ...] = ()
        qr: tuple[str, ...] = ()

        if tipo == "ejecutable":
            senales.append(SenalAdjunto.EJECUTABLE)
        if ext in EXT_DOCUMENTO and tipo in ("ejecutable", "html", "svg", "lnk", "iso") \
                or ext in ("pdf",) and tipo in ("zip", "rar", "7z", "ole") \
                or ext in ("jpg", "jpeg", "png", "gif") and tipo not in (None, *TIPOS_IMAGEN):
            senales.append(SenalAdjunto.DISFRAZADO)

        if len(datos) <= MAX_BYTES_INSPECCION:
            try:
                if tipo == "zip":
                    contenido, extra = self._zip(datos)
                    senales += extra
                    if "META-INF/MANIFEST.MF" in contenido and any(n.endswith(".class") for n in contenido):
                        tipo = "jar"
                        senales.append(SenalAdjunto.EJECUTABLE)
                    elif "[Content_Types].xml" in contenido:
                        tipo = "ooxml"
                    contenido = tuple(n for n in contenido if not n.endswith("/"))[:50] if tipo == "zip" else ()
                elif tipo == "ole":
                    senales += self._ole(datos)
                elif tipo == "pdf":
                    extra, enlaces, qr = self._pdf(datos)
                    senales += extra
                elif tipo in ("html", "svg") or ext in ("html", "htm", "svg", "xhtml", "shtml"):
                    extra, enlaces = self._html(datos)
                    senales += extra
                if tipo in TIPOS_IMAGEN:
                    qr = self.qr_de_imagen(datos)
            except Exception:  # noqa: BLE001 - adjunto corrupto a propósito: se queda con lo que se alcanzó a ver
                log.info("No se pudo inspeccionar por completo un adjunto de tipo %s", tipo)
        if qr:
            senales.append(SenalAdjunto.CODIGO_QR)
        return Inspeccion(tipo, tuple(dict.fromkeys(senales)), contenido, enlaces[:MAX_ENLACES_ADJUNTO], qr)

    def _zip(self, datos: bytes, profundidad: int = 0) -> tuple[tuple[str, ...], list[SenalAdjunto]]:
        senales: list[SenalAdjunto] = []
        with zipfile.ZipFile(io.BytesIO(datos)) as z:
            infos = z.infolist()[:MAX_ARCHIVOS_ZIP]
            nombres = tuple(i.filename for i in infos)
            if any(i.flag_bits & 0x1 for i in infos):
                senales.append(SenalAdjunto.CIFRADO)
            if "[Content_Types].xml" in nombres:                       # documento de Office moderno
                if any(n.lower().endswith("vbaproject.bin") for n in nombres):
                    senales.append(SenalAdjunto.MACROS)
                rels = next((i for i in infos if i.filename.lower() == "word/_rels/settings.xml.rels"), None)
                if rels and rels.file_size < 100_000:
                    xml = z.read(rels).lower()
                    if b"attachedtemplate" in xml and b'targetmode="external"' in xml:
                        senales.append(SenalAdjunto.PLANTILLA_REMOTA)
                return nombres, senales
            for i in infos:
                ext = i.filename.rsplit(".", 1)[-1].lower() if "." in i.filename else ""
                if ext in EXT_RIESGO_INTERNO:
                    senales.append(SenalAdjunto.COMPRIMIDO_PELIGROSO)
                elif ext in ("zip",) and profundidad == 0 and i.file_size <= MAX_BYTES_ZIP_INTERNO \
                        and not i.flag_bits & 0x1 and (i.compress_size == 0 or i.file_size / i.compress_size < 100):
                    _, internas = self._zip(z.read(i), profundidad + 1)
                    senales += [s for s in internas if s in (SenalAdjunto.COMPRIMIDO_PELIGROSO, SenalAdjunto.CIFRADO)]
                elif ext in ("rar", "7z", "iso", "img", "gz", "tar", "ace"):
                    senales.append(SenalAdjunto.COMPRIMIDO_PELIGROSO)
        return nombres, senales

    @staticmethod
    def _ole(datos: bytes) -> list[SenalAdjunto]:
        """Documentos de Office antiguos (.doc, .xls): las macros viven en un «almacén» llamado _VBA_PROJECT."""
        senales = []
        if _VBA_UTF16 in datos or _MACROS_UTF16 in datos:
            senales.append(SenalAdjunto.MACROS)
        if _CIFRADO_UTF16 in datos:
            senales.append(SenalAdjunto.CIFRADO)
        return senales

    def _pdf(self, datos: bytes) -> tuple[list[SenalAdjunto], tuple[str, ...], tuple[str, ...]]:
        """Busca acciones activas y enlaces en el PDF, también dentro de los flujos comprimidos (FlateDecode).
        Las imágenes JPEG incrustadas se revisan en busca de códigos QR. Un PDF con clave (los extractos bancarios en
        Colombia suelen venir así) no se marca: su contenido simplemente no se puede leer."""
        partes = [datos]
        jpegs: list[bytes] = []
        total = 0
        for i, m in enumerate(_RE_FLUJO_PDF.finditer(datos)):
            if i >= MAX_FLUJOS_PDF or total > MAX_BYTES_FLUJOS_PDF:
                break
            inicio = m.end()
            fin = datos.find(b"endstream", inicio)
            if fin < 0:
                break
            flujo = datos[inicio:fin]
            cabecera = datos[max(0, m.start() - 400):m.start()]
            if _RE_JPEG_PDF.search(cabecera) and flujo.startswith(b"\xff\xd8") and len(jpegs) < MAX_IMAGENES_QR:
                jpegs.append(flujo)
                continue
            try:
                d = zlib.decompressobj()
                plano = d.decompress(flujo, MAX_BYTES_FLUJOS_PDF - total)
            except zlib.error:
                continue
            total += len(plano)
            partes.append(plano)
        texto = b"\n".join(partes)
        senales = []
        if re.search(rb"/(JavaScript|JS|Launch)\b", texto):
            senales.append(SenalAdjunto.PDF_JAVASCRIPT)
        if re.search(rb"/(EmbeddedFiles?|RichMedia)\b", texto):
            senales.append(SenalAdjunto.PDF_ARCHIVO_OCULTO)
        urls = [m.group(1).decode("latin-1", "ignore").replace("\\", "") for m in _RE_URI_PDF.finditer(texto)]
        enlaces = tuple(dict.fromkeys(u for u in urls if u.lower().startswith(("http://", "https://"))))
        qr = tuple(dict.fromkeys(u for j in jpegs for u in self.qr_de_imagen(j)))
        return senales, enlaces, qr

    @staticmethod
    def _html(datos: bytes) -> tuple[list[SenalAdjunto], tuple[str, ...]]:
        t = datos[:MAX_BYTES_INSPECCION].lower()
        senales = []
        if re.search(rb"<form\b", t) or re.search(rb"type\s*=\s*[\"']?password", t):
            senales.append(SenalAdjunto.FORMULARIO)
        if re.search(rb"<script\b|\bon(load|error|click|mouseover)\s*=|javascript:|<foreignobject\b|http-equiv\s*=\s*[\"']?"
                     rb"refresh|window\.location|document\.location|atob\(", t):
            senales.append(SenalAdjunto.SCRIPT)
        urls = [m.group(1).decode("utf-8", "ignore").rstrip(".,;") for m in _RE_URL.finditer(datos[:MAX_BYTES_INSPECCION])]
        externos = [u for u in urls if "w3.org/" not in u]           # espacios de nombres de SVG/XHTML, no son enlaces
        return senales, tuple(dict.fromkeys(externos))
