"""Reglas de seguridad explicables (criterio experto, no aprendidas). Portadas y ampliadas desde el prototipo.

Cada regla produce una Razon con un texto en español sencillo. Las reglas cubren lo que el dataset de
entrenamiento no trae (remitente, autenticación, enlaces y adjuntos) y el contexto colombiano
(entidades suplantadas y pretextos frecuentes).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from centinela.dominio.correo import CorreoParseado, ResultadoAuth
from centinela.dominio.dominios import (
    ACORTADORES,
    CORREO_GRATUITO,
    TLDS_ABUSO,
    dominio_en_texto,
    dominio_registrado,
    es_ip,
    host_de_url,
    tld,
)
from centinela.dominio.entidades import CatalogoEntidades
from centinela.dominio.riesgo import PESO_GRAVEDAD, Area, Gravedad, Razon

EXT_PELIGROSAS = frozenset({"exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "msi", "jar", "hta", "lnk", "ps1",
                            "iso", "img", "dll", "com", "pif", "wsf"})
EXT_MACROS = frozenset({"docm", "xlsm", "pptm", "xlsb", "xlam"})
EXT_COMPRIMIDOS = frozenset({"zip", "rar", "7z", "ace", "gz", "tar"})
EXT_WEB = frozenset({"html", "htm", "shtml", "xhtml"})
EXT_DOCUMENTO = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"})

_URGENCIA = re.compile(r"(?i)\b(urgente|inmediatamente|de inmediato|últim[oa] aviso|acción requerida|será (suspendid|"
                       r"bloquead|cancelad)|en las próximas \d+ horas|dentro de las \d+ horas|urgent|immediately|"
                       r"action required|will be (suspended|closed|terminated)|within \d+ hours)")
_DATOS = re.compile(r"(?i)\b(contraseña|clave|tarjeta|cvv|número de cuenta|ingrese sus datos|actualice sus datos|"
                    r"verifique su|confirme su|password|credentials|verify your|confirm your|update your)\b")
_PREMIO = re.compile(r"(?i)\b(ganaste|ganador|premio|herencia|regalo|gratis|sorteo|you have won|winner|lottery|"
                     r"inheritance|free gift)\b")
_PRETEXTO_CO = re.compile(r"(?i)\b(comparendo|fotomulta|embargo|saldo a favor|devoluci[oó]n de (impuestos|saldo)|"
                          r"factura electr[oó]nica|proceso (judicial|de cobro)|citaci[oó]n|demanda en su contra|"
                          r"pago (por|v[ií]a) pse|su (paquete|env[ií]o) (est[aá] )?(retenido|pendiente))\b")
_DIRECCION_EN_NOMBRE = re.compile(r"[\w.+-]+@([\w-]+\.)+[a-z]{2,}", re.I)


@dataclass
class ResultadoReglas:
    razones: list[Razon] = field(default_factory=list)
    positivas: list[str] = field(default_factory=list)
    remitente_verificado: bool = False     # dominio oficial de una entidad del catálogo + DMARC aprobado por Google

    def agregar(self, area: Area, gravedad: Gravedad, texto: str, entidad_id: int | None = None) -> None:
        self.razones.append(Razon(area, gravedad, texto, aporte=PESO_GRAVEDAD[gravedad], entidad_id=entidad_id))


def _autenticacion(c: CorreoParseado, r: ResultadoReglas) -> None:
    a = c.autenticacion
    if not a.confiable:            # sin el encabezado de Google no hay datos fiables (p. ej. un .eml subido)
        return
    dom = c.remitente_dominio or "el remitente"
    if a.dmarc is ResultadoAuth.FAIL:
        r.agregar(Area.AUTENTICACION, Gravedad.ALTA,
                  f"El correo no pasó la verificación DMARC: {dom} no autorizó este envío. "
                  "Es una señal típica de que el remitente es falso.")
    if a.spf in (ResultadoAuth.FAIL, ResultadoAuth.PERMERROR):
        r.agregar(Area.AUTENTICACION, Gravedad.MEDIA,
                  f"El servidor que envió el correo no está autorizado por {dom} (falló SPF).")
    elif a.spf is ResultadoAuth.SOFTFAIL:
        r.agregar(Area.AUTENTICACION, Gravedad.BAJA,
                  "El servidor que envió el correo no es el habitual del remitente (SPF dudoso).")
    if a.dkim is ResultadoAuth.FAIL:
        r.agregar(Area.AUTENTICACION, Gravedad.MEDIA, "La firma digital del correo no es válida (falló DKIM).")
    if a.spf is ResultadoAuth.PASS and a.dkim is ResultadoAuth.PASS and a.dmarc is ResultadoAuth.PASS:
        r.positivas.append("El remitente pasó las verificaciones SPF, DKIM y DMARC.")
    elif a.dkim in (None, ResultadoAuth.NONE) and a.spf in (None, ResultadoAuth.NONE):
        r.agregar(Area.AUTENTICACION, Gravedad.BAJA, "Ningún mecanismo de autenticación respalda al remitente.")


def _remitente(c: CorreoParseado, r: ResultadoReglas) -> None:
    reg = dominio_registrado(c.remitente_dominio) if c.remitente_dominio else ""
    if c.responder_a_dominio and reg and dominio_registrado(c.responder_a_dominio) != reg:
        r.agregar(Area.REMITENTE, Gravedad.MEDIA,
                  f"Si respondes, tu respuesta iría a {c.responder_a_dominio}, un dominio distinto al del remitente.")
    m = _DIRECCION_EN_NOMBRE.search(c.remitente_nombre or "")
    if m and reg and dominio_registrado(m.group(0).rsplit("@", 1)[1].lower()) != reg:
        r.agregar(Area.REMITENTE, Gravedad.ALTA,
                  f"El nombre del remitente muestra «{m.group(0)}», pero el correo real viene de {reg}.")
    if reg and tld(reg) in TLDS_ABUSO:
        r.agregar(Area.REMITENTE, Gravedad.MEDIA,
                  f"El remitente usa una terminación de dominio muy frecuente en fraudes (.{tld(reg)}).")


def _suplantacion(c: CorreoParseado, catalogo: CatalogoEntidades, r: ResultadoReglas) -> None:
    reg = dominio_registrado(c.remitente_dominio) if c.remitente_dominio else ""
    imitada = catalogo.mencionada_en(re.sub(r"[.\-_]", " ", reg)) if reg else None
    if imitada and not imitada.es_oficial(reg):
        r.agregar(Area.SUPLANTACION, Gravedad.ALTA,
                  f"El dominio del remitente ({reg}) imita el nombre de {imitada.nombre}, pero no es suyo.", imitada.id)
        return
    en_cabecera = catalogo.mencionada_en(f"{c.remitente_nombre} {c.asunto}")
    entidad = en_cabecera or catalogo.mencionada_en(c.cuerpo[:3000])
    if entidad is None:
        return
    if entidad.es_oficial(reg):
        if c.autenticacion.confiable and c.autenticacion.dmarc is ResultadoAuth.PASS:
            r.positivas.append(f"Viene de un dominio oficial de {entidad.nombre} y pasó la verificación DMARC.")
        return
    origen = reg or "un remitente desconocido"
    if reg in CORREO_GRATUITO:
        r.agregar(Area.SUPLANTACION, Gravedad.ALTA,
                  f"Dice ser de {entidad.nombre}, pero se envió desde una cuenta gratuita ({origen}). "
                  f"{entidad.nombre} no escribe desde cuentas personales.", entidad.id)
    elif en_cabecera:
        r.agregar(Area.SUPLANTACION, Gravedad.ALTA,
                  f"Dice ser de {entidad.nombre}, pero lo envía {origen}, que no es un dominio oficial de {entidad.nombre}.",
                  entidad.id)
    else:
        r.agregar(Area.SUPLANTACION, Gravedad.MEDIA,
                  f"Habla en nombre de {entidad.nombre}, pero lo envía {origen}, que no pertenece a {entidad.nombre}.",
                  entidad.id)


def _enlaces(c: CorreoParseado, catalogo: CatalogoEntidades, r: ResultadoReglas) -> None:
    vistos: set[str] = set()
    for e in c.enlaces:
        url = e.url.strip()
        if url.lower().startswith("javascript:"):
            r.agregar(Area.ENLACE, Gravedad.ALTA, "Hay un enlace que ejecuta código (javascript) al abrirlo.")
            continue
        host = host_de_url(url)
        if not host or host in vistos:
            continue
        vistos.add(host)
        real = dominio_registrado(host)
        visible = dominio_en_texto(e.texto_visible)
        if visible and real and visible != real and not es_ip(host):
            r.agregar(Area.ENLACE, Gravedad.ALTA, f"Un enlace dice «{e.texto_visible[:60]}» pero en realidad lleva a {real}.")
        if es_ip(host):
            r.agregar(Area.ENLACE, Gravedad.ALTA, "Un enlace lleva a una dirección IP en lugar de a un sitio con nombre.")
            continue
        imitada = catalogo.mencionada_en(re.sub(r"[.\-_]", " ", host))
        if imitada and not imitada.es_oficial(host):
            r.agregar(Area.ENLACE, Gravedad.ALTA,
                      f"Un enlace lleva a {real}, que usa el nombre de {imitada.nombre} pero no es su sitio oficial.",
                      imitada.id)
        if "xn--" in host:
            r.agregar(Area.ENLACE, Gravedad.ALTA,
                      f"Un enlace usa letras de otros alfabetos para imitar un sitio conocido ({host}).")
        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            r.agregar(Area.ENLACE, Gravedad.ALTA, "Un enlace usa el símbolo @ para esconder su verdadero destino.")
        if tld(real) in TLDS_ABUSO:
            r.agregar(Area.ENLACE, Gravedad.MEDIA, f"Un enlace lleva a {real}, una terminación muy usada en fraudes.")
        if re.search(r"\.(" + "|".join(EXT_PELIGROSAS) + r")(\?|$)", url.lower()):
            r.agregar(Area.ENLACE, Gravedad.ALTA, "Un enlace descarga directamente un programa o archivo peligroso.")
        if real in ACORTADORES:
            r.agregar(Area.ENLACE, Gravedad.MEDIA, f"Un enlace está acortado ({real}): no se ve a dónde lleva realmente.")


def _adjuntos(c: CorreoParseado, r: ResultadoReglas) -> None:
    for a in c.adjuntos:
        partes = a.nombre.lower().split(".")
        ext = a.extension or ""
        doble = len(partes) >= 3 and partes[-2] in EXT_DOCUMENTO and ext in (EXT_PELIGROSAS | EXT_WEB | EXT_COMPRIMIDOS)
        if doble:
            r.agregar(Area.ADJUNTO, Gravedad.ALTA,
                      f"El adjunto «{a.nombre}» usa una doble extensión para disfrazarse de documento.")
        elif ext in EXT_PELIGROSAS:
            r.agregar(Area.ADJUNTO, Gravedad.ALTA,
                      f"El adjunto «{a.nombre}» es un programa o archivo que puede infectar tu equipo.")
        elif ext in EXT_WEB:
            r.agregar(Area.ADJUNTO, Gravedad.ALTA, f"El adjunto «{a.nombre}» es una página web: se usa para robar contraseñas.")
        elif ext in EXT_MACROS:
            r.agregar(Area.ADJUNTO, Gravedad.MEDIA, f"El adjunto «{a.nombre}» tiene macros: puede ejecutar programas al abrirlo.")
        elif ext in EXT_COMPRIMIDOS:
            r.agregar(Area.ADJUNTO, Gravedad.MEDIA,
                      f"El adjunto «{a.nombre}» está comprimido: puede esconder archivos peligrosos.")


def _contenido(c: CorreoParseado, r: ResultadoReglas) -> None:
    """Señales de ingeniería social. Solo explican: el riesgo del texto lo estima el modelo de contenido."""
    t = f"{c.asunto} {c.cuerpo[:6000]}"
    if _PRETEXTO_CO.search(t):
        r.agregar(Area.CONTENIDO, Gravedad.BAJA,
                  "Usa un pretexto común en fraudes en Colombia (multas, embargos, devoluciones o paquetes retenidos).")
    if _URGENCIA.search(t):
        r.agregar(Area.CONTENIDO, Gravedad.BAJA, "Te presiona con urgencia o amenazas para que actúes sin pensar.")
    if _DATOS.search(t):
        r.agregar(Area.CONTENIDO, Gravedad.BAJA, "Pide o menciona contraseñas, tarjetas o datos personales.")
    if _PREMIO.search(t):
        r.agregar(Area.CONTENIDO, Gravedad.BAJA, "Ofrece premios, regalos o dinero fácil.")


def evaluar_reglas(c: CorreoParseado, catalogo: CatalogoEntidades) -> ResultadoReglas:
    r = ResultadoReglas()
    _autenticacion(c, r)
    _remitente(c, r)
    _suplantacion(c, catalogo, r)
    _enlaces(c, catalogo, r)
    _adjuntos(c, r)
    _contenido(c, r)
    a = c.autenticacion
    r.remitente_verificado = bool(a.confiable and a.dmarc is ResultadoAuth.PASS and catalogo.duena_de(c.remitente_dominio))
    return r
