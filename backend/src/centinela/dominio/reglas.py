"""Reglas de seguridad explicables (criterio experto, no aprendidas). Portadas y ampliadas desde el prototipo.

Cada regla produce una Razon con un texto en español sencillo. Las reglas cubren lo que el dataset de
entrenamiento no trae (remitente, autenticación, enlaces y adjuntos) y el contexto colombiano
(entidades suplantadas y pretextos frecuentes).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from centinela.dominio.correo import Adjunto, CorreoParseado, OrigenEnlace, ResultadoAuth, SenalAdjunto
from centinela.dominio.dominios import (
    ACORTADORES,
    CORREO_GRATUITO,
    TLDS_ABUSO,
    dominio_enganoso,
    dominio_registrado,
    es_ip,
    host_de_url,
    tld,
)
from centinela.dominio.entidades import CatalogoEntidades
from centinela.dominio.fraude import ContextoDestinatario, evaluar_fraude
from centinela.dominio.riesgo import PESO_GRAVEDAD, Area, Gravedad, Razon

EXT_PELIGROSAS = frozenset({"exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "msi", "jar", "hta", "lnk", "ps1",
                            "iso", "img", "dll", "com", "pif", "wsf"})
EXT_MACROS = frozenset({"docm", "xlsm", "pptm", "xlsb", "xlam"})
EXT_COMPRIMIDOS = frozenset({"zip", "rar", "7z", "ace", "gz", "tar"})
EXT_WEB = frozenset({"html", "htm", "shtml", "xhtml"})
EXT_DOCUMENTO = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"})
# Señales inequívocas de malware (un programa disfrazado de documento, un .zip con un .exe adentro, una página que
# pide la contraseña): bastan solas para riesgo ALTO, igual que el fraude evidente sin enlaces.
APORTE_INEQUIVOCO = 0.75

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
_ESCANEAR = re.compile(r"(?i)\b(escane[ae]r?|escanea|escanee|esc[aá]nealo|esc[aá]nelo|c[oó]digo qr|scan( the)? (qr|code))\b")
_DIRECCION_EN_NOMBRE = re.compile(r"[\w.+-]+@([\w-]+\.)+[a-z]{2,}", re.I)


@dataclass
class ResultadoReglas:
    razones: list[Razon] = field(default_factory=list)
    positivas: list[str] = field(default_factory=list)
    remitente_verificado: bool = False     # dominio oficial de una entidad del catálogo + DMARC aprobado por Google

    def agregar(self, area: Area, gravedad: Gravedad, texto: str, entidad_id: int | None = None,
                aporte: float | None = None) -> None:
        self.razones.append(Razon(area, gravedad, texto, aporte=aporte or PESO_GRAVEDAD[gravedad], entidad_id=entidad_id))


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
    elif a.dkim is ResultadoAuth.NONE and a.spf is ResultadoAuth.NONE:
        # Solo si Google dijo explícitamente "none". Un resultado ausente es "desconocido", nunca señal de phishing.
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


def _qr(c: CorreoParseado, catalogo: CatalogoEntidades, r: ResultadoReglas) -> None:
    """Quishing: el enlace va dentro de una imagen con código QR para que lo abras en el celular, donde no ves la
    dirección completa y los filtros de correo no lo leen. Un QR hacia un sitio oficial (p. ej. el de la DIAN en una
    factura electrónica) o hacia el propio dominio del remitente es normal."""
    reg_remitente = dominio_registrado(c.remitente_dominio) if c.remitente_dominio else ""
    sospechosos = []
    for e in c.enlaces:
        host = host_de_url(e.url) if e.origen is OrigenEnlace.QR else ""
        if host and not catalogo.duena_de(host) and dominio_registrado(host) != reg_remitente:
            sospechosos.append((e, dominio_registrado(host)))
    if not sospechosos:
        return
    e, real = sospechosos[0]
    donde = f"la imagen «{e.fuente}»" if e.fuente else "una imagen del correo"
    texto = f"{donde[0].upper()}{donde[1:]} trae un código QR que lleva a {real}."
    t = f"{c.asunto} {c.cuerpo[:6000]}"
    if _DATOS.search(t) or _URGENCIA.search(t) or _ESCANEAR.search(t):
        r.agregar(Area.ENLACE, Gravedad.ALTA, texto + " Te pide escanearlo para «verificar» o «actualizar» datos: "
                  "es una técnica para que abras el enlace en el celular, donde es más difícil ver que es falso.")
    else:
        r.agregar(Area.ENLACE, Gravedad.MEDIA, texto + " Los códigos QR esconden la dirección real: no lo escanees "
                  "si no esperabas este correo.")


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
        un = {OrigenEnlace.QR: "El código QR", OrigenEnlace.ADJUNTO: f"Un enlace dentro de «{e.fuente or 'un adjunto'}»"}\
            .get(e.origen, "Un enlace")
        if dominio_enganoso(url, e.texto_visible):
            r.agregar(Area.ENLACE, Gravedad.ALTA, f"Un enlace dice «{e.texto_visible[:60]}» pero en realidad lleva a {real}.")
        if es_ip(host):
            r.agregar(Area.ENLACE, Gravedad.ALTA, f"{un} lleva a una dirección IP en lugar de a un sitio con nombre.")
            continue
        imitada = catalogo.mencionada_en(re.sub(r"[.\-_]", " ", host))
        if imitada and not imitada.es_oficial(host):
            r.agregar(Area.ENLACE, Gravedad.ALTA,
                      f"{un} lleva a {real}, que usa el nombre de {imitada.nombre} pero no es su sitio oficial.",
                      imitada.id)
        if "xn--" in host:
            r.agregar(Area.ENLACE, Gravedad.ALTA,
                      f"{un} usa letras de otros alfabetos para imitar un sitio conocido ({host}).")
        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            r.agregar(Area.ENLACE, Gravedad.ALTA, f"{un} usa el símbolo @ para esconder su verdadero destino.")
        if tld(real) in TLDS_ABUSO:
            r.agregar(Area.ENLACE, Gravedad.MEDIA, f"{un} lleva a {real}, una terminación muy usada en fraudes.")
        if re.search(r"\.(" + "|".join(EXT_PELIGROSAS) + r")(\?|$)", url.lower()):
            r.agregar(Area.ENLACE, Gravedad.ALTA, f"{un} descarga directamente un programa o archivo peligroso.")
        if real in ACORTADORES:
            r.agregar(Area.ENLACE, Gravedad.MEDIA, f"{un} está acortado ({real}): no se ve a dónde lleva realmente.")


_TIPO_LEGIBLE = {"ejecutable": "un programa", "html": "una página web", "svg": "una imagen con código", "zip": "un comprimido",
                 "lnk": "un acceso directo", "iso": "una imagen de disco", "pdf": "un PDF", "ole": "un documento de Office",
                 "ooxml": "un documento de Office", "rar": "un comprimido", "7z": "un comprimido", "jar": "un programa Java"}


def riesgo_adjunto(a: Adjunto) -> tuple[Gravedad, str, float | None] | None:
    """El riesgo de un adjunto, por qué y su peso (None: el de su gravedad), mirando su nombre Y su contenido real.
    Lo más grave primero."""
    partes = a.nombre.lower().split(".")
    ext = a.extension or ""
    s = set(a.senales)
    real = _TIPO_LEGIBLE.get(a.tipo_real or "", a.tipo_real or "otra cosa")
    if SenalAdjunto.EJECUTABLE in s and ext not in EXT_PELIGROSAS:
        return Gravedad.ALTA, (f"El adjunto «{a.nombre}» es en realidad un programa, aunque su nombre diga otra cosa. "
                               "Abrirlo puede infectar tu equipo."), APORTE_INEQUIVOCO
    if len(partes) >= 3 and partes[-2] in EXT_DOCUMENTO and ext in (EXT_PELIGROSAS | EXT_WEB | EXT_COMPRIMIDOS):
        return Gravedad.ALTA, f"El adjunto «{a.nombre}» usa una doble extensión para disfrazarse de documento.", APORTE_INEQUIVOCO
    if ext in EXT_PELIGROSAS or SenalAdjunto.EJECUTABLE in s:
        return Gravedad.ALTA, f"El adjunto «{a.nombre}» es un programa o archivo que puede infectar tu equipo.", None
    if SenalAdjunto.COMPRIMIDO_PELIGROSO in s:
        peligroso = next((n for n in a.contenido if n.rsplit(".", 1)[-1].lower() in EXT_PELIGROSAS | EXT_WEB), None)
        dentro = f"«{peligroso}», " if peligroso else ""
        return Gravedad.ALTA, (f"El comprimido «{a.nombre}» trae adentro {dentro}un programa o página que puede "
                               "infectar tu equipo o robar tus contraseñas."), APORTE_INEQUIVOCO
    if SenalAdjunto.FORMULARIO in s:
        return Gravedad.ALTA, (f"El adjunto «{a.nombre}» es una página que pide usuario y contraseña: se usa para "
                               "robarlos sin que se vea un enlace en el correo."), APORTE_INEQUIVOCO
    if SenalAdjunto.SCRIPT in s:
        return Gravedad.ALTA, (f"El adjunto «{a.nombre}» trae código que se ejecuta al abrirlo en el navegador: "
                               "puede llevarte a una página falsa."), None
    if SenalAdjunto.DISFRAZADO in s:
        return Gravedad.ALTA, f"El adjunto «{a.nombre}» dice ser .{ext}, pero en realidad es {real}.", APORTE_INEQUIVOCO
    if SenalAdjunto.PDF_JAVASCRIPT in s:
        return Gravedad.ALTA, (f"El PDF «{a.nombre}» trae código o la orden de abrir programas: un PDF normal "
                               "(una factura, un extracto) no lo necesita."), None
    if SenalAdjunto.PLANTILLA_REMOTA in s:
        return Gravedad.ALTA, (f"El documento «{a.nombre}» descarga contenido de internet al abrirlo, una técnica "
                               "para instalar programas maliciosos."), None
    if ext in EXT_WEB:
        return Gravedad.ALTA, f"El adjunto «{a.nombre}» es una página web: se usa para robar contraseñas.", None
    if ext in EXT_MACROS or SenalAdjunto.MACROS in s:
        return Gravedad.MEDIA, f"El adjunto «{a.nombre}» tiene macros: puede ejecutar programas al abrirlo.", None
    if SenalAdjunto.PDF_ARCHIVO_OCULTO in s:
        return Gravedad.MEDIA, f"El PDF «{a.nombre}» lleva otros archivos escondidos adentro.", None
    if SenalAdjunto.CIFRADO in s:
        return Gravedad.MEDIA, (f"El archivo «{a.nombre}» está protegido con clave: así los antivirus no pueden "
                                "revisarlo. Si no lo esperabas, no lo abras."), None
    if ext in EXT_COMPRIMIDOS:
        return Gravedad.MEDIA, f"El adjunto «{a.nombre}» está comprimido: puede esconder archivos peligrosos.", None
    return None


def _adjuntos(c: CorreoParseado, r: ResultadoReglas) -> None:
    for a in c.adjuntos:
        if riesgo := riesgo_adjunto(a):
            gravedad, texto, aporte = riesgo
            r.agregar(Area.ADJUNTO, gravedad, texto, aporte=aporte)


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


def evaluar_reglas(c: CorreoParseado, catalogo: CatalogoEntidades,
                   contexto: ContextoDestinatario | None = None) -> ResultadoReglas:
    r = ResultadoReglas()
    _autenticacion(c, r)
    _remitente(c, r)
    _suplantacion(c, catalogo, r)
    _qr(c, catalogo, r)
    _enlaces(c, catalogo, r)
    _adjuntos(c, r)
    _contenido(c, r)
    a = c.autenticacion
    r.remitente_verificado = bool(a.confiable and a.dmarc is ResultadoAuth.PASS and catalogo.duena_de(c.remitente_dominio))
    if (fraude := evaluar_fraude(c, contexto, r.remitente_verificado).razon) is not None:
        r.razones.append(fraude)
    return r
