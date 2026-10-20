"""Fraude sin enlaces: correos que no traen nada «técnico» que analizar y aun así buscan dinero.

Cubre tres familias que el modelo de texto y las reglas de enlaces no ven bien:
  * Suplantación de un jefe o proveedor (BEC, «Business Email Compromise»): «¿Estás disponible?», «necesito que
    hagas una transferencia hoy, es confidencial», «cambiamos nuestra cuenta bancaria, consigna a esta nueva».
  * Tarjetas de regalo y recargas: «compra 5 tarjetas de Google Play y envíame los códigos».
  * Extorsión: «tengo un video tuyo, paga en bitcoin o lo publico».

Es un criterio experto con puntaje, documentado para la tesis: cada señal del texto suma, el contexto del remitente
(cuenta gratuita, primera vez que escribe, dominio parecido al de tu empresa, respuestas a otro dominio) suma, y el
puntaje total fija la gravedad. Una sola señal nunca basta: un proveedor real que recuerda una factura no se marca.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from centinela.dominio.correo import CorreoParseado
from centinela.dominio.dominios import CORREO_GRATUITO, dominio_parecido, dominio_registrado
from centinela.dominio.riesgo import PESO_GRAVEDAD, Area, Gravedad, Razon


class SenalFraude(StrEnum):
    PAGO = "pago"                       # pide transferir, consignar o pagar
    CAMBIO_CUENTA = "cambio_cuenta"     # avisa de una cuenta bancaria nueva para recibir pagos
    TARJETAS = "tarjetas"               # tarjetas de regalo, recargas o códigos
    CRIPTO = "cripto"                   # pago en criptomonedas
    AMENAZA = "amenaza"                 # chantaje: video, fotos, publicar, contactos
    SECRETO = "secreto"                 # «es confidencial», «no le comentes a nadie»
    URGENCIA = "urgencia"
    NO_DISPONIBLE = "no_disponible"     # «estoy en reunión», «no puedo atender llamadas»: evita que lo verifiques
    APERTURA = "apertura"               # «¿estás disponible?», «necesito un favor»
    AUTORIDAD = "autoridad"             # firma o nombre con cargo: gerente, director, CEO


_PATRONES: dict[SenalFraude, re.Pattern[str]] = {
    SenalFraude.PAGO: re.compile(
        r"(?i)\b(transferencia|transfiere|transferir|consignaci[oó]n|consigna(r|s|rle)?|(hacer|enviar|realizar) (un|el) giro|"
        r"realizar (el|un) pago|"
        r"hacer (el|un) pago|pago (urgente|pendiente)|env[ií]a(r|me)? (el )?dinero|nequi|daviplata|llave bre-?b|"
        r"cuenta de cobro|wire transfer|bank transfer|make a payment|send (the )?money)\b"),
    SenalFraude.CAMBIO_CUENTA: re.compile(
        r"(?i)\b(nueva cuenta (bancaria|de ahorros|corriente)?|cambi(o|amos|aron|ar) (de |nuestra |la )?(cuenta|datos "
        r"bancarios|informaci[oó]n bancaria)|actualiza(mos|r)? (nuestros |los )?datos bancarios|(cuenta|datos bancarios) "
        r"(anterior|antigua)(es)? (ya )?no (est[aá]|est[aá]n|es|son) (activa|v[aá]lid)|new bank account|"
        r"changed? (our|the) bank (account|details)|updated? (our )?banking details)\b"),
    SenalFraude.TARJETAS: re.compile(
        r"(?i)\b(tarjetas? (de )?regalo|gift ?cards?|c[oó]digos? (de )?(google play|itunes|apple|amazon|steam|"
        r"netflix|xbox|playstation)|tarjetas? (de )?(google play|itunes|apple|amazon|steam)|recargas? (de )?"
        r"(celular|saldo)|raspa (la tarjeta|el c[oó]digo)|scratch (the|off))\b"),
    SenalFraude.CRIPTO: re.compile(r"(?i)\b(bitcoins?|btc|usdt|criptomonedas?|cryptocurrency|billetera (de )?bitcoin|"
                                   r"bitcoin wallet|wallet address)\b"),
    SenalFraude.AMENAZA: re.compile(
        r"(?i)\b(grab[eé] (un )?video|tengo (un )?video|tengo acceso a tu (c[aá]mara|dispositivo|computador|celular)|"
        r"(enviar[eé]|mandar[eé]|publicar[eé]) (el video|las fotos|todo) a (todos )?tus contactos|"
        r"hacked your (device|computer)|recorded (a )?video of you|send (it|the video) to (all )?your contacts)\b"),
    SenalFraude.SECRETO: re.compile(
        r"(?i)\b(confidencial|no (le )?(comentes|digas|cuentes) (a nadie|nada)|entre (t[uú] y yo|nosotros)|con "
        r"(total )?discreci[oó]n|que nadie se entere|keep (this|it) (confidential|between us)|don'?t tell anyone)\b"),
    SenalFraude.URGENCIA: re.compile(
        r"(?i)\b(urgente|hoy mismo|lo (m[aá]s )?antes posible|de inmediato|inmediatamente|antes de las \d|en (la )?"
        r"pr[oó]xima hora|cuanto antes|asap|right away|immediately|as soon as possible)\b"),
    SenalFraude.NO_DISPONIBLE: re.compile(
        r"(?i)\b(estoy en (una )?reuni[oó]n|no puedo (atender|contestar|recibir) (llamadas|el tel[eé]fono)|no me "
        r"llames|estoy de viaje|estoy en un (vuelo|evento)|solo por (este medio|correo)|i'?m in a meeting|"
        r"can'?t (take|talk on the) (calls|phone))\b"),
    SenalFraude.APERTURA: re.compile(
        r"(?i)(\best[aá]s disponible\b|¿\s*est[aá] disponible\s*\?|\btienes (un )?(momento|minuto)\b|\bnecesito (que me hagas "
        r")?un favor\b|\bme puedes (hacer|ayudar con) (un favor|algo)\b|\bare you (available|free)\b|"
        r"\bi need a (quick )?favou?r\b)"),
    SenalFraude.AUTORIDAD: re.compile(
        r"(?i)\b(gerente|director(a)?|presidente|vicepresidente|ceo|cfo|jefe|jefa|rector(a)?|alcalde|gerencia "
        r"general|managing director)\b"),
}

# Cuánto pesa cada señal del texto. Las que piden dinero son las que deciden; las demás solo agravan.
PUNTOS: dict[SenalFraude, int] = {
    SenalFraude.CAMBIO_CUENTA: 3, SenalFraude.TARJETAS: 3, SenalFraude.PAGO: 1, SenalFraude.CRIPTO: 1,
    SenalFraude.AMENAZA: 2, SenalFraude.SECRETO: 1, SenalFraude.URGENCIA: 1, SenalFraude.NO_DISPONIBLE: 1,
    SenalFraude.APERTURA: 1, SenalFraude.AUTORIDAD: 1,
}
_PIDE_ALGO = {SenalFraude.PAGO, SenalFraude.CAMBIO_CUENTA, SenalFraude.TARJETAS, SenalFraude.CRIPTO, SenalFraude.APERTURA}

PUNTOS_MEDIA = 3
PUNTOS_ALTA = 4
PUNTOS_MUY_ALTA = 6
APORTE_MUY_ALTA = 0.75       # sola, lleva el correo a riesgo ALTO (≥ 0.70): reconoce el fraude aunque no haya enlaces


@dataclass(frozen=True)
class ContextoDestinatario:
    """Lo que se sabe del buzón que recibe el correo. En un .eml subido al panel no se sabe nada (None)."""
    correo: str | None = None
    remitente_conocido: bool | None = None      # ¿este remitente ya había escrito antes a este buzón?


@dataclass(frozen=True)
class EvaluacionFraude:
    senales: frozenset[SenalFraude]
    agravantes: tuple[str, ...]
    puntos: int
    razon: Razon | None


def senales_de_texto(asunto: str, cuerpo: str, remitente_nombre: str = "") -> frozenset[SenalFraude]:
    texto = f"{asunto}\n{cuerpo[:6000]}"
    encontradas = {s for s, patron in _PATRONES.items() if s is not SenalFraude.AUTORIDAD and patron.search(texto)}
    # El cargo cuenta si está en el nombre del remitente o en la firma (las últimas líneas), no en cualquier parte.
    firma = "\n".join(cuerpo.strip().splitlines()[-6:])
    if _PATRONES[SenalFraude.AUTORIDAD].search(f"{remitente_nombre}\n{firma}"):
        encontradas.add(SenalFraude.AUTORIDAD)
    return frozenset(encontradas)


def _agravantes(c: CorreoParseado, contexto: ContextoDestinatario | None) -> list[tuple[str, int]]:
    reg = dominio_registrado(c.remitente_dominio) if c.remitente_dominio else ""
    salida: list[tuple[str, int]] = []
    if contexto and contexto.correo and "@" in contexto.correo:
        propio = contexto.correo.rsplit("@", 1)[1].lower()
        if reg and propio not in CORREO_GRATUITO and dominio_parecido(reg, propio):
            salida.append((f"el remitente usa {reg}, un dominio que imita al de tu organización ({dominio_registrado(propio)})",
                           3))
    if reg in CORREO_GRATUITO:
        salida.append(("lo envía una cuenta de correo gratuita", 1))
    if c.responder_a_dominio and reg and dominio_registrado(c.responder_a_dominio) != reg:
        salida.append(("las respuestas irían a otro dominio", 1))
    if contexto and contexto.remitente_conocido is False:
        salida.append(("es la primera vez que este remitente te escribe", 1))
    return salida


def _texto(senales: frozenset[SenalFraude], agravantes: list[str], sin_enlaces: bool) -> str:
    if SenalFraude.CAMBIO_CUENTA in senales:
        base = ("Avisa de un cambio de cuenta bancaria para recibir pagos: es el fraude más común contra empresas y "
                "proveedores. Antes de pagar, confírmalo llamando a un número que ya tengas, no al del correo")
    elif SenalFraude.TARJETAS in senales:
        base = ("Pide comprar tarjetas de regalo o recargas y enviar los códigos: ningún jefe, empresa ni entidad pide "
                "pagos así")
    elif SenalFraude.AMENAZA in senales or SenalFraude.CRIPTO in senales:
        base = "Exige dinero con amenazas o en criptomonedas (extorsión). No pagues ni respondas: es un engaño masivo"
    elif SenalFraude.PAGO in senales:
        extras = [t for s, t in ((SenalFraude.URGENCIA, "con urgencia"), (SenalFraude.SECRETO, "en secreto"),
                                 (SenalFraude.NO_DISPONIBLE, "sin que puedas llamar a confirmar")) if s in senales]
        base = ("Pide una transferencia o un pago " + ", ".join(extras)).strip() + \
            ": así operan los fraudes que se hacen pasar por un jefe o un proveedor. Confírmalo por otro canal antes de pagar"
    else:
        base = ("Empieza preguntando si estás disponible para un «favor», como los fraudes que suplantan a un jefe para "
                "luego pedir dinero o tarjetas de regalo")
    detalles = list(agravantes) + (["no trae enlaces ni adjuntos, para no despertar sospechas"] if sin_enlaces else [])
    if detalles:
        base += ". Además, " + ", ".join(detalles[:2])
    return base + "."


def evaluar_fraude(c: CorreoParseado, contexto: ContextoDestinatario | None = None,
                   remitente_verificado: bool = False) -> EvaluacionFraude:
    senales = senales_de_texto(c.asunto, c.cuerpo, c.remitente_nombre)
    if not senales & _PIDE_ALGO:
        return EvaluacionFraude(senales, (), 0, None)
    agravantes = _agravantes(c, contexto)
    puntos = sum(PUNTOS[s] for s in senales) + sum(p for _, p in agravantes)
    if SenalFraude.AMENAZA in senales and SenalFraude.CRIPTO in senales:
        puntos += 2                                 # chantaje + bitcoin: extorsión típica
    if remitente_verificado:
        puntos -= 2                                 # dominio oficial verificado: hace falta mucho más para acusarlo
    textos = tuple(t for t, _ in agravantes)
    if puntos < PUNTOS_MEDIA:
        return EvaluacionFraude(senales, textos, puntos, None)
    if puntos >= PUNTOS_ALTA:
        gravedad, aporte = Gravedad.ALTA, APORTE_MUY_ALTA if puntos >= PUNTOS_MUY_ALTA else PESO_GRAVEDAD[Gravedad.ALTA]
    else:
        gravedad, aporte = Gravedad.MEDIA, PESO_GRAVEDAD[Gravedad.MEDIA]
    sin_enlaces = not c.enlaces and not c.adjuntos
    razon = Razon(Area.FRAUDE, gravedad, _texto(senales, list(textos), sin_enlaces), aporte=aporte)
    return EvaluacionFraude(senales, textos, puntos, razon)
