"""Piezas puras de la Fase 5: cifrado Web Push, VAPID, servicios push permitidos, Gemini y el modo local."""
from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from centinela.adaptadores.salida.gemini import AsistenteGemini
from centinela.adaptadores.salida.push import (
    EnviadorWebPush,
    b64,
    carga_de_aviso,
    cifrar,
    desde_b64,
    generar_llaves_vapid,
)
from centinela.aplicacion.guia_asistente import PASOS_SI_CAI, anonimizar, responder_local
from centinela.aplicacion.puertos import DatosAviso, IANoDisponible, ResultadoPush, SuscripcionPush, TurnoIA
from centinela.dominio.errores import DatoInvalido
from centinela.dominio.notificaciones import nombre_dispositivo, validar_endpoint
from tests.fakes import RelojFijo


def test_cifrado_web_push_coincide_con_el_vector_del_rfc_8291():
    """Apéndice A del RFC 8291: con las mismas llaves y sal, el resultado debe ser idéntico byte a byte."""
    efimera = ec.derive_private_key(int.from_bytes(desde_b64("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"), "big"),
                                    ec.SECP256R1())
    cuerpo = cifrar(b"When I grow up, I want to be a watermelon",
                    "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
                    "BTBZMqHH6r4Tts7J_aSIgg", sal=desde_b64("DGv6ra1nlYgDCS1FRnbzlw"), efimera=efimera)
    assert b64(cuerpo) == (
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK"
        "6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN")


def _suscripcion(endpoint="https://fcm.googleapis.com/fcm/send/abc") -> SuscripcionPush:
    _, publica = generar_llaves_vapid()          # sirve como llave del «navegador»
    return SuscripcionPush(1, 1, endpoint, publica, b64(b"0123456789abcdef"))


def test_envio_push_firma_vapid_y_clasifica_las_respuestas():
    privada, publica = generar_llaves_vapid()
    recibidas: list[httpx.Request] = []
    respuesta = {"codigo": 201}

    def servicio(req: httpx.Request) -> httpx.Response:
        recibidas.append(req)
        return httpx.Response(respuesta["codigo"])

    reloj = RelojFijo(datetime(2026, 10, 19, 12, 0, tzinfo=UTC))
    enviador = EnviadorWebPush(privada, "mailto:admin@centinela.co", httpx.Client(transport=httpx.MockTransport(servicio)),
                               reloj)
    assert enviador.clave_publica == publica
    assert enviador.enviar(_suscripcion(), {"titulo": "x"}) is ResultadoPush.ENTREGADO
    req = recibidas[0]
    assert req.headers["content-encoding"] == "aes128gcm" and req.headers["ttl"] == "86400"
    token = req.headers["authorization"].removeprefix("vapid t=").split(",")[0]
    assert req.headers["authorization"].endswith(f"k={publica}")
    llave = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), desde_b64(publica))
    reclamos = jwt.decode(token, llave, algorithms=["ES256"], audience="https://fcm.googleapis.com",
                          options={"verify_exp": False})
    assert reclamos["sub"] == "mailto:admin@centinela.co"
    assert 0 < reclamos["exp"] - reloj.ahora().timestamp() <= 24 * 3600          # el estándar exige ≤ 24 h
    assert b"titulo" not in req.content                                           # viaja cifrado

    for codigo, esperado in ((410, ResultadoPush.VENCIDA), (404, ResultadoPush.VENCIDA), (500, ResultadoPush.ERROR),
                             (429, ResultadoPush.ERROR)):
        respuesta["codigo"] = codigo
        assert enviador.enviar(_suscripcion(), {}) is esperado


@pytest.mark.parametrize("endpoint", [
    "https://fcm.googleapis.com/fcm/send/abc", "https://updates.push.services.mozilla.com/wpush/v2/abc",
    "https://web.push.apple.com/QGx", "https://wns2-by3p.notify.windows.com/w/?token=abc"])
def test_servicios_push_permitidos(endpoint):
    assert validar_endpoint(endpoint) == endpoint


@pytest.mark.parametrize("endpoint", [
    "http://fcm.googleapis.com/x", "https://localhost/x", "https://10.0.0.5/x", "https://evil.co/fcm.googleapis.com",
    "https://fcm.googleapis.com.evil.co/x", "https://fcm.googleapis.com:8443/x", "https://user@fcm.googleapis.com/x",
    "https://push.services.mozilla.com.evil.co/x", "javascript:alert(1)"])
def test_servicios_push_rechazados(endpoint):
    with pytest.raises(DatoInvalido):
        validar_endpoint(endpoint)


def test_nombre_del_dispositivo():
    assert nombre_dispositivo("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
                              "Version/18.0 Safari/605.1.15") == "Safari en macOS"
    assert nombre_dispositivo("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/141.0 Mobile Safari/537.36") \
        == "Chrome en Android"
    assert nombre_dispositivo("Mozilla/5.0 (Windows NT 10.0) Chrome/141.0 Safari/537.36 Edg/141.0") == "Edge en Windows"
    assert nombre_dispositivo(None) == "Navegador"


def test_la_notificacion_no_incluye_lo_que_escribio_el_atacante():
    d = DatosAviso(destinatario="ana@gmail.com", nivel="alto", remitente="DIAN <dian@evil.co>",
                   asunto="Llame ya al 3001234567", resumen="r", razones=["x"], accion="a", caso_id=7, en_cuarentena=True)
    carga = carga_de_aviso(d)
    assert carga["url"] == "/casos/7" and "cuarentena" in carga["cuerpo"]
    assert "3001234567" not in json.dumps(carga) and "evil" not in json.dumps(carga)


def test_anonimizar_quita_correos_enlaces_y_numeros():
    t = anonimizar("Escribe a pagos@banco-falso.co o entra a https://banco-falso.co/login?id=9 con tu cédula 1.020.304.050")
    assert t == ("Escribe a [correo]@banco-falso.co o entra a [enlace a banco-falso.co] con tu cédula [número]")


def test_modo_local_responde_sobre_el_caso_y_sobre_el_panel():
    caso = {"nivel": "alto", "probabilidad": "93 %", "razones": ["Suplanta a Bancolombia"], "dominio_remitente": "evil.co",
            "spf": "fail", "dkim": None, "dmarc": "fail", "enlaces": [{"dominio": "evil.co", "enganoso": True}]}
    assert "Suplanta a Bancolombia" in responder_local("¿por qué lo marcaron?", caso)
    assert responder_local("Ya le di clic al enlace", caso) == PASOS_SI_CAI
    assert "SPF: fail" in responder_local("¿qué significa DKIM?", caso)
    assert "evil.co" in responder_local("¿cómo sé si es legítimo?", caso)
    assert "Conectar Gmail" in responder_local("cómo conecto mi gmail", None)
    assert "Mi cuenta" in responder_local("quiero notificaciones en el celular", None)
    assert "No entendí" in responder_local("asdfgh", None)
    assert "tarjetas de regalo" in responder_local("Mi jefe me pide comprar tarjetas de regalo, ¿qué hago?", None)
    assert "código QR" in responder_local("¿Es peligroso escanear un QR de un correo?", None)
    assert "Reportes" in responder_local("¿Cómo descargo un reporte en Excel?", None)
    assert "No abras" in responder_local("¿Qué hago?", None)


def _gemini(respuestas: list[httpx.Response]) -> tuple[AsistenteGemini, list[httpx.Request]]:
    peticiones: list[httpx.Request] = []

    def api(req: httpx.Request) -> httpx.Response:
        peticiones.append(req)
        return respuestas.pop(0)

    return AsistenteGemini("clave", "gemini-flash-latest", httpx.Client(transport=httpx.MockTransport(api))), peticiones


def _texto(t: str) -> httpx.Response:
    return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "pensando", "thought": True},
                                                                          {"text": t}]}}]})


def test_gemini_envia_instrucciones_contexto_e_historial():
    ia, peticiones = _gemini([_texto("Hola 👋")])
    assert ia.responder("REGLAS", "DATOS", [TurnoIA("usuario", "a"), TurnoIA("asistente", "b")], "¿y ahora?") == "Hola 👋"
    cuerpo = json.loads(peticiones[0].content)
    assert peticiones[0].headers["x-goog-api-key"] == "clave"
    assert cuerpo["system_instruction"]["parts"][0]["text"] == "REGLAS"
    assert [c["role"] for c in cuerpo["contents"]] == ["user", "model", "user", "model", "user"]
    assert cuerpo["generationConfig"]["thinkingConfig"] == {"thinkingBudget": 0}


def test_gemini_reintenta_y_traduce_errores():
    ia, peticiones = _gemini([httpx.Response(400), _texto("ok")])         # el modelo no acepta thinkingConfig
    assert ia.responder("", "", [], "?") == "ok" and "thinkingConfig" not in json.loads(peticiones[1].content)["generationConfig"]
    ia, peticiones = _gemini([httpx.Response(404), _texto("respaldo")])   # modelo retirado: usa el de respaldo
    assert ia.responder("", "", [], "?") == "respaldo" and "gemini-flash-lite-latest" in str(peticiones[1].url)
    for estado, motivo in ((429, "límite"), (403, "clave"), (500, "error 500")):
        ia, _ = _gemini([httpx.Response(estado)])
        with pytest.raises(IANoDisponible, match=motivo):
            ia.responder("", "", [], "?")
