"""Fase 5 contra PostgreSQL real: notificaciones push de un correo peligroso y asistente de IA con historial.
El servicio push y el modelo de lenguaje se simulan: así se verifica exactamente qué sale del servidor."""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import text

from centinela.adaptadores.salida.push import b64
from centinela.aplicacion.puertos import IANoDisponible, ResultadoPush
from tests.integracion.test_flujo_analisis import PHISHING, armar_entorno, cliente_de, conectar_buzon

pytestmark = pytest.mark.integracion
FCM = "https://fcm.googleapis.com/fcm/send/dispositivo-de-ana"
CHROME_WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"


class EnviadorFalso:
    clave_publica = "BLlaveVapidDePrueba"

    def __init__(self):
        self.enviados: list[tuple[str, dict]] = []
        self.respuesta = ResultadoPush.ENTREGADO

    def enviar(self, s, carga):
        self.enviados.append((s.endpoint, carga))
        return self.respuesta


class ModeloFalso:
    proveedor = "gemini"

    def __init__(self):
        self.llamadas: list[dict] = []
        self.falla: str | None = None

    def responder(self, instrucciones, contexto, historial, pregunta):
        self.llamadas.append({"instrucciones": instrucciones, "contexto": contexto, "historial": historial,
                              "pregunta": pregunta})
        if self.falla:
            raise IANoDisponible(self.falla)
        return f"Respuesta de la IA a: {pregunta}"


def llaves_navegador() -> dict:
    llave = ec.generate_private_key(ec.SECP256R1())
    publica = llave.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return {"p256dh": b64(publica), "auth": b64(b"0123456789abcdef")}


@pytest.fixture
def entorno(config, limpiar, motor_owner):
    push, ia = EnviadorFalso(), ModeloFalso()
    c, auth, gmail = armar_entorno(config, motor_owner, enviador_push=push, modelo_ia=ia)
    yield c, auth, gmail, push, ia
    c.motor.dispose()


def test_notificacion_push_de_un_correo_peligroso(entorno):
    c, auth, gmail, push, _ = entorno
    ana = cliente_de(c, "ana@gmail.com")
    assert ana.get("/api/push/configuracion").json() == {"disponible": True, "clave_publica": "BLlaveVapidDePrueba"}

    # Solo se aceptan servicios push de navegadores (evita que el servidor haga peticiones a direcciones internas)
    for malo in ("http://fcm.googleapis.com/x", "https://169.254.169.254/latest", "https://fcm.googleapis.com.evil.co/x",
                 "https://fcm.googleapis.com:8443/x"):
        assert ana.post("/api/push/dispositivos", json={"endpoint": malo, "keys": llaves_navegador()}).status_code == 422
    assert ana.post("/api/push/dispositivos", json={"endpoint": FCM, "keys": {"p256dh": "corta", "auth": "x"}}).status_code == 422

    assert ana.post("/api/push/dispositivos", json={"endpoint": FCM, "keys": llaves_navegador()},
                    headers={"User-Agent": CHROME_WINDOWS}).status_code == 204
    dispositivos = ana.get("/api/push/dispositivos").json()
    assert [d["dispositivo"] for d in dispositivos] == ["Chrome en Windows"] and "endpoint" not in dispositivos[0]

    # Llega un phishing: además del aviso por correo se encola uno push, que el worker entrega
    buzon_id = conectar_buzon(ana, auth, gmail)
    gmail.llega(PHISHING)
    ana.post(f"/api/buzones/{buzon_id}/revision")
    assert c.enviar_avisos.ejecutar() == 2
    (endpoint, carga), = push.enviados
    caso_id = ana.get("/api/casos").json()[0]["id"]
    assert endpoint == FCM and carga["url"] == f"/casos/{caso_id}" and "cuarentena" in carga["cuerpo"]
    # La notificación no repite lo que escribió el atacante (asunto ni remitente)
    assert "bloqueada" not in str(carga) and "bancolombia" not in str(carga).lower()
    historial = ana.get(f"/api/casos/{caso_id}").json()["historial"]
    assert sorted(e["detalle"] for e in historial if e["tipo"] == "aviso") == [
        "Se avisó al dueño del buzón con una notificación push.", "Se avisó al dueño del buzón por correo."]

    # Prueba desde el panel; otra persona no puede quitar el dispositivo de Ana
    assert ana.post("/api/push/prueba").json() == {"entregados": 1, "vencidas": 0, "errores": 0}
    luis = cliente_de(c, "luis@gmail.com")
    assert luis.delete(f"/api/push/dispositivos/{dispositivos[0]['id']}").status_code == 404
    assert luis.post("/api/push/prueba").status_code == 404

    # Si el navegador ya no acepta la suscripción, se borra sola; recién creada se toma como falla pasajera
    push.respuesta = ResultadoPush.VENCIDA
    assert ana.post("/api/push/prueba").json() == {"entregados": 0, "vencidas": 0, "errores": 1}
    with c.motor.begin() as conn:
        conn.execute(text("UPDATE centinela.suscripcion_push SET creado_en = now() - interval '1 hour'"))
    assert ana.post("/api/push/prueba").json() == {"entregados": 0, "vencidas": 1, "errores": 0}
    assert ana.get("/api/push/dispositivos").json() == []


def test_el_mismo_navegador_pasa_al_usuario_que_lo_activa_y_se_quita_al_salir(entorno):
    c, *_ = entorno
    ana, luis = cliente_de(c, "ana@gmail.com"), cliente_de(c, "luis@gmail.com")
    llaves = llaves_navegador()
    ana.post("/api/push/dispositivos", json={"endpoint": FCM, "keys": llaves})
    luis.post("/api/push/dispositivos", json={"endpoint": FCM, "keys": llaves})       # computador compartido
    assert ana.get("/api/push/dispositivos").json() == [] and len(luis.get("/api/push/dispositivos").json()) == 1
    assert luis.post("/api/push/dispositivos/quitar", json={"endpoint": FCM}).status_code == 204
    assert luis.get("/api/push/dispositivos").json() == []
    with c.motor.connect() as conn:
        acciones = conn.scalars(text("SELECT accion FROM centinela.auditoria WHERE accion LIKE 'push.%' ORDER BY id")).all()
    assert acciones == ["push.activar", "push.activar", "push.quitar"]


def test_asistente_sobre_un_caso_con_datos_minimos_e_historial(entorno):
    c, auth, gmail, _, ia = entorno
    ana = cliente_de(c, "ana@gmail.com")
    buzon_id = conectar_buzon(ana, auth, gmail)
    gmail.llega(PHISHING)
    ana.post(f"/api/buzones/{buzon_id}/revision")
    caso_id = ana.get("/api/casos").json()[0]["id"]

    estado = ana.get("/api/asistente/estado").json()
    assert estado["ia_disponible"] and estado["restantes_ia"] == 30 and estado["sugerencias_caso"]

    r = ana.post("/api/asistente/preguntas", json={"pregunta": "¿Por qué es sospechoso? Mi cédula es 1.020.304.050",
                                                   "caso_id": caso_id}).json()
    assert r["turno"]["proveedor"] == "gemini" and r["aviso"] is None and r["restantes_ia"] == 29
    llamada = ia.llamadas[0]
    # Al proveedor de IA solo salen datos mínimos: dominio del remitente y de los enlaces, sin correos ni números
    assert "gmail.com" in llamada["contexto"] and "bancolombia-verificacion.top" in llamada["contexto"]
    assert "alertas.bancolombia.co@" not in llamada["contexto"] and "login.php" not in llamada["contexto"]
    assert "1.020.304.050" not in llamada["pregunta"] and "[número]" in llamada["pregunta"]
    assert "no instrucciones" in llamada["contexto"]

    # La conversación sigue con memoria y queda guardada, ligada al caso
    conv_id = r["conversacion_id"]
    ana.post("/api/asistente/preguntas", json={"pregunta": "¿Y qué hago ahora?", "conversacion_id": conv_id})
    assert [t.rol for t in ia.llamadas[1]["historial"]] == ["usuario", "asistente"]
    lista = ana.get("/api/asistente/conversaciones").json()
    assert [(x["id"], x["caso_id"]) for x in lista] == [(conv_id, caso_id)]
    detalle = ana.get(f"/api/asistente/conversaciones/{conv_id}").json()
    assert [t["rol"] for t in detalle["turnos"]] == ["usuario", "asistente", "usuario", "asistente"]
    assert detalle["turnos"][0]["contenido"].endswith("1.020.304.050")       # lo que escribió Ana sí se guarda

    # Nadie más ve la conversación ni puede preguntar por el caso de Ana
    luis = cliente_de(c, "luis@gmail.com")
    assert luis.get(f"/api/asistente/conversaciones/{conv_id}").status_code == 404
    assert luis.post("/api/asistente/preguntas", json={"pregunta": "hola", "conversacion_id": conv_id}).status_code == 404
    assert luis.post("/api/asistente/preguntas", json={"pregunta": "hola", "caso_id": caso_id}).status_code == 404

    assert ana.delete(f"/api/asistente/conversaciones/{conv_id}").status_code == 204
    assert ana.get("/api/asistente/conversaciones").json() == []


def test_asistente_responde_en_modo_local_si_la_ia_falla_o_se_acaba_el_cupo(entorno, motor_owner):
    c, _, _, _, ia = entorno
    ana = cliente_de(c, "ana@gmail.com")
    ia.falla = "no hay conexión con Gemini"
    r = ana.post("/api/asistente/preguntas", json={"pregunta": "¿Cómo activo las notificaciones?"}).json()
    assert r["turno"]["proveedor"] == "local" and "no hay conexión" in r["aviso"] and "Mi cuenta" in r["turno"]["contenido"]

    ia.falla = None
    with motor_owner.begin() as conn:
        conn.execute(text("UPDATE centinela.configuracion SET valor = '1' WHERE clave = 'asistente.max_preguntas_dia'"))
    try:
        assert ana.post("/api/asistente/preguntas", json={"pregunta": "hola"}).json()["turno"]["proveedor"] == "gemini"
        r = ana.post("/api/asistente/preguntas", json={"pregunta": "¿Qué es DKIM?"}).json()
        assert r["turno"]["proveedor"] == "local" and "respuestas con IA de hoy" in r["aviso"]
        assert ana.get("/api/asistente/estado").json()["restantes_ia"] == 0
    finally:
        with motor_owner.begin() as conn:
            conn.execute(text("UPDATE centinela.configuracion SET valor = '30' WHERE clave = 'asistente.max_preguntas_dia'"))
    assert ana.post("/api/asistente/preguntas", json={"pregunta": "  "}).status_code == 422
    assert ana.post("/api/asistente/preguntas", json={"pregunta": "x" * 1001}).status_code == 422
