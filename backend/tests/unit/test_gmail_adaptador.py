"""Adaptador real de Gmail contra respuestas HTTP simuladas (httpx.MockTransport): sin red, sin cuenta de Google."""
import base64
import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from centinela.adaptadores.salida.gmail import ALCANCE_GMAIL, AutorizacionGoogle, ProveedorGmail
from centinela.aplicacion.puertos import AccesoCorreoRevocado, ErrorProveedorCorreo, HistorialExpirado, PermisoInsuficiente
from tests.fakes import RelojFijo


class GoogleSimulado:
    def __init__(self):
        self.peticiones: list[httpx.Request] = []
        self.rutas = {}

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.peticiones.append(req)
        clave = (req.method, req.url.path)
        manejador = self.rutas.get(clave)
        if manejador is None:
            return httpx.Response(404, json={"error": {"code": 404}})
        return manejador(req)

    def cliente(self):
        return httpx.Client(transport=httpx.MockTransport(self))


def token_ok(_req):
    return httpx.Response(200, json={"access_token": "at-1", "expires_in": 3600})


def test_url_de_autorizacion_pide_un_solo_permiso_con_pkce():
    a = AutorizacionGoogle("cid", "secreto", "http://localhost:8000/api/gmail/callback", httpx.Client())
    q = parse_qs(urlparse(a.url_autorizacion("estado-1", "reto-1")).query)
    assert q["scope"] == [ALCANCE_GMAIL] and q["code_challenge_method"] == ["S256"]
    assert q["access_type"] == ["offline"] and q["state"] == ["estado-1"]


def test_intercambio_rechaza_si_no_se_concedio_el_permiso():
    g = GoogleSimulado()
    g.rutas[("POST", "/token")] = lambda r: httpx.Response(200, json={
        "access_token": "a", "refresh_token": "r", "scope": "openid email"})
    g.rutas[("POST", "/revoke")] = lambda r: httpx.Response(200)
    a = AutorizacionGoogle("cid", "s", "http://x", g.cliente())
    with pytest.raises(PermisoInsuficiente):
        a.intercambiar_codigo("codigo", "verificador")
    assert any(p.url.path == "/revoke" for p in g.peticiones)       # no deja permisos colgando


def test_intercambio_envia_el_verificador_pkce():
    g = GoogleSimulado()
    g.rutas[("POST", "/token")] = lambda r: httpx.Response(200, json={
        "access_token": "a", "refresh_token": "r-1", "scope": ALCANCE_GMAIL})
    cred = AutorizacionGoogle("cid", "s", "http://x", g.cliente()).intercambiar_codigo("codigo", "verif")
    assert cred.refresh_token == "r-1"
    assert parse_qs(g.peticiones[0].content.decode())["code_verifier"] == ["verif"]


def test_token_revocado_por_el_usuario():
    g = GoogleSimulado()
    g.rutas[("POST", "/token")] = lambda r: httpx.Response(400, json={"error": "invalid_grant"})
    cliente = ProveedorGmail("cid", "s", g.cliente(), RelojFijo()).abrir("rt")
    with pytest.raises(AccesoCorreoRevocado):
        cliente.perfil()


def test_historial_paginado_y_expirado():
    g = GoogleSimulado()
    g.rutas[("POST", "/token")] = token_ok

    def historial(req):
        if req.url.params.get("startHistoryId") == "1":
            return httpx.Response(404, json={"error": {"code": 404}})
        if "pageToken" not in req.url.params:
            return httpx.Response(200, json={"history": [{"messagesAdded": [{"message": {"id": "a"}}]}],
                                             "historyId": "20", "nextPageToken": "p2"})
        return httpx.Response(200, json={"history": [{"messagesAdded": [{"message": {"id": "b"}},
                                                                        {"message": {"id": "a"}}]}], "historyId": "25"})
    g.rutas[("GET", "/gmail/v1/users/me/history")] = historial
    cliente = ProveedorGmail("cid", "s", g.cliente(), RelojFijo()).abrir("rt")
    cambios = cliente.nuevos_desde(10)
    assert cambios.ids_nuevos == ["a", "b"] and cambios.history_id == 25
    with pytest.raises(HistorialExpirado):
        cliente.nuevos_desde(1)
    assert sum(p.url.path == "/token" for p in g.peticiones) == 1      # el token de acceso se reutiliza


def test_descarga_mensaje_y_reintenta_si_el_token_expiro():
    g = GoogleSimulado()
    g.rutas[("POST", "/token")] = token_ok
    llamadas = {"n": 0}
    crudo = b"From: a@b.co\r\nSubject: hola\r\n\r\ncuerpo"

    def mensaje(req):
        llamadas["n"] += 1
        if llamadas["n"] == 1:
            return httpx.Response(401)
        if req.url.params["format"] == "minimal":
            return httpx.Response(200, json={"id": "m1", "threadId": "t1", "labelIds": ["INBOX"],
                                             "sizeEstimate": len(crudo), "internalDate": "1792000000000"})
        return httpx.Response(200, json={"raw": base64.urlsafe_b64encode(crudo).decode().rstrip("=")})
    g.rutas[("GET", "/gmail/v1/users/me/messages/m1")] = mensaje
    m = ProveedorGmail("cid", "s", g.cliente(), RelojFijo()).abrir("rt").obtener("m1")
    assert m.crudo == crudo and m.hilo_id == "t1" and m.etiquetas == ["INBOX"]


def test_cuota_excedida_es_error_pasajero():
    g = GoogleSimulado()
    g.rutas[("POST", "/token")] = token_ok
    g.rutas[("GET", "/gmail/v1/users/me/profile")] = lambda r: httpx.Response(429)
    with pytest.raises(ErrorProveedorCorreo):
        ProveedorGmail("cid", "s", g.cliente(), RelojFijo()).abrir("rt").perfil()


def test_crea_las_etiquetas_que_faltan():
    g = GoogleSimulado()
    g.rutas[("POST", "/token")] = token_ok
    g.rutas[("GET", "/gmail/v1/users/me/labels")] = lambda r: httpx.Response(200, json={"labels": [
        {"id": "L1", "name": "Centinela/Cuarentena"}, {"id": "INBOX", "name": "INBOX"}]})
    g.rutas[("POST", "/gmail/v1/users/me/labels")] = lambda r: httpx.Response(200, json={
        "id": "L2", "name": json.loads(r.content)["name"]})
    e = ProveedorGmail("cid", "s", g.cliente(), RelojFijo()).abrir("rt").asegurar_etiquetas()
    assert (e.cuarentena_id, e.sospechoso_id) == ("L1", "L2")
