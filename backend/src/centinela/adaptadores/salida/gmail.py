"""Adaptadores de Gmail: OAuth2 con PKCE y la API REST de Gmail, usando httpx (sin SDK de Google).

Permiso único que se pide: gmail.modify (leer, poner y quitar etiquetas, insertar avisos). Nunca se borra un correo.
Endpoints: https://developers.google.com/gmail/api/reference/rest
"""
from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

import httpx

from centinela.aplicacion.puertos import (
    AccesoCorreoRevocado,
    CambiosBuzon,
    CredencialCorreo,
    ErrorProveedorCorreo,
    HistorialExpirado,
    MensajeCrudo,
    MensajeNoDisponible,
    PerfilBuzon,
    PermisoInsuficiente,
    Reloj,
    Vigilancia,
)
from centinela.dominio.buzon import EtiquetasCentinela

ALCANCE_GMAIL = "https://www.googleapis.com/auth/gmail.modify"
URL_AUTORIZACION = "https://accounts.google.com/o/oauth2/v2/auth"
URL_TOKEN = "https://oauth2.googleapis.com/token"  # noqa: S105 - es una URL pública, no un secreto
URL_REVOCAR = "https://oauth2.googleapis.com/revoke"
URL_API = "https://gmail.googleapis.com/gmail/v1/users/me"
ETIQUETA_CUARENTENA = "Centinela/Cuarentena"
ETIQUETA_SOSPECHOSO = "Centinela/Sospechoso"
MAX_BYTES_MENSAJE = 10_000_000


def _b64url_decodificar(texto: str) -> bytes:
    return base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4))


def _error_oauth(r: httpx.Response) -> str:
    try:
        return r.json().get("error", "")
    except ValueError:
        return ""


class AutorizacionGoogle:
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str, http: httpx.Client):
        self._id, self._secreto, self._redirect, self._http = client_id, client_secret, redirect_uri, http

    def url_autorizacion(self, estado: str, reto_pkce: str) -> str:
        return URL_AUTORIZACION + "?" + urlencode({
            "client_id": self._id, "redirect_uri": self._redirect, "response_type": "code",
            "scope": ALCANCE_GMAIL, "access_type": "offline", "prompt": "consent",
            "state": estado, "code_challenge": reto_pkce, "code_challenge_method": "S256",
        })

    def intercambiar_codigo(self, codigo: str, verificador_pkce: str) -> CredencialCorreo:
        try:
            r = self._http.post(URL_TOKEN, data={
                "grant_type": "authorization_code", "code": codigo, "redirect_uri": self._redirect,
                "client_id": self._id, "client_secret": self._secreto, "code_verifier": verificador_pkce})
        except httpx.HTTPError as e:
            raise ErrorProveedorCorreo("No hubo respuesta de Google.") from e
        if r.status_code != 200:
            raise ErrorProveedorCorreo(f"Google rechazó el código de autorización ({_error_oauth(r) or r.status_code}).")
        datos = r.json()
        alcances = datos.get("scope", "").split()
        if ALCANCE_GMAIL not in alcances:
            if datos.get("refresh_token") or datos.get("access_token"):
                self.revocar(datos.get("refresh_token") or datos["access_token"])
            raise PermisoInsuficiente()
        if not datos.get("refresh_token"):
            raise ErrorProveedorCorreo("Google no entregó un permiso permanente.")
        return CredencialCorreo(refresh_token=datos["refresh_token"], alcances=alcances)

    def revocar(self, refresh_token: str) -> None:
        try:
            self._http.post(URL_REVOCAR, data={"token": refresh_token})
        except httpx.HTTPError as e:
            raise ErrorProveedorCorreo("No se pudo revocar el permiso en Google.") from e


class ProveedorGmail:
    """Fábrica de clientes por buzón. Guarda en memoria los tokens de acceso (duran ~1 hora)."""

    def __init__(self, client_id: str, client_secret: str, http: httpx.Client, reloj: Reloj):
        self._id, self._secreto, self._http, self._reloj = client_id, client_secret, http, reloj
        self._cache: dict[str, tuple[str, datetime]] = {}

    def abrir(self, refresh_token: str) -> ClienteGmail:
        return ClienteGmail(self, refresh_token)

    def token_acceso(self, refresh_token: str, forzar: bool = False) -> str:
        llave = hashlib.sha256(refresh_token.encode()).hexdigest()
        ahora = self._reloj.ahora()
        guardado = self._cache.get(llave)
        if guardado and not forzar and guardado[1] > ahora + timedelta(seconds=60):
            return guardado[0]
        try:
            r = self._http.post(URL_TOKEN, data={"grant_type": "refresh_token", "refresh_token": refresh_token,
                                                 "client_id": self._id, "client_secret": self._secreto})
        except httpx.HTTPError as e:
            raise ErrorProveedorCorreo("No hubo respuesta de Google.") from e
        if r.status_code in (400, 401) and _error_oauth(r) in ("invalid_grant", "unauthorized_client"):
            self._cache.pop(llave, None)
            raise AccesoCorreoRevocado()
        if r.status_code != 200:
            raise ErrorProveedorCorreo(f"Google no renovó el acceso (HTTP {r.status_code}).")
        datos = r.json()
        self._cache[llave] = (datos["access_token"], ahora + timedelta(seconds=int(datos.get("expires_in", 3600))))
        return datos["access_token"]

    def solicitar(self, refresh_token: str, metodo: str, ruta: str, *, revisar_403: bool = True, **kw) -> httpx.Response:
        for intento in range(2):
            token = self.token_acceso(refresh_token, forzar=intento > 0)
            try:
                r = self._http.request(metodo, URL_API + ruta, headers={"Authorization": f"Bearer {token}"}, **kw)
            except httpx.HTTPError as e:
                raise ErrorProveedorCorreo("No hubo respuesta de Gmail.") from e
            if r.status_code != 401:
                break
        if r.status_code == 401:
            raise AccesoCorreoRevocado()
        if r.status_code == 403 and revisar_403:
            razon = ""
            try:
                razon = r.json()["error"]["errors"][0]["reason"]
            except (ValueError, KeyError, IndexError, TypeError):
                pass
            if razon in ("insufficientPermissions", "forbidden", "authError"):
                raise AccesoCorreoRevocado()
            raise ErrorProveedorCorreo(f"Gmail limitó las solicitudes ({razon or 'HTTP 403'}).")
        if r.status_code == 429 or r.status_code >= 500:
            raise ErrorProveedorCorreo(f"Gmail no está disponible (HTTP {r.status_code}).")
        return r


class ClienteGmail:
    def __init__(self, proveedor: ProveedorGmail, refresh_token: str):
        self._p, self._token = proveedor, refresh_token

    def _json(self, metodo: str, ruta: str, **kw) -> dict:
        r = self._p.solicitar(self._token, metodo, ruta, **kw)
        if r.status_code >= 400:
            raise ErrorProveedorCorreo(f"Gmail respondió HTTP {r.status_code} en {ruta.split('?')[0]}.")
        return r.json() if r.content else {}

    def perfil(self) -> PerfilBuzon:
        d = self._json("GET", "/profile")
        return PerfilBuzon(correo=d["emailAddress"].lower(), history_id=int(d["historyId"]))

    def asegurar_etiquetas(self) -> EtiquetasCentinela:
        ids = {e["name"]: e["id"] for e in self._json("GET", "/labels").get("labels", [])}
        for nombre in (ETIQUETA_CUARENTENA, ETIQUETA_SOSPECHOSO):
            if nombre not in ids:
                r = self._p.solicitar(self._token, "POST", "/labels", json={
                    "name": nombre, "labelListVisibility": "labelShow", "messageListVisibility": "show"})
                if r.status_code == 409:      # otra revisión la creó al mismo tiempo
                    ids = {e["name"]: e["id"] for e in self._json("GET", "/labels").get("labels", [])}
                elif r.status_code >= 400:
                    raise ErrorProveedorCorreo(f"No se pudo crear la etiqueta {nombre}.")
                else:
                    ids[nombre] = r.json()["id"]
        return EtiquetasCentinela(cuarentena_id=ids[ETIQUETA_CUARENTENA], sospechoso_id=ids[ETIQUETA_SOSPECHOSO])

    def nuevos_desde(self, history_id: int) -> CambiosBuzon:
        ids: list[str] = []
        params = {"startHistoryId": str(history_id), "historyTypes": "messageAdded", "labelId": "INBOX"}
        ultimo = history_id
        while True:
            r = self._p.solicitar(self._token, "GET", "/history", params=params)
            if r.status_code == 404:
                raise HistorialExpirado()
            if r.status_code >= 400:
                raise ErrorProveedorCorreo(f"Gmail respondió HTTP {r.status_code} al leer el historial.")
            d = r.json()
            ultimo = int(d.get("historyId", ultimo))
            for h in d.get("history", []):
                for agregado in h.get("messagesAdded", []):
                    mid = agregado["message"]["id"]
                    if mid not in ids:
                        ids.append(mid)
            if not d.get("nextPageToken"):
                return CambiosBuzon(ids_nuevos=ids, history_id=ultimo)
            params["pageToken"] = d["nextPageToken"]

    def recientes(self, maximo: int) -> list[str]:
        d = self._json("GET", "/messages", params={"labelIds": "INBOX", "maxResults": str(maximo)})
        return [m["id"] for m in reversed(d.get("messages", []))]     # del más antiguo al más nuevo

    def obtener(self, gmail_id: str) -> MensajeCrudo:
        r = self._p.solicitar(self._token, "GET", f"/messages/{gmail_id}", params={"format": "minimal"})
        if r.status_code == 404:
            raise MensajeNoDisponible()
        if r.status_code >= 400:
            raise ErrorProveedorCorreo(f"Gmail respondió HTTP {r.status_code} al leer un mensaje.")
        meta = r.json()
        tamano = int(meta.get("sizeEstimate", 0))
        crudo = None
        if tamano <= MAX_BYTES_MENSAJE:
            r = self._p.solicitar(self._token, "GET", f"/messages/{gmail_id}", params={"format": "raw"})
            if r.status_code == 404:
                raise MensajeNoDisponible()
            if r.status_code >= 400:
                raise ErrorProveedorCorreo(f"Gmail respondió HTTP {r.status_code} al descargar un mensaje.")
            crudo = _b64url_decodificar(r.json()["raw"])
        return MensajeCrudo(gmail_id=gmail_id, hilo_id=meta.get("threadId"), tamano_bytes=tamano,
                            recibido_en=datetime.fromtimestamp(int(meta.get("internalDate", 0)) / 1000, UTC),
                            etiquetas=list(meta.get("labelIds", [])), crudo=crudo)

    def modificar_etiquetas(self, gmail_id: str, agregar: list[str], quitar: list[str]) -> None:
        r = self._p.solicitar(self._token, "POST", f"/messages/{gmail_id}/modify",
                              json={"addLabelIds": agregar, "removeLabelIds": quitar})
        if r.status_code == 404:
            raise MensajeNoDisponible()
        if r.status_code >= 400:
            raise ErrorProveedorCorreo(f"Gmail respondió HTTP {r.status_code} al cambiar etiquetas.")

    def insertar(self, crudo: bytes, etiquetas: list[str]) -> str:
        raw = base64.urlsafe_b64encode(crudo).decode()
        return self._json("POST", "/messages", params={"internalDateSource": "dateHeader"},
                          json={"raw": raw, "labelIds": etiquetas})["id"]

    def vigilar(self, tema: str) -> Vigilancia:
        """users.watch: Gmail publicará en el tema de Pub/Sub cada cambio en la bandeja de entrada durante ~7 días.
        Para que funcione, la cuenta gmail-api-push@system.gserviceaccount.com debe poder publicar en el tema."""
        # Un 403 aquí suele ser del tema de Pub/Sub (sin permiso para publicar), no del buzón: no se toma como revocado
        r = self._p.solicitar(self._token, "POST", "/watch", revisar_403=False,
                              json={"topicName": tema, "labelIds": ["INBOX"], "labelFilterBehavior": "INCLUDE"})
        if r.status_code >= 400:
            detalle = ""
            try:
                detalle = r.json()["error"]["message"][:200]
            except (ValueError, KeyError, TypeError):
                pass
            raise ErrorProveedorCorreo(f"Gmail no activó los avisos en tiempo real (HTTP {r.status_code}). {detalle}".strip())
        d = r.json()
        return Vigilancia(history_id=int(d["historyId"]),
                          expira_en=datetime.fromtimestamp(int(d["expiration"]) / 1000, UTC))
