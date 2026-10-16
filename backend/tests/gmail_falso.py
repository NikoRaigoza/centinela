"""Gmail simulado en memoria: implementa los mismos puertos que el adaptador real de Google."""
from __future__ import annotations

from datetime import UTC, datetime
from email.message import EmailMessage

from centinela.aplicacion.casos_uso.buzones import reto_pkce
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
)
from centinela.dominio.buzon import EtiquetasCentinela

ALCANCE = "https://www.googleapis.com/auth/gmail.modify"


def correo(remitente="Bancolombia <alertas@bancolombia-seguro.xyz>", asunto="Su cuenta fue bloqueada",
           cuerpo="Ingrese ya para verificar sus datos: http://bancolombia-seguro.xyz/login", html=None,
           autenticacion="mx.google.com; dkim=fail; spf=softfail smtp.mailfrom=x; dmarc=fail (p=NONE)",
           message_id="<abc@x>", adjuntos=(), extra=None) -> bytes:
    m = EmailMessage()
    if autenticacion:
        m["Authentication-Results"] = autenticacion
    m["From"], m["To"], m["Subject"] = remitente, "ana@gmail.com", asunto
    m["Message-ID"], m["Date"] = message_id, "Thu, 15 Oct 2026 10:00:00 -0500"
    for k, v in (extra or {}).items():
        m[k] = v
    m.set_content(cuerpo)
    if html:
        m.add_alternative(html, subtype="html")
    for nombre, datos, tipo in adjuntos:
        principal, sub = tipo.split("/")
        m.add_attachment(datos, maintype=principal, subtype=sub, filename=nombre)
    return m.as_bytes()


class BuzonGmailFalso:
    def __init__(self, direccion="ana@gmail.com", history_id=1000):
        self.direccion = direccion
        self.history_id = history_id
        self.mensajes: dict[str, dict] = {}
        self.eventos: list[tuple[int, str]] = []
        self.etiquetas: dict[str, str] = {}
        self.revocado = False
        self.falla: str | None = None
        self.historial_expirado = False

    def llega(self, crudo: bytes, etiquetas=("INBOX", "UNREAD")) -> str:
        self.history_id += 1
        gid = f"g{len(self.mensajes) + 1}"
        self.mensajes[gid] = {"crudo": crudo, "etiquetas": list(etiquetas), "fecha": datetime.now(UTC)}
        self.eventos.append((self.history_id, gid))
        return gid


class ClienteGmailFalso:
    def __init__(self, b: BuzonGmailFalso):
        self.b = b

    def _revisar(self):
        if self.b.revocado:
            raise AccesoCorreoRevocado()
        if self.b.falla:
            raise ErrorProveedorCorreo(self.b.falla)

    def perfil(self):
        self._revisar()
        return PerfilBuzon(self.b.direccion, self.b.history_id)

    def asegurar_etiquetas(self):
        self._revisar()
        for n in ("Centinela/Cuarentena", "Centinela/Sospechoso"):
            self.b.etiquetas.setdefault(n, f"Label_{len(self.b.etiquetas) + 1}")
        return EtiquetasCentinela(self.b.etiquetas["Centinela/Cuarentena"], self.b.etiquetas["Centinela/Sospechoso"])

    def nuevos_desde(self, history_id):
        self._revisar()
        if self.b.historial_expirado:
            raise HistorialExpirado()
        return CambiosBuzon([g for h, g in self.b.eventos if h > history_id], self.b.history_id)

    def recientes(self, maximo):
        self._revisar()
        return [g for _, g in self.b.eventos][-maximo:]

    def obtener(self, gmail_id):
        self._revisar()
        m = self.b.mensajes.get(gmail_id)
        if m is None:
            raise MensajeNoDisponible()
        return MensajeCrudo(gmail_id, f"h-{gmail_id}", m["fecha"], len(m["crudo"]), m["etiquetas"], m["crudo"])

    def modificar_etiquetas(self, gmail_id, agregar, quitar):
        m = self.b.mensajes[gmail_id]
        m["etiquetas"] = [e for e in m["etiquetas"] if e not in quitar] + list(agregar)

    def insertar(self, crudo, etiquetas):
        return self.b.llega(crudo, etiquetas)


class ProveedorGmailFalso:
    def __init__(self):
        self.por_token: dict[str, BuzonGmailFalso] = {}

    def abrir(self, refresh_token):
        if refresh_token not in self.por_token:
            raise AccesoCorreoRevocado()
        return ClienteGmailFalso(self.por_token[refresh_token])


class AutorizacionFalsa:
    """`codigos` asocia cada código de autorización con el refresh token que entregaría Google."""

    def __init__(self, proveedor: ProveedorGmailFalso):
        self.proveedor = proveedor
        self.codigos: dict[str, str] = {}
        self.retos: set[str] = set()
        self.revocados: list[str] = []

    def autoriza(self, codigo: str, buzon: BuzonGmailFalso, token: str | None = None) -> str:
        token = token or f"rt-{codigo}"
        self.codigos[codigo] = token
        self.proveedor.por_token[token] = buzon
        return token

    def url_autorizacion(self, estado, reto_pkce_):
        self.retos.add(reto_pkce_)
        return f"https://accounts.google.test/auth?state={estado}"

    def intercambiar_codigo(self, codigo, verificador_pkce):
        if codigo == "sin-permiso":
            raise PermisoInsuficiente()
        if codigo not in self.codigos or reto_pkce(verificador_pkce) not in self.retos:
            raise ErrorProveedorCorreo("invalid_grant")
        return CredencialCorreo(self.codigos[codigo], [ALCANCE])

    def revocar(self, refresh_token):
        self.revocados.append(refresh_token)
