"""
Conector IMAP de Centinela (probado con Gmail: imap.gmail.com, puerto 993, contrasena de aplicacion).

Reglas de seguridad de este modulo:
  - NUNCA borra correos. La cuarentena copia el mensaje a la carpeta "Centinela/Cuarentena" y lo saca de la bandeja de entrada
    (en Gmail, eso solo quita la etiqueta de bandeja de entrada: el correo sigue guardado en "Todos los mensajes").
  - Lee con BODY.PEEK, asi que no marca los correos como leidos.
  - La contrasena solo se usa para iniciar sesion: no se guarda en ningun archivo.
Solo usa la libreria estandar.
"""
import hashlib
import html as _html
import imaplib
import re
import smtplib
import socket
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import formataddr, formatdate

FABRICA_IMAP = imaplib.IMAP4_SSL   # las pruebas la reemplazan por un buzon simulado
FABRICA_SMTP = smtplib.SMTP_SSL   # idem, para el envio de avisos
CARPETA_CUARENTENA = "Centinela/Cuarentena"
MAX_BYTES_MENSAJE = 10_000_000


class ErrorBuzon(Exception):
    """Error con un mensaje listo para mostrarle a la persona."""


def _q(nombre):
    return '"' + nombre.replace("\\", "\\\\").replace('"', '\\"') + '"'


def traducir_error(e):
    t = str(e)
    if isinstance(e, imaplib.IMAP4.error):
        bajo = t.lower()
        if "authenticationfailed" in bajo or "invalid credentials" in bajo or "application-specific" in bajo or "login failed" in bajo or "authentication failed" in bajo:
            return ("Gmail rechazó el correo o la contraseña. Usa la contraseña de aplicación de 16 letras (no la normal de Gmail), "
                    "sin espacios, y revisa que la verificación en dos pasos esté activa.")
        return "El servidor de correo respondió con un error: " + t[:150]
    if isinstance(e, (socket.gaierror, socket.timeout, TimeoutError, ConnectionError, OSError)):
        return "No pude conectarme al servidor de correo. Revisa tu conexión a internet e inténtalo de nuevo."
    return "Error inesperado al hablar con el buzón: " + t[:150]


def id_mensaje(raw):
    """Identificador estable del correo (el Message-ID; si no trae, una huella del contenido)."""
    try:
        mid = str(BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)["Message-ID"] or "").strip()
    except Exception:
        mid = ""
    return mid or ("sha1:" + hashlib.sha1(raw[:200000]).hexdigest())


class BuzonIMAP:
    def __init__(self, usuario, clave, host="imap.gmail.com", puerto=993, carpeta_cuarentena=CARPETA_CUARENTENA, timeout=25):
        self.usuario = usuario.strip()
        self.clave = clave.replace(" ", "")      # Google muestra la clave con espacios: hay que quitarlos
        self.host, self.puerto, self.timeout = host, puerto, timeout
        self.carpeta_cuarentena = carpeta_cuarentena
        self.m = None

    def __enter__(self):
        self.conectar()
        return self

    def __exit__(self, *a):
        self.cerrar()

    def conectar(self):
        if not self.usuario or not self.clave:
            raise ErrorBuzon("Escribe el correo y la contraseña de aplicación.")
        try:
            self.m = FABRICA_IMAP(self.host, self.puerto, timeout=self.timeout)
            self.m.login(self.usuario, self.clave)
        except Exception as e:
            self.cerrar()
            raise ErrorBuzon(traducir_error(e)) from None

    def cerrar(self):
        m, self.m = self.m, None
        if m is not None:
            try:
                m.logout()
            except Exception:
                pass

    # ---------------- utilidades ----------------
    def _ok(self, resp, que):
        typ, datos = resp
        if typ != "OK":
            detalle = datos[0].decode("utf-8", "ignore") if datos and isinstance(datos[0], bytes) else ""
            raise ErrorBuzon("El servidor no aceptó la operación (" + que + "). " + detalle[:100])
        return datos

    def _seleccionar(self, carpeta, solo_lectura=False):
        try:
            typ, datos = self.m.select(_q(carpeta), readonly=solo_lectura)
        except Exception as e:
            raise ErrorBuzon(traducir_error(e)) from None
        if typ != "OK":
            raise ErrorBuzon("No pude abrir la carpeta «" + carpeta + "».")
        return datos

    def _expulsar(self, uids):
        """Saca de la carpeta actual los mensajes marcados (en Gmail solo quita esa etiqueta)."""
        try:
            typ, _ = self.m.uid("EXPUNGE", ",".join(str(u) for u in uids))
            if typ == "OK":
                return
        except Exception:
            pass
        self.m.expunge()

    def _tamano(self, uid):
        try:
            typ, d = self.m.uid("FETCH", str(uid), "(RFC822.SIZE)")
            if typ == "OK" and d and d[0]:
                m = re.search(rb"RFC822\.SIZE (\d+)", d[0] if isinstance(d[0], bytes) else d[0][0])
                return int(m.group(1)) if m else None
        except Exception:
            pass
        return None

    # ---------------- operaciones ----------------
    def probar(self):
        """Devuelve la cantidad de correos de la bandeja (lanza ErrorBuzon si algo falla)."""
        datos = self._seleccionar("INBOX", solo_lectura=True)
        try:
            return int(datos[0])
        except Exception:
            return 0

    def nuevos(self, ultimo_uid, maximo):
        """[(uid, bytes)] de los correos de la bandeja con UID mayor a ultimo_uid. Si es None, trae los ultimos `maximo`.
        Si un correo pesa demasiado, devuelve (uid, None)."""
        self._seleccionar("INBOX", solo_lectura=True)
        try:
            if ultimo_uid is None:
                _, d = self.m.uid("SEARCH", "ALL")
                uids = sorted(int(x) for x in (d[0] or b"").split())[-maximo:]
            else:
                _, d = self.m.uid("SEARCH", "UID", str(ultimo_uid + 1) + ":*")
                uids = sorted(u for u in (int(x) for x in (d[0] or b"").split()) if u > ultimo_uid)[:maximo]
            salida = []
            for u in uids:
                tam = self._tamano(u)
                if tam is not None and tam > MAX_BYTES_MENSAJE:
                    salida.append((u, None))
                    continue
                typ, d = self.m.uid("FETCH", str(u), "(BODY.PEEK[])")
                raw = next((parte[1] for parte in (d or []) if isinstance(parte, tuple)), None) if typ == "OK" else None
                salida.append((u, raw))
            return salida
        except ErrorBuzon:
            raise
        except Exception as e:
            raise ErrorBuzon(traducir_error(e)) from None

    def a_cuarentena(self, uid):
        """Copia el correo a la carpeta de cuarentena y lo saca de la bandeja de entrada. No borra nada."""
        try:
            self.m.create(_q(self.carpeta_cuarentena))          # si ya existe, el servidor responde NO y se ignora
            self._seleccionar("INBOX")
            self._ok(self.m.uid("COPY", str(uid), _q(self.carpeta_cuarentena)), "copiar a cuarentena")
            self._ok(self.m.uid("STORE", str(uid), "+FLAGS", r"(\Deleted)"), "sacar de la bandeja")
            self._expulsar([uid])
            return True
        except ErrorBuzon:
            raise
        except Exception as e:
            raise ErrorBuzon(traducir_error(e)) from None

    def liberar(self, mensaje_id):
        """Devuelve el correo de la cuarentena a la bandeja de entrada."""
        try:
            self._seleccionar(self.carpeta_cuarentena)
            _, d = self.m.uid("SEARCH", "HEADER", "Message-ID", _q(mensaje_id))
            uids = [int(x) for x in (d[0] or b"").split()]
            if not uids:
                raise ErrorBuzon("No encontré ese correo en la carpeta de cuarentena (¿ya lo moviste?).")
            for u in uids:
                self._ok(self.m.uid("COPY", str(u), "INBOX"), "devolver a la bandeja")
                self._ok(self.m.uid("STORE", str(u), "+FLAGS", r"(\Deleted)"), "sacar de cuarentena")
            self._expulsar(uids)
            return True
        except ErrorBuzon:
            raise
        except Exception as e:
            raise ErrorBuzon(traducir_error(e)) from None


# ---------------------------------------------------------------------
# Avisos por correo: Centinela le escribe a la persona cuando detecta algo sospechoso
# ---------------------------------------------------------------------
def tipos_de_amenaza(r):
    """Traduce las razones del analisis a tipos de amenaza que se entienden (maximo 3)."""
    tipos = []

    def agregar(t):
        if t not in tipos:
            tipos.append(t)
    for x in r.get("razones", []):
        a, t = x["area"], x["texto"].lower()
        if a == "Autenticación":
            agregar("Posible suplantación: falló la verificación del remitente")
        elif a == "Remitente":
            if "dice ser o hablar de" in t or "imita" in t:
                agregar("Suplantación de una entidad o marca")
            else:
                agregar("Remitente sospechoso")
        elif a == "Enlaces":
            agregar("Enlace acortado que esconde el destino" if "acortado" in t else "Enlace engañoso")
        elif a == "Adjuntos":
            agregar("Adjunto peligroso")
        elif a == "Contenido":
            agregar("Ingeniería social: urgencia, premios o pide datos")
    if not tipos:
        agregar("Mensaje con lenguaje típico de phishing")
    return tipos[:3]


_COLORES = {"ALTO": ("#E23D3D", "#FDE8E8", "#C62828"), "MEDIO": ("#E0A93B", "#FFF4D6", "#946200")}
CID_LOGO = "logo-centinela@centinela"


def construir_aviso(remitente, destinatario, sospechosos, logo_png=None):
    """sospechosos: [{'nivel','de','asunto','tipos':[...],'razones':[...],'accion'}]. Devuelve un EmailMessage con el logo embebido."""
    esc = _html.escape
    n = len(sospechosos)
    hay_alto = any(s["nivel"] == "ALTO" for s in sospechosos)
    color = "#E23D3D" if hay_alto else "#E0A93B"
    plural = "" if n == 1 else "s"
    asunto = "⚠ Advertencia de Centinela: detectamos " + str(n) + " correo" + plural + " sospechoso" + plural + " en tu bandeja"
    titulo = "Advertencia de seguridad: detectamos " + str(n) + " correo" + plural + " sospechoso" + plural + " en tu bandeja"
    intro = "Centinela revisó tu buzón y encontró " + ("este correo" if n == 1 else "estos correos") + " con señales de phishing (un intento de engañarte para que entregues datos, dinero o abras algo peligroso). Ten mucho cuidado."
    tarjetas, texto = "", [titulo, "", intro, ""]
    for s in sospechosos[:10]:
        fg, bg, tx = _COLORES.get(s["nivel"], _COLORES["MEDIO"])
        razones = "".join('<li style="margin:3px 0;">' + esc(r) + '</li>' for r in s.get("razones", []))
        tarjetas += (
            '<tr><td style="padding:0 28px 14px 28px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #E5EAF0;border-left:6px solid ' + fg + ';border-radius:10px;">'
            '<tr><td style="padding:14px 16px;font-size:14px;color:#16202B;line-height:1.5;">'
            '<span style="display:inline-block;background:' + bg + ';color:' + tx + ';font-weight:bold;font-size:11px;padding:3px 10px;border-radius:12px;">RIESGO ' + esc(s["nivel"]) + '</span>'
            '<div style="margin-top:8px;"><b>De:</b> ' + esc(s["de"]) + '</div><div><b>Asunto:</b> ' + esc(s["asunto"]) + '</div>'
            '<div style="margin-top:6px;"><b>Tipo de amenaza:</b> ' + esc(" · ".join(s["tipos"])) + '</div>'
            + ('<div style="margin-top:6px;"><b>Por qué:</b><ul style="margin:4px 0 0 18px;padding:0;">' + razones + '</ul></div>' if razones else '')
            + '<div style="margin-top:8px;color:#3B4A5C;">' + esc(s["accion"]) + '</div></td></tr></table></td></tr>')
        texto += ["[" + s["nivel"] + "] De: " + s["de"], "Asunto: " + s["asunto"], "Tipo de amenaza: " + " · ".join(s["tipos"]), s["accion"], ""]
    if n > 10:
        tarjetas += '<tr><td style="padding:0 28px 14px 28px;font-size:13px;color:#6B7B8C;">… y ' + str(n - 10) + ' más. Míralos en el Historial de Centinela.</td></tr>'
    consejos = ["No abras los enlaces ni los adjuntos de esos correos y no respondas.",
                "Verifica por otro canal: llama a un número oficial de la entidad o escribe tú la dirección en el navegador.",
                "Si ya entregaste datos, cambia tus contraseñas de inmediato y avisa a tu equipo de TI."]
    texto += ["Qué hacer:"] + ["- " + c for c in consejos] + ["", "Centinela detecta, prioriza y sugiere: no reemplaza tu criterio."]
    logo = ('<img src="cid:' + CID_LOGO + '" width="150" alt="Centinela" style="display:block;margin:0 auto;border:0;">' if logo_png else '<b style="font-size:22px;letter-spacing:1px;">CENTINELA</b>')
    html = (
        '<html><body style="margin:0;padding:0;background:#F4F7FA;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F4F7FA;padding:24px 0;"><tr><td align="center">'
        '<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#FFFFFF;border-radius:14px;font-family:Arial,Helvetica,sans-serif;">'
        '<tr><td align="center" style="padding:24px 28px 14px 28px;">' + logo + '</td></tr>'
        '<tr><td style="background:' + color + ';color:#FFFFFF;padding:16px 28px;font-size:18px;font-weight:bold;line-height:1.35;">' + "⚠ " + esc(titulo) + '</td></tr>'
        '<tr><td style="padding:20px 28px 14px 28px;font-size:14px;color:#16202B;line-height:1.55;">' + esc(intro) + '</td></tr>'
        + tarjetas +
        '<tr><td style="padding:6px 28px 8px 28px;font-size:14px;color:#16202B;line-height:1.55;"><b>Qué hacer ahora</b><ul style="margin:6px 0 0 18px;padding:0;">'
        + "".join('<li style="margin:4px 0;">' + esc(c) + '</li>' for c in consejos) + '</ul></td></tr>'
        '<tr><td style="padding:18px 28px 24px 28px;font-size:12px;color:#6B7B8C;line-height:1.5;border-top:1px solid #EEF1F5;">Este aviso lo envió Centinela automáticamente porque activaste los avisos por correo. '
        'Centinela detecta, prioriza y sugiere: no reemplaza tu criterio. Puedes ver el detalle y devolver correos desde la cuarentena en Centinela, sección Historial.</td></tr>'
        '</table></td></tr></table></body></html>')
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"], msg["Date"] = asunto, formataddr(("Centinela", remitente)), destinatario, formatdate(localtime=True)
    msg["X-Centinela-Alerta"] = "1"          # Centinela se salta sus propios avisos para no entrar en un ciclo
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content("\n".join(texto))
    msg.add_alternative(html, subtype="html")
    if logo_png:
        msg.get_payload()[1].add_related(logo_png, "image", "png", cid="<" + CID_LOGO + ">", filename="centinela.png")
    return msg


def enviar_aviso(usuario, clave, mensaje, host="smtp.gmail.com", puerto=465):
    try:
        with FABRICA_SMTP(host, puerto, timeout=25) as s:
            s.login(usuario.strip(), clave.replace(" ", ""))
            s.send_message(mensaje)
    except smtplib.SMTPAuthenticationError:
        raise ErrorBuzon("Gmail rechazó la contraseña al enviar el aviso. Revisa la contraseña de aplicación.") from None
    except (smtplib.SMTPException, OSError) as e:
        raise ErrorBuzon("No pude enviar el aviso por correo: " + str(e)[:120]) from None
