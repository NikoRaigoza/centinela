"""Redacta el aviso que Centinela inserta en el buzón del dueño cuando detecta un correo peligroso."""
from __future__ import annotations

import html
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path

from centinela.adaptadores.salida.lector_correo import ENCABEZADO_AVISO, firmar_aviso
from centinela.aplicacion.puertos import DatosAviso

CONSEJOS = (
    "No abras sus enlaces ni sus adjuntos, y no respondas.",
    "Si dice venir de una entidad (banco, DIAN, transportadora), verifica por otro canal: escribe tú mismo la "
    "dirección oficial en el navegador o llama a su línea oficial.",
    "Si ya entregaste datos o claves, cámbialas de inmediato y comunícate con tu banco.",
)
_COLOR = {"alto": ("#C62828", "#FDE8E8"), "medio": ("#946200", "#FFF4D6")}
# El logo va dentro del mismo correo (cid): Gmail no podría descargarlo de un panel local o privado
LOGO = (Path(__file__).parent / "recursos" / "logo-blanco.png").read_bytes()
CID_LOGO = "logo-centinela"


class RedactorAvisosMime:
    def __init__(self, clave_avisos: bytes, url_panel: str, dominio_ids: str = "centinela.local"):
        self._clave = clave_avisos
        self._url_panel = url_panel
        self._dominio_ids = dominio_ids

    def _enlace(self, d: DatosAviso) -> str:
        base = self._url_panel.rstrip("/")
        return f"{base}/casos/{d.caso_id}" if d.caso_id else base

    def redactar(self, d: DatosAviso) -> bytes:
        nivel = d.nivel.upper()
        asunto_corto = d.asunto if len(d.asunto) <= 60 else d.asunto[:57] + "…"
        msg = EmailMessage()
        message_id = make_msgid(idstring="aviso", domain=self._dominio_ids)
        msg["Subject"] = f"⚠ Centinela: correo peligroso detectado — «{asunto_corto}»"
        msg["From"] = formataddr(("Centinela", d.destinatario))
        msg["To"] = d.destinatario
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = message_id
        msg[ENCABEZADO_AVISO] = firmar_aviso(self._clave, message_id)
        msg["Auto-Submitted"] = "auto-generated"

        texto = [f"Centinela detectó un correo con riesgo {nivel}.", "", f"De: {d.remitente}", f"Asunto: {d.asunto}", "",
                 d.resumen, "", "Por qué creemos que es peligroso:"]
        texto += [f"  {i}. {r}" for i, r in enumerate(d.razones, 1)]
        texto += ["", "Qué hicimos:", f"  {d.accion}", "", "Qué te recomendamos:"]
        texto += [f"  - {c}" for c in CONSEJOS]
        texto += ["", f"Revisa el detalle en Centinela: {self._enlace(d)}"]
        msg.set_content("\n".join(texto))
        msg.add_alternative(self._html(d, nivel), subtype="html")
        msg.get_payload()[1].add_related(LOGO, maintype="image", subtype="png", cid=f"<{CID_LOGO}>",
                                         filename="centinela.png", disposition="inline")
        return msg.as_bytes()

    def _html(self, d: DatosAviso, nivel: str) -> str:
        e = html.escape
        fg, bg = _COLOR.get(d.nivel, _COLOR["medio"])
        razones = "".join(f'<li style="margin:4px 0">{e(r)}</li>' for r in d.razones)
        consejos = "".join(f'<li style="margin:4px 0">{e(c)}</li>' for c in CONSEJOS)
        return f"""<html><body style="margin:0;background:#F4F7FA;font-family:Arial,Helvetica,sans-serif;color:#16202B">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding:24px 0"><tr><td align="center">
<table role="presentation" width="600" cellpadding="0" cellspacing="0"
 style="max-width:600px;width:100%;background:#fff;border-radius:12px">
<tr><td style="background:{fg};color:#fff;padding:16px 24px;font-size:18px;font-weight:bold;border-radius:12px 12px 0 0">
<img src="cid:{CID_LOGO}" width="28" height="32" alt="" style="vertical-align:middle;margin-right:10px;border:0">
Centinela detectó un correo peligroso</td></tr>
<tr><td style="padding:20px 24px;font-size:14px;line-height:1.55">
<span style="background:{bg};color:{fg};font-weight:bold;font-size:12px;padding:3px 10px;border-radius:12px">
RIESGO {e(nivel)}</span>
<p style="margin:12px 0 4px"><b>De:</b> {e(d.remitente)}</p><p style="margin:0 0 12px"><b>Asunto:</b> {e(d.asunto)}</p>
<p style="margin:0 0 12px">{e(d.resumen)}</p>
<p style="margin:0"><b>Por qué creemos que es peligroso:</b></p><ol style="margin:6px 0 14px 18px;padding:0">{razones}</ol>
<p style="margin:0"><b>Qué hicimos:</b> {e(d.accion)}</p>
<p style="margin:14px 0 0"><b>Qué te recomendamos:</b></p><ul style="margin:6px 0 0 18px;padding:0">{consejos}</ul>
<p style="margin:18px 0 0"><a href="{e(self._enlace(d))}" style="color:#2E7CE4">Ver el detalle en Centinela</a></p>
</td></tr><tr><td style="padding:14px 24px 20px;font-size:12px;color:#6B7B8C;border-top:1px solid #EEF1F5">
Este aviso lo generó Centinela automáticamente. Centinela nunca te pedirá contraseñas por correo.
</td></tr></table></td></tr></table></body></html>"""
