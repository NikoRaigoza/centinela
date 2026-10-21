"""Ingesta segura de sandboxes: ningún adjunto llega al disco y la evaluación conserva lo que vería producción.
Los "programas" de estas pruebas son bytes inofensivos con la firma de un ejecutable (MZ), no malware."""
from __future__ import annotations

import base64
import hashlib
import io
import json
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

import conjunto_colombia as cc
import importar_sandbox as imp
import numpy as np
import pytest
import pyzipper
import zxingcpp
from PIL import Image

PROGRAMA = b"MZ\x90\x00" + b"\x00" * 60 + b"This program cannot be run in DOS mode." + b"\x00" * 200


def qr_png(texto: str) -> bytes:
    codigo = zxingcpp.write_barcode_to_image(zxingcpp.create_barcode(texto, zxingcpp.BarcodeFormat.QRCode), scale=5)
    lienzo = Image.new("RGB", (420, 420), "white")
    lienzo.paste(Image.fromarray(np.array(codigo)).convert("RGB"), (30, 30))
    b = io.BytesIO()
    lienzo.save(b, "PNG")
    return b.getvalue()


def zip_simple(archivos: dict[str, bytes]) -> bytes:
    b = io.BytesIO()
    with pyzipper.ZipFile(b, "w", compression=pyzipper.ZIP_DEFLATED) as z:
        for n, d in archivos.items():
            z.writestr(n, d)
    return b.getvalue()


def correo_malicioso() -> bytes:
    m = EmailMessage()
    m["Received"] = "from mail.atacante.xyz (mail.atacante.xyz [203.0.113.9]) by mx.victima.co; Tue, 1 Oct 2026"
    m["Authentication-Results"] = "mx.victima.co; spf=fail smtp.mailfrom=bancolombia.com.co"
    m["From"] = "Bancolombia <alertas@bancolombia-seguridad.xyz>"
    m["To"] = "cliente@empresa.co"
    m["Subject"] = "Su cuenta será bloqueada"
    m["Date"] = "Tue, 01 Oct 2026 10:00:00 -0500"
    m["Message-ID"] = "<abc123@atacante.xyz>"
    m["X-Encabezado-Raro"] = "valor con   espacios   raros"
    m.set_content("Estimado cliente, abra el comprobante adjunto para evitar el bloqueo de su cuenta. Detectamos un "
                  "ingreso inusual desde otro dispositivo y por su seguridad suspenderemos sus productos en las próximas "
                  "24 horas si no confirma sus datos. Gracias por confiar en nosotros.")
    contrabando = base64.b64encode(zip_simple({"factura.exe": PROGRAMA}) * 40).decode()
    m.add_alternative(f'<p>Estimado cliente</p><a href="https://bancolombia-seguridad.xyz/login">Ingrese aquí</a>'
                      f'<script>var b="{contrabando}";</script>', subtype="html")
    m.get_payload()[1].add_related(qr_png("https://qr-bancolombia.xyz/validar"), "image", "png", cid="qr1")
    m.add_attachment(zip_simple({"comprobante.pdf.exe": PROGRAMA}), "application", "zip", filename="comprobante.zip")
    m.add_attachment(b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "image", "svg+xml",
                     filename="aviso.svg")
    m.add_attachment(PROGRAMA, "application", "octet-stream", filename="Factura_Electrónica.pdf.exe")
    reenviado = EmailMessage()
    reenviado["From"], reenviado["Subject"] = "x@y.co", "interno"
    reenviado.set_content("texto del correo reenviado")
    reenviado.add_attachment(PROGRAMA, "application", "octet-stream", filename="otro.exe")
    m.add_attachment(reenviado)
    return m.as_bytes()


def _partes(crudo: bytes):
    return list(BytesParser(policy=policy.default).parsebytes(crudo).walk())


def test_sanear_vacia_adjuntos_y_conserva_encabezados_y_cuerpos():
    original = correo_malicioso()
    s = imp.sanear(original)
    assert PROGRAMA[:40] not in s.crudo and b"TVqQ" not in s.crudo            # ni crudo ni en base64
    assert b"UEsDB" not in s.crudo and b"<svg" not in s.crudo
    # encabezados intactos, byte a byte
    cabeza_o, cabeza_s = original.split(b"\n\n", 1)[0], s.crudo.split(b"\n\n", 1)[0]
    assert cabeza_o == cabeza_s
    # cuerpos: el texto y el enlace siguen; el bloque de contrabando no
    msg = BytesParser(policy=policy.default).parsebytes(s.crudo)
    assert "abra el comprobante adjunto" in msg.get_body(("plain",)).get_content()
    html = msg.get_body(("html",)).get_content()
    assert "https://bancolombia-seguridad.xyz/login" in html and "[centinela: bloque base64 retirado" in html
    assert s.bloques_b64 == 1
    # cada adjunto: vacío, con nombre, tipo, tamaño y sha256 originales
    retirados = {r.nombre: r for r in s.retirados}
    assert set(retirados) == {"(sin nombre)", "comprobante.zip", "aviso.svg", "Factura_Electrónica.pdf.exe"}
    assert retirados["Factura_Electrónica.pdf.exe"].sha256 == hashlib.sha256(PROGRAMA).hexdigest()
    for p in _partes(s.crudo):
        if p.get_filename() == "comprobante.zip":
            assert p.get_content_type() == "application/zip" and p.get_payload(decode=True) == b""
            assert f"tamano={retirados['comprobante.zip'].tamano}" in p[imp.ENCABEZADO_RETIRADO]
            insp = json.loads(base64.b64decode(p[imp.ENCABEZADO_INSPECCION]))
            assert insp["tipo_real"] == "zip" and "comprimido_peligroso" in insp["senales"]
            assert insp["contenido"] == ["comprobante.pdf.exe"]
        if p.get_content_type() == "image/png":                            # el QR del cuerpo quedó leído
            assert json.loads(base64.b64decode(p[imp.ENCABEZADO_INSPECCION]))["qr"] == ["https://qr-bancolombia.xyz/validar"]
    assert b"texto del correo reenviado" not in s.crudo                    # el reenviado también se vació


def test_conservar_imagenes_solo_deja_imagenes_verificadas():
    s = imp.sanear(correo_malicioso(), conservar_imagenes=True)
    assert s.imagenes_conservadas == 1 and b"<svg" not in s.crudo
    png = next(p for p in _partes(s.crudo) if p.get_content_type() == "image/png")
    assert png.get_payload(decode=True).startswith(b"\x89PNG")
    # un "png" que en realidad es un programa no se conserva
    m = EmailMessage()
    m["From"], m["Subject"] = "a@b.co", "x"
    m.set_content("hola")
    m.add_attachment(PROGRAMA, "image", "png", filename="foto.png")
    assert PROGRAMA[:40] not in imp.sanear(m.as_bytes(), conservar_imagenes=True).crudo


def test_verificar_rechaza_lo_que_no_se_saneo():
    with pytest.raises(imp.CorreoInseguro):
        imp.verificar(correo_malicioso())
    m = EmailMessage()
    m["From"], m["Subject"] = "a@b.co", "x"
    m.set_content(PROGRAMA.decode("latin-1"))                             # un "cuerpo" que es un programa
    with pytest.raises(imp.CorreoInseguro):
        imp.verificar(m.as_bytes())


def test_zip_aes_en_memoria_e_importacion_completa(tmp_path, monkeypatch):
    datos = tmp_path / "colombia"
    monkeypatch.setattr(cc, "DATOS", datos)
    descargas = tmp_path / "descargas"
    descargas.mkdir()
    zip_aes = descargas / "tarea.zip"
    with pyzipper.AESZipFile(zip_aes, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
        z.setpassword(b"infected")
        z.writestr("muestra.eml", correo_malicioso())
        z.writestr("0f1e2d3c4b5a", correo_malicioso().replace(b"Su cuenta", b"Tu cuenta"))   # sin extensión
        z.writestr("adjunto.exe", PROGRAMA)
        z.writestr("correo.msg", b"\xd0\xcf\x11\xe0 outlook")
    correos, omitidos = imp.correos_del_zip(zip_aes, "infected")
    assert [n for n, _ in correos] == ["muestra.eml", "0f1e2d3c4b5a"]
    assert any("adjunto.exe" in o for o in omitidos) and any(".msg" in o for o in omitidos)
    with pytest.raises(RuntimeError):
        imp.correos_del_zip(zip_aes, "otra-clave")

    antes = {p for p in tmp_path.rglob("*")}
    monkeypatch.setattr("sys.argv", ["importar_sandbox.py", str(zip_aes), "--origen", "anyrun", "--categoria", "bancos",
                                     "--url-fuente", "https://app.any.run/tasks/abc"])
    imp.main()
    nuevos = sorted(p for p in tmp_path.rglob("*") if p not in antes and p.is_file())
    nombres = [p.name for p in nuevos]
    assert sum(n.endswith(".eml") for n in nombres) == 2
    assert not any(n.endswith((".exe", ".zip", ".svg", ".msg", ".xhtml")) for n in nombres)
    for p in nuevos:
        assert PROGRAMA[:40] not in p.read_bytes() and b"TVqQ" not in p.read_bytes()
    filas = cc.leer_manifiesto(datos)
    assert len(filas) == 2 and {f["origen"] for f in filas} == {"anyrun"}
    assert {f["url_fuente"] for f in filas} == {"https://app.any.run/tasks/abc"}
    assert {f["fecha"] for f in filas} == {"2026-10-01"}
    assert len({f["campana"] for f in filas}) == 1                         # misma plantilla → misma campaña
    for f in filas:
        assert hashlib.sha256((datos / f["archivo"]).read_bytes()).hexdigest() == f["sha256"]

    imp.main()                                                             # importar dos veces no duplica
    assert len(cc.leer_manifiesto(datos)) == 2


def test_malwarebazaar_completa_la_url(tmp_path, monkeypatch):
    datos = tmp_path / "colombia"
    monkeypatch.setattr(cc, "DATOS", datos)
    crudo = correo_malicioso()
    z = tmp_path / "m.zip"
    with pyzipper.AESZipFile(z, "w", encryption=pyzipper.WZ_AES) as zz:
        zz.setpassword(b"infected")
        zz.writestr(hashlib.sha256(crudo).hexdigest() + ".eml", crudo)
    monkeypatch.setattr("sys.argv", ["x", str(z), "--origen", "malwarebazaar", "--categoria", "otros"])
    imp.main()
    (fila,) = cc.leer_manifiesto(datos)
    assert fila["url_fuente"] == f"https://bazaar.abuse.ch/sample/{hashlib.sha256(crudo).hexdigest()}/"
