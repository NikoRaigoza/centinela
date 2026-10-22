"""Lector MIME: extracción de remitente, enlaces, adjuntos y autenticación, y defensas contra encabezados falsos."""
from centinela.adaptadores.salida.lector_correo import LectorCorreoMime, firmar_aviso
from centinela.dominio.correo import ResultadoAuth
from tests.gmail_falso import correo

CLAVE = b"clave-de-avisos-de-prueba"
lector = LectorCorreoMime(CLAVE)


def test_campos_basicos_y_enlaces_html():
    c = lector.leer(correo(html='<p>Hola</p><a href="http://bancolombia-seguro.xyz/login">www.bancolombia.com</a>'
                                '<script>alert(1)</script>'))
    assert c.remitente_nombre == "Bancolombia" and c.remitente_dominio == "bancolombia-seguro.xyz"
    assert c.asunto == "Su cuenta fue bloqueada" and c.fecha.year == 2026
    enlace = next(e for e in c.enlaces if e.texto_visible)
    assert enlace.url == "http://bancolombia-seguro.xyz/login" and enlace.texto_visible == "www.bancolombia.com"
    assert "alert(1)" not in c.cuerpo


def test_resultados_de_autenticacion_de_google():
    c = lector.leer(correo())
    a = c.autenticacion
    assert (a.spf, a.dkim, a.dmarc, a.confiable) == (ResultadoAuth.SOFTFAIL, ResultadoAuth.FAIL, ResultadoAuth.FAIL, True)


def test_ignora_autenticacion_falsificada_por_el_remitente():
    """El atacante escribe su propio Authentication-Results con 'pass'; Google agrega el verdadero."""
    crudo = correo(autenticacion="mx.google.com; spf=fail; dkim=none; dmarc=fail",
                   extra={"Authentication-Results": "falso.example; spf=pass; dkim=pass; dmarc=pass"})
    a = lector.leer(crudo).autenticacion
    assert a.spf is ResultadoAuth.FAIL and a.dmarc is ResultadoAuth.FAIL and a.confiable


def test_sin_encabezado_de_google_no_es_confiable():
    a = lector.leer(correo(autenticacion="otro.servidor; spf=pass")).autenticacion
    assert a.spf is ResultadoAuth.PASS and not a.confiable


def test_adjuntos_con_hash():
    c = lector.leer(correo(adjuntos=[("factura.pdf.exe", b"MZ\x90\x00", "application/octet-stream")]))
    adj = c.adjuntos[0]
    assert adj.nombre == "factura.pdf.exe" and adj.extension == "exe" and adj.tamano_bytes == 4 and len(adj.sha256) == 64


def test_aviso_de_centinela_solo_si_la_firma_es_valida():
    mid = "<aviso-1@centinela>"
    legitimo = correo(message_id=mid, extra={"X-Centinela-Alerta": firmar_aviso(CLAVE, mid)})
    falsificado = correo(message_id=mid, extra={"X-Centinela-Alerta": "v1;" + "0" * 64})
    copiado_de_otro = correo(message_id="<otro@x>", extra={"X-Centinela-Alerta": firmar_aviso(CLAVE, mid)})
    assert lector.leer(legitimo).es_aviso_centinela
    assert not lector.leer(falsificado).es_aviso_centinela
    assert not lector.leer(copiado_de_otro).es_aviso_centinela


def test_correo_mal_formado_no_rompe_el_lector():
    c = lector.leer(b"From: sin-cierre <x@\nSubject: =?utf-8?q?roto\n\n<a href='http://x.co'>sin cerrar")
    assert c.asunto is not None


def test_texto_plano_de_relleno_usa_el_html():
    """Boletines que traen «Plain text version not available» como texto plano: el contenido real está en el HTML."""
    html = "<p>" + "Descubre nuestras ofertas de vuelos y hoteles para esta temporada. " * 10 + "</p>"
    c = lector.leer(correo(cuerpo="Plain text version not available", html=html))
    assert "ofertas de vuelos" in c.cuerpo and "not available" not in c.cuerpo
    normal = "Hola Ana, te comparto el informe de la reunión de ayer con los compromisos de cada área."
    c = lector.leer(correo(cuerpo=normal, html=f"<p>{normal}</p>"))
    assert c.cuerpo == normal                                    # si ambos dicen lo mismo, se usa el texto plano


def test_remitente_ilegible_usa_el_texto_crudo():
    """Un From roto no tumba el análisis en ninguna versión de Python: se analiza con lo que se alcanza a leer."""
    c = lector.leer(b"From: Bancolombia <alertas@bancolombia-seguro.xyz\nSubject: Hola\n\nTexto")
    assert c.asunto == "Hola" and "bancolombia" in (c.remitente_correo + c.remitente_nombre).lower()
