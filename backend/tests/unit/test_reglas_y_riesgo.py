"""Reglas expertas, combinación del riesgo y política de cuarentena (dominio puro)."""
import pytest

from centinela.dominio.buzon import ModoCuarentena
from centinela.dominio.correo import Adjunto, Autenticacion, CorreoParseado, Enlace, ResultadoAuth
from centinela.dominio.entidades import CatalogoEntidades, Entidad
from centinela.dominio.politica import decidir_acciones
from centinela.dominio.reglas import evaluar_reglas
from centinela.dominio.riesgo import Area, Gravedad, NivelRiesgo, Razon, combinar_riesgo

CATALOGO = CatalogoEntidades([
    Entidad(1, "DIAN", "gobierno", ("dian", "impuestos y aduanas"), ("dian.gov.co",)),
    Entidad(2, "Bancolombia", "banco", ("bancolombia",), ("bancolombia.com", "grupobancolombia.com")),
    Entidad(3, "Nequi", "billetera_digital", ("nequi",), ("nequi.com.co",)),
])
P = ResultadoAuth.PASS
GOOGLE_OK = Autenticacion(spf=P, dkim=P, dmarc=P, confiable=True)


def correo(**kw):
    base = dict(asunto="Hola", remitente_nombre="Ana", remitente_correo="ana@ejemplo.co", remitente_dominio="ejemplo.co",
                cuerpo="Texto normal del correo sin nada raro.", autenticacion=GOOGLE_OK)
    return CorreoParseado(**{**base, **kw})


def areas(c):
    return {(r.area, r.gravedad) for r in evaluar_reglas(c, CATALOGO).razones}


def test_correo_normal_no_dispara_reglas():
    r = evaluar_reglas(correo(), CATALOGO)
    assert r.razones == [] and "SPF, DKIM y DMARC" in r.positivas[0]


def test_dmarc_fallido_es_alta():
    c = correo(autenticacion=Autenticacion(spf=ResultadoAuth.FAIL, dmarc=ResultadoAuth.FAIL, confiable=True))
    assert (Area.AUTENTICACION, Gravedad.ALTA) in areas(c) and (Area.AUTENTICACION, Gravedad.MEDIA) in areas(c)


def test_autenticacion_no_confiable_se_ignora():
    c = correo(autenticacion=Autenticacion(dmarc=ResultadoAuth.FAIL, confiable=False))
    assert not any(a is Area.AUTENTICACION for a, _ in areas(c))


def test_suplantacion_desde_cuenta_gratuita():
    c = correo(remitente_nombre="Nequi Soporte", remitente_dominio="gmail.com")
    razon = next(r for r in evaluar_reglas(c, CATALOGO).razones if r.area is Area.SUPLANTACION)
    assert razon.gravedad is Gravedad.ALTA and razon.entidad_id == 3 and "cuenta gratuita" in razon.texto


def test_dominio_que_imita_a_la_entidad():
    c = correo(remitente_dominio="dian-notificaciones.com", asunto="Notificación")
    assert any("imita el nombre de DIAN" in r.texto for r in evaluar_reglas(c, CATALOGO).razones)


def test_mencion_en_el_cuerpo_es_media_y_dominio_oficial_no_se_acusa():
    assert (Area.SUPLANTACION, Gravedad.MEDIA) in areas(correo(cuerpo="Su pago a Bancolombia está pendiente de revisión."))
    oficial = correo(remitente_nombre="Bancolombia", remitente_dominio="notificaciones.bancolombia.com")
    r = evaluar_reglas(oficial, CATALOGO)
    assert not any(x.area is Area.SUPLANTACION for x in r.razones) and r.remitente_verificado


def test_enlaces_enganosos_acortados_e_ip():
    c = correo(enlaces=(Enlace("http://bancolombia-seguro.top/login", "www.bancolombia.com"),
                        Enlace("https://bit.ly/abc"), Enlace("http://192.168.10.5/pago"),
                        Enlace("javascript:alert(1)")))
    textos = " ".join(r.texto for r in evaluar_reglas(c, CATALOGO).razones)
    for esperado in ("dice «www.bancolombia.com» pero en realidad lleva a bancolombia-seguro.top",
                     "acortado (bit.ly)", "dirección IP", "ejecuta código", "usa el nombre de Bancolombia"):
        assert esperado in textos


@pytest.mark.parametrize("nombre,gravedad", [("factura.pdf.exe", Gravedad.ALTA), ("instalador.msi", Gravedad.ALTA),
                                             ("acceso.html", Gravedad.ALTA), ("informe.docm", Gravedad.MEDIA),
                                             ("fotos.zip", Gravedad.MEDIA)])
def test_adjuntos_peligrosos(nombre, gravedad):
    assert (Area.ADJUNTO, gravedad) in areas(correo(adjuntos=(Adjunto(nombre, "application/x", 10),)))


def test_pretextos_colombianos():
    c = correo(asunto="Notificación de fotomulta", cuerpo="Tiene un comparendo pendiente, pague vía PSE.")
    assert any("pretexto común en fraudes en Colombia" in r.texto for r in evaluar_reglas(c, CATALOGO).razones)


def test_combinacion_del_riesgo():
    alta = Razon(Area.AUTENTICACION, Gravedad.ALTA, "x")
    media = Razon(Area.REMITENTE, Gravedad.MEDIA, "y")
    r = combinar_riesgo(None, None, [alta, media])
    assert r.p_tecnico == pytest.approx(1 - 0.55 * 0.80)
    # contenido 0.8, enlaces 0.6·0.9 = 0.54, técnico 0.56 → tres fuentes ≥ 0.5 → 0.8 + 2·0.05
    assert combinar_riesgo(0.8, 0.9, [alta, media]).p_final == pytest.approx(0.9)
    assert combinar_riesgo(0.8, 0.1, []).p_final == pytest.approx(0.8)                    # una sola fuente, sin bono
    assert combinar_riesgo(None, 1.0, []).p_final == pytest.approx(0.6)                  # enlaces solos: máximo MEDIO
    assert combinar_riesgo(None, None, [Razon(Area.CONTENIDO, Gravedad.ALTA, "z")]).p_final == 0.0
    assert combinar_riesgo(0.99, 0.99, [alta] * 5).p_final == 0.99                        # tope


def test_remitente_verificado_atenua_solo_si_no_hay_senales_tecnicas():
    assert combinar_riesgo(0.4, None, [], remitente_verificado=True).p_final == pytest.approx(0.2)
    assert combinar_riesgo(0.6, None, [], remitente_verificado=True).p_final == pytest.approx(0.3)   # sigue MEDIO
    alta = Razon(Area.ADJUNTO, Gravedad.ALTA, "x")
    assert combinar_riesgo(0.4, None, [alta], remitente_verificado=True).p_final == pytest.approx(0.45)


def test_politica_de_cuarentena():
    auto, solo = ModoCuarentena.CUARENTENA_AUTOMATICA, ModoCuarentena.SOLO_AVISAR
    assert decidir_acciones(NivelRiesgo.ALTO, auto, True).cuarentena
    a = decidir_acciones(NivelRiesgo.ALTO, solo, True)
    assert (a.cuarentena, a.etiquetar_sospechoso, a.avisar) == (False, True, True)
    a = decidir_acciones(NivelRiesgo.MEDIO, auto, True)
    assert (a.cuarentena, a.etiquetar_sospechoso, a.avisar) == (False, True, False)
    assert decidir_acciones(NivelRiesgo.BAJO, auto, True) == decidir_acciones(NivelRiesgo.BAJO, solo, False)
