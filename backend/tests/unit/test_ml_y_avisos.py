"""Adaptadores de ML (con los modelos reales del repositorio) y redacción de avisos."""
import shutil
from pathlib import Path

import pytest

from centinela.adaptadores.salida.avisos import RedactorAvisosMime
from centinela.adaptadores.salida.lector_correo import LectorCorreoMime
from centinela.adaptadores.salida.ml.registro import (
    MANIFIESTO,
    ModeloAlterado,
    construir_clasificador,
    sha256_archivo,
    verificar,
)
from centinela.aplicacion.puertos import DatosAviso

MODELOS = Path(__file__).resolve().parents[2] / "modelos"
ENLACES = MODELOS / "enlaces" / "v3-prototipo"
CONTENIDO = MODELOS / "contenido" / "v1-prototipo"


def cargar(carpeta):
    return construir_clasificador(carpeta, verificar(carpeta, sha256_archivo(carpeta / MANIFIESTO)), modelo_id=7)


def test_modelo_alterado_no_se_carga(tmp_path):
    copia = tmp_path / "enlaces"
    shutil.copytree(ENLACES, copia)
    sha = sha256_archivo(copia / MANIFIESTO)
    with (copia / "modelo.json").open("a") as f:
        f.write(" ")                                         # un solo byte cambiado
    with pytest.raises(ModeloAlterado):
        verificar(copia, sha)
    with pytest.raises(ModeloAlterado):
        verificar(ENLACES, "0" * 64)


def test_modelo_de_enlaces():
    c = cargar(ENLACES)
    evs = c.evaluar(["https://www.bancolombia.com/personas", "http://192.168.1.20/secure-login/verify-account.php?id=99",
                     "https://bit.ly/3xYz"])
    sano, ip, corto = evs
    assert c.modelo_id == 7 and sano.dominio == "bancolombia.com"
    assert ip.probabilidad > sano.probabilidad
    assert corto.probabilidad is None                       # un acortador no se puntúa


def test_modelo_de_contenido_explica_con_palabras():
    c = cargar(CONTENIDO)
    phishing = c.evaluar("Su cuenta será suspendida",
                         "Estimado cliente, verifique su cuenta de inmediato ingresando su usuario y contraseña en el "
                         "siguiente enlace o su cuenta será bloqueada en 24 horas.")
    normal = c.evaluar("Reunión", "Hola equipo, les recuerdo que la reunión de mañana es a las 10 en la sala de juntas. "
                                  "Lleven el informe del mes por favor. Gracias.")
    assert phishing.idioma == "es" and phishing.probabilidad > normal.probabilidad
    if phishing.razones:
        assert "«" in phishing.razones[0].texto
    assert c.evaluar("123", "4567 890 !!! ### 2026-10-16 $$$ 99.99") is None       # sin idioma reconocible


def test_aviso_firmado_y_legible():
    clave = b"clave"
    crudo = RedactorAvisosMime(clave, "http://localhost:5173").redactar(DatosAviso(
        destinatario="ana@gmail.com", nivel="alto", remitente="Bancolombia <x@gmail.com>", asunto="Cuenta <bloqueada>",
        resumen="Este correo tiene señales claras de phishing.", razones=["Razón 1", "Razón 2"],
        accion="Lo movimos a cuarentena."))
    leido = LectorCorreoMime(clave).leer(crudo)
    assert leido.es_aviso_centinela and "Cuenta <bloqueada>" in leido.asunto
    assert "Razón 2" in leido.cuerpo
    assert not LectorCorreoMime(b"otra-clave").leer(crudo).es_aviso_centinela
