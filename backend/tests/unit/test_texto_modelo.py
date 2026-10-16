"""Normalización compartida entre entrenamiento y producción: debe borrar las diferencias de sanitización."""
from pathlib import Path

from centinela.adaptadores.salida.ml.clasificadores import ModeloTextoLineal
from centinela.adaptadores.salida.ml.texto import NOMBRES_RASGOS, normalizar, rasgos

V2 = Path(__file__).resolve().parents[2] / "modelos" / "contenido" / "v2-corpus-combinado"


def test_dataset_sanitizado_y_correo_real_quedan_iguales():
    dataset = normalizar("Su cuenta", "Estimada/o Ernesto Pacheco,  Verifique en hxxp://banco[.]info/x ya. Tel <TELEFONO>, "
                                      "escriba a <EMAIL>")
    real = normalizar("Su cuenta", "Hola Ana María,\nVerifique en https://banco.info/x ya. Tel 300 555 1234, "
                                   "escriba a soporte@banco.info")
    assert dataset == real == "su cuenta verifique en zurl ya. tel ztelefono , escriba a zcorreo"


def test_rasgos_sin_artefactos_de_marcadores():
    con_marcador = dict(zip(NOMBRES_RASGOS, rasgos("Hola", "Llame al <TELEFONO> ya"), strict=True))
    sin_marcador = dict(zip(NOMBRES_RASGOS, rasgos("Hola", "Llame al 3005551234 ya"), strict=True))
    assert con_marcador == sin_marcador


def test_modelo_v2_normaliza_y_calibra():
    m = ModeloTextoLineal(V2 / "es.json")
    assert m.normalizacion == "1"
    texto = m.preparar("Verifique su cuenta", "Estimado cliente, verifique su cuenta de inmediato en http://x.top/login")
    assert "zurl" in texto and "estimado" not in texto
    assert 0.0 <= m.probabilidad(texto) <= 1.0
    assert m.probabilidad(texto) > m.probabilidad(m.preparar("Acta", "Comparto el acta de la reunión del martes."))
