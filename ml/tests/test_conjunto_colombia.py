"""Manifiesto, campañas, división por campaña, intervalos y el modo «solo contenido» de la evaluación."""
from __future__ import annotations

import csv
import json
import random
from email.message import EmailMessage

import conjunto_colombia as cc
import evaluar_colombia as ev
import importar_sandbox as imp
import pytest
from centinela.adaptadores.salida.inspector_adjuntos import InspectorAdjuntos
from centinela.adaptadores.salida.lector_correo import LectorCorreoMime
from test_importar_sandbox import correo_malicioso

GOOGLE = ("mx.google.com; dkim=pass header.i=@banco.co; spf=pass smtp.mailfrom=banco.co; dmarc=pass header.from=banco.co")
RELLENO = ("Le recordamos que puede consultar el detalle de sus movimientos en la aplicación oficial o en cualquiera de "
           "nuestras oficinas en el horario habitual de atención al público de lunes a viernes.")


def correo(remitente: str, asunto: str, cuerpo: str, auth: str | None = None) -> bytes:
    m = EmailMessage()
    m["Received"] = "from mail.ejemplo.co by mx.google.com with ESMTPS id x; Tue, 01 Oct 2026 10:00:00 -0700"
    if auth:
        m["Authentication-Results"] = auth
    m["X-Gm-Message-State"] = "AOJu0Yw"
    m["From"], m["To"], m["Subject"] = remitente, "yo@gmail.com", asunto
    m["Date"] = "Tue, 01 Oct 2026 10:00:00 -0500"
    m.set_content(cuerpo)
    return m.as_bytes()


VOCABULARIO = ["cuenta", "pago", "factura", "envío", "bodega", "clave", "tarjeta", "saldo", "oficina", "cliente", "reunión", "informe", "proyecto", "viaje", "colegio", "salud", "cita", "médico", "premio", "sorteo", "bono", "crédito", "deuda", "cobro", "embargo", "multa", "paquete", "pedido", "tienda", "descuento", "evento", "curso", "beca", "nómina", "contrato", "arriendo", "servicio", "energía", "agua", "gas", "internet", "plan"]


def plantilla(semilla: str, n: int = 40) -> str:
    """Texto propio de cada campaña: campañas distintas no se parecen entre sí."""
    rng = random.Random(semilla)
    return " ".join(rng.choice(VOCABULARIO) for _ in range(n)) + "."


def poblar(datos, n_campanas_phishing=6, n_campanas_legitimas=6, por_campana=3):
    """Campañas de phishing (misma plantilla con datos distintos) y legítimos (boletines de varias empresas)."""
    cc.crear_arbol(datos)
    for k in range(n_campanas_phishing):
        for j in range(por_campana):
            (datos / "phishing" / "bancos" / f"c{k}-{j}.eml").write_bytes(texto_campana(k, j))
    for k in range(n_campanas_legitimas):
        for j in range(por_campana):
            cuerpo = f"Hola, te compartimos el boletín {j} con las novedades del mes. " + plantilla(f"legitimo-{k}")
            (datos / "legitimo" / "boletines" / f"b{k}-{j}.eml").write_bytes(
                correo(f"Empresa {k} <noticias@empresa{k}.co>", f"Boletín mensual empresa {k}", cuerpo, GOOGLE))


def texto_campana(k: int, j: int) -> bytes:
    cuerpo = (f"Estimado cliente {j}, su cuenta número {1000 + j} presenta un bloqueo. Ingrese a "
              f"http://banco-{k}.xyz/validar para reactivarla. " + plantilla(f"phishing-{k}"))
    return correo(f"Banco <alertas@banco-{k}.xyz>", f"Bloqueo preventivo {k} cuenta {j}", cuerpo)


@pytest.fixture
def datos(tmp_path, monkeypatch):
    d = tmp_path / "colombia"
    monkeypatch.setattr(cc, "DATOS", d)
    return d


# ------------------------------------------------------------------------------------------------- árbol y manifiesto
def test_crear_arbol(datos):
    hechos = cc.crear_arbol()
    for etiqueta, categorias in cc.CATEGORIAS.items():
        for c in categorias:
            assert (datos / etiqueta / c).is_dir()
    for nombre, columnas in (("manifiesto.csv", cc.COLUMNAS_MANIFIESTO), ("reconstruidos.csv", cc.COLUMNAS_RECONSTRUIDOS)):
        assert next(csv.reader((datos / nombre).open())) == list(columnas)
    assert len(hechos) == 2 and cc.crear_arbol() == []                     # idempotente
    assert "url_fuente" in cc.COLUMNAS_RECONSTRUIDOS and "entidad" in cc.COLUMNAS_RECONSTRUIDOS


def test_manifiesto_campanas_duplicados_y_correcciones(datos):
    poblar(datos, 2, 2, 3)
    (datos / "phishing" / "bancos" / "copia.eml").write_bytes((datos / "phishing" / "bancos" / "c0-0.eml").read_bytes())
    with (datos / "reconstruidos.csv").open("a", newline="") as f:
        csv.writer(f).writerow(["phishing", "gobierno", "DIAN <notificaciones@dian-cobros.com>", "Proceso de embargo",
                                "Usted tiene un proceso de cobro coactivo pendiente.", "http://dian-cobros.com/x",
                                "https://www.dian.gov.co/alerta", "DIAN", "2026-09-30"])
    filas, s = cc.sincronizar()
    assert len(filas) == 13 and s.duplicados == [("phishing/bancos/copia.eml", "phishing/bancos/c0-0.eml")]
    por_archivo = {f["archivo"]: f for f in filas}
    rec = por_archivo["reconstruidos.csv#2"]
    assert (rec["origen"], rec["url_fuente"], rec["fecha"]) == ("reconstruido", "https://www.dian.gov.co/alerta", "2026-09-30")
    assert por_archivo["phishing/bancos/c0-1.eml"]["fecha"] == "2026-10-01"
    campanas = Counter_(filas)
    assert sorted(campanas.values()) == [1, 3, 3, 3, 3]                   # 4 campañas de 3 + el reconstruido
    assert all(c.startswith("auto-") for c in campanas)

    # correcciones a mano: se respetan al volver a sincronizar y al recalcular
    for f in filas:
        if f["archivo"].startswith("phishing/bancos/c0-"):
            f["campana"] = "bloqueo-banco-0"
        if f["archivo"] == "phishing/bancos/c1-0.eml":
            f["origen"] = "contribuido"
    cc.escribir_manifiesto(filas)
    nuevas, _ = cc.sincronizar(recalcular_campanas=True)
    por_archivo = {f["archivo"]: f for f in nuevas}
    assert {por_archivo[f"phishing/bancos/c0-{j}.eml"]["campana"] for j in range(3)} == {"bloqueo-banco-0"}
    assert por_archivo["phishing/bancos/c1-0.eml"]["origen"] == "contribuido"

    # un correo nuevo de una campaña conocida hereda su nombre; uno borrado sale del manifiesto
    (datos / "phishing" / "bancos" / "c0-9.eml").write_bytes(texto_campana(0, 9))
    (datos / "legitimo" / "boletines" / "b0-0.eml").unlink()
    filas, s = cc.sincronizar()
    assert {f["archivo"]: f for f in filas}["phishing/bancos/c0-9.eml"]["campana"] == "bloqueo-banco-0"
    assert s.retirados == ["legitimo/boletines/b0-0.eml"]


def Counter_(filas):
    from collections import Counter
    return Counter(f["campana"] for f in filas)


def test_correos_personales_no_se_agrupan_por_ser_de_gmail():
    a = cc.huella(correo("Ana <ana@gmail.com>", "Reunión del viernes en la oficina", "nos vemos"))
    b = cc.huella(correo("Luis <luis@gmail.com>", "Reunión del viernes en la oficina", "listo"))
    c = cc.huella(correo("Ana <ana@gmail.com>", "Re: Reunión del viernes en la oficina", "ok"))
    corto = cc.huella(correo("Ana <ana@gmail.com>", "hola", "x"))
    otro_corto = cc.huella(correo("Ana <ana@gmail.com>", "hola", "y"))
    grupos = cc.agrupar(["legitimo"] * 5, [a, b, c, corto, otro_corto])
    assert grupos[0] == grupos[2]                  # misma persona, mismo asunto (con «Re:»)
    assert grupos[0] != grupos[1]                  # mismo asunto pero otra persona de gmail.com
    assert grupos[3] != grupos[4]                  # asuntos muy cortos no bastan
    assert cc.agrupar(["legitimo", "phishing"], [a, c])[0] != cc.agrupar(["legitimo", "phishing"], [a, c])[1]


def test_simhash_textos_casi_iguales():
    base = "Su paquete está retenido en la bodega por falta de pago del arancel. " + RELLENO
    assert (cc.simhash(base) ^ cc.simhash(base.replace("bodega", "aduana"))).bit_count() <= cc.MAX_DISTANCIA_SIMHASH
    assert (cc.simhash(base) ^ cc.simhash("Mañana hay reunión de padres en el colegio. " + RELLENO[::-1])).bit_count() > 10
    assert cc.simhash("muy corto") is None


# ------------------------------------------------------------------------------------------------------- división
def test_division_por_campana_estratificada(datos):
    poblar(datos, 8, 8, 3)
    filas, _ = cc.sincronizar()
    p = cc.dividir(filas)
    assert p.regenerada and cc.campanas_repartidas(filas, p.conjunto) == []
    for etiqueta in ("legitimo", "phishing"):
        conj = [p.conjunto[f["sha256"]] for f in filas if f["etiqueta"] == etiqueta]
        assert conj.count("ajuste") == conj.count("prueba") == 12      # 4 campañas de 3 a cada lado
    # estable: correr otra vez no cambia nada; un correo nuevo sigue a su campaña
    assert cc.dividir(filas).conjunto == p.conjunto
    (datos / "phishing" / "bancos" / "c3-7.eml").write_bytes(texto_campana(3, 7))
    filas2, _ = cc.sincronizar()
    p2 = cc.dividir(filas2)
    campana3 = next(f["campana"] for f in filas2 if f["archivo"] == "phishing/bancos/c3-0.eml")
    assert {p2.conjunto[f["sha256"]] for f in filas2 if f["campana"] == campana3} == {p.conjunto[
        next(f["sha256"] for f in filas if f["archivo"] == "phishing/bancos/c3-0.eml")]}
    assert all(p2.conjunto[s] == c for s, c in p.conjunto.items())


def test_division_antigua_se_regenera_si_la_prueba_no_se_abrio(datos):
    poblar(datos, 4, 4, 2)
    filas, _ = cc.sincronizar()
    with (datos / "particion.csv").open("w", newline="") as f:                 # formato anterior: por hash
        w = csv.writer(f)
        w.writerow(["id", "conjunto"])
        w.writerows([(x["sha256"][:16], "prueba" if i % 2 else "ajuste") for i, x in enumerate(filas)])
    p = cc.dividir(filas)
    assert p.regenerada and "regeneró por campaña" in p.avisos[0]
    assert cc.campanas_repartidas(filas, p.conjunto) == []


def test_con_la_prueba_abierta_la_division_se_congela(datos):
    poblar(datos, 4, 4, 2)
    filas, _ = cc.sincronizar()
    p = cc.dividir(filas)
    cc.sellar_prueba()
    assert json.loads((datos / "prueba_abierta.json").read_text())["particion_sha256"]
    with pytest.raises(SystemExit):
        cc.dividir(filas, regenerar=True)
    (datos / "legitimo" / "boletines" / "nuevo.eml").write_bytes(correo("Otra <hola@otra.co>", "Algo totalmente distinto",
                                                                         "Contenido nuevo " + RELLENO[::-1]))
    filas2, _ = cc.sincronizar()
    p2 = cc.dividir(filas2)
    assert all(p2.conjunto[s] == c for s, c in p.conjunto.items())
    assert [p2.conjunto[f["sha256"]] for f in filas2 if f["archivo"].endswith("nuevo.eml")] == ["posterior"]


# ------------------------------------------------------------------------------------------------- estadísticas
def test_wilson():
    assert cc.wilson(0, 200) == [0.0, 0.0188]                           # sin errores el límite superior NO es 0
    lo, hi = cc.wilson(50, 100)
    assert lo == pytest.approx(0.4038, abs=1e-4) and hi == pytest.approx(0.5962, abs=1e-4)
    assert cc.wilson(0, 0) == [None, None]


# --------------------------------------------------------------------------------------------- solo contenido
def test_solo_contenido_quita_los_encabezados_de_recepcion():
    crudo = correo("Banco <a@banco.co>", "Hola", "texto", GOOGLE)
    crudo = crudo.replace(b"From:", b"ARC-Seal: i=1; a=rsa-sha256;\n b=abc\nX-Google-Smtp-Source: xyz\nFrom:", 1)
    limpio = ev.sin_encabezados_de_recepcion(crudo)
    for h in (b"Received:", b"Authentication-Results:", b"ARC-Seal:", b" b=abc", b"X-Gm-", b"X-Google-"):
        assert h not in limpio
    assert b"From: Banco <a@banco.co>" in limpio and limpio.endswith(b"texto\n")
    lector = LectorCorreoMime(b"x")
    antes, despues = lector.leer(crudo), lector.leer(limpio)
    assert antes.autenticacion.confiable and antes.saltos == 1
    assert not despues.autenticacion.confiable and despues.saltos == 0 and despues.autenticacion.spf is None


def test_la_inspeccion_guardada_reproduce_lo_que_veria_produccion():
    original = correo_malicioso()
    saneado = imp.sanear(original).crudo
    real = LectorCorreoMime(b"x", InspectorAdjuntos()).leer(original)
    reproductor = ev.InspectorReproducido(InspectorAdjuntos())
    reproductor.preparar(saneado)
    rep = LectorCorreoMime(b"x", reproductor).leer(saneado)
    clave = lambda a: (a.nombre, a.tipo_mime, a.tipo_real, a.senales, a.contenido)
    adj_real = [clave(a) for a in real.adjuntos if a.nombre != "otro.exe"]       # el que venía dentro del reenviado
    assert [clave(a) for a in rep.adjuntos if a.nombre != "(sin nombre)"] == [x for x in adj_real if x[0] != "(sin nombre)"]
    assert {e.url for e in rep.enlaces} >= {"https://qr-bancolombia.xyz/validar", "https://bancolombia-seguridad.xyz/login"}
    assert reproductor.reproducidas >= 4
