"""Evaluación de Centinela con correos colombianos: el experimento central de la tesis.

Evalúa la configuración de PRODUCCIÓN (modelos activos del registro + catálogo de la BD + reglas + inspector de
adjuntos) sobre correos que nunca se usaron para entrenar. Los correos se registran en datos/colombia/manifiesto.csv
(scripts/manifiesto.py o scripts/importar_sandbox.py); este script se niega a correr si hay archivos sin registrar.

División SELLADA por campaña: cada campaña (correos casi duplicados) va entera a "ajuste" (50 %) o a "prueba" (50 %),
estratificado por clase, y queda guardada en datos/colombia/particion.csv. Ajuste = análisis de errores y mejoras.
Prueba = cifra final de la tesis; solo se abre con --abrir-prueba-final, una vez, y desde ahí la división se congela.

    uv run python -I scripts/evaluar_colombia.py                              # ajuste, sistema completo
    uv run python -I scripts/evaluar_colombia.py --solo-contenido             # sin encabezados de recepción
    uv run python -I scripts/evaluar_colombia.py --conjunto prueba --abrir-prueba-final

Sesgo de procedencia: los legítimos exportados de Gmail traen la autenticación de Google y los de sandboxes no, así
que el sistema podría "acertar" por la procedencia y no por el contenido. Por eso el informe se desglosa por origen
y --solo-contenido quita los encabezados que agrega la recepción (Received, ARC, Authentication-Results, X-Gm-*...):
sin ellos, la autenticación queda "desconocida" (nunca cuenta como phishing) y saltos = 0 para todos.
"""
from __future__ import annotations

import argparse
import base64
import csv
import json
import re
import sys
import time
from collections import Counter
from datetime import datetime
from email import policy
from email.parser import BytesParser
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))      # python -I no agrega la carpeta del script
import conjunto_colombia as cc
from centinela.adaptadores.salida.inspector_adjuntos import Inspeccion, InspectorAdjuntos
from centinela.adaptadores.salida.lector_correo import LectorCorreoMime
from centinela.aplicacion.casos_uso.analisis import MotorAnalisis
from centinela.config import Configuracion
from centinela.contenedor import construir
from centinela.dominio.correo import SenalAdjunto
from importar_sandbox import ENCABEZADO_INSPECCION, ENCABEZADO_RETIRADO

SALIDA = cc.RAIZ_ML / "resultados"
ENV_BACKEND = cc.RAIZ_ML.parent / "backend" / ".env"
NIVELES = ("bajo", "medio", "alto")

# Encabezados que agrega la RECEPCIÓN del correo (no el remitente): revelan por dónde llegó, no qué dice.
_RE_RECEPCION = re.compile(
    rb"(?i)^(received|x-received|received-spf|authentication-results|x-original-authentication-results|arc-[a-z-]+|"
    rb"x-gm-[a-z0-9-]+|x-google-[a-z0-9-]+|delivered-to|return-path|x-ms-exchange-organization-auth[a-z-]*|"
    rb"x-ms-exchange-authentication-results?)\s*:")


def sin_encabezados_de_recepcion(crudo: bytes) -> bytes:
    cortes = [(i, sep) for sep in (b"\r\n\r\n", b"\n\n") if (i := crudo.find(sep)) >= 0]
    if not cortes:
        return crudo
    fin, sep = min(cortes)
    lineas = crudo[:fin].splitlines(keepends=True)
    quedan, quitar = [], False
    for linea in lineas:
        if linea[:1] in (b" ", b"\t"):                      # continuación del encabezado anterior
            if not quitar:
                quedan.append(linea)
            continue
        quitar = bool(_RE_RECEPCION.match(linea))
        if not quitar:
            quedan.append(linea)
    cabeza = b"".join(quedan).rstrip(b"\r\n")
    return cabeza + sep + crudo[fin + len(sep):]


class InspectorReproducido:
    """En los correos saneados (sandbox) el adjunto está vacío: se usa la inspección que se hizo en memoria al
    importarlo (X-Centinela-Inspeccion). En los demás correos se inspecciona de verdad, igual que en producción."""

    def __init__(self, real: InspectorAdjuntos):
        self._real = real
        self._adjuntos: list[dict | None] = []
        self._imagenes: list[dict | None] = []
        self.reproducidas = 0

    def preparar(self, crudo: bytes) -> None:
        self._adjuntos, self._imagenes = [], []
        for parte in BytesParser(policy=policy.default).parsebytes(crudo).walk():   # mismo recorrido que el lector
            if parte.is_multipart():
                continue
            guardada = None
            if parte[ENCABEZADO_RETIRADO] is not None and parte[ENCABEZADO_INSPECCION] is not None \
                    and not parte.get_payload(decode=True):
                guardada = json.loads(base64.b64decode(str(parte[ENCABEZADO_INSPECCION])))
            tipo, disposicion = parte.get_content_type(), parte.get_content_disposition()
            if tipo.startswith("image/") and disposicion != "attachment":
                self._imagenes.append(guardada)
            elif disposicion == "attachment" or parte.get_filename() or tipo not in ("text/plain", "text/html"):
                self._adjuntos.append(guardada)

    def inspeccionar(self, nombre: str, tipo_mime: str, datos: bytes) -> Inspeccion:
        g = self._adjuntos.pop(0) if self._adjuntos else None
        if g is None:
            return self._real.inspeccionar(nombre, tipo_mime, datos)
        self.reproducidas += 1
        return Inspeccion(g.get("tipo_real"), tuple(SenalAdjunto(s) for s in g.get("senales", [])),
                          tuple(g.get("contenido", [])), tuple(g.get("enlaces", [])), tuple(g.get("qr", [])))

    def qr_de_imagen(self, datos: bytes) -> tuple[str, ...]:
        g = self._imagenes.pop(0) if self._imagenes else None
        if g is None:
            return self._real.qr_de_imagen(datos)
        self.reproducidas += 1
        return tuple(g.get("qr", []))


class SoloAlgunosModelos:
    """Para la ablación: deja pasar solo los modelos indicados."""

    def __init__(self, base, contenido: bool, enlaces: bool):
        self._base, self._c, self._e = base, contenido, enlaces

    def contenido(self):
        return self._base.contenido() if self._c else None

    def enlaces(self):
        return self._base.enlaces() if self._e else None


def _tasa(marcas: np.ndarray) -> dict:
    k, n = int(marcas.sum()), len(marcas)
    return {"k": k, "n": n, "tasa": round(k / n, 4) if n else None, "ic95": cc.wilson(k, n)}


def metricas(y: np.ndarray, nivel: np.ndarray, desde: str) -> dict:
    pred = np.isin(nivel, NIVELES[NIVELES.index(desde):])
    leg, phi = pred[y == 0], pred[y == 1]
    tp, fp = int(phi.sum()), int(leg.sum())
    return {"recall": _tasa(phi), "fp_en_legitimos": _tasa(leg),
            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
            "vp": tp, "fp": fp, "fn": int((~phi).sum()), "vn": int((~leg).sum())}


def desglose(claves: list[str], y: np.ndarray, niveles: np.ndarray) -> dict:
    """Por grupo: en legítimos la tasa es de FALSOS POSITIVOS; en phishing, de detección (recall)."""
    salida = {}
    for clave in sorted(set(claves)):
        mask = np.array([c == clave for c in claves])
        for e, nombre in ((0, "legitimo"), (1, "phishing")):
            m = mask & (y == e)
            if not m.any():
                continue
            salida[f"{clave} · {nombre}"] = {
                "metrica": "falsos_positivos" if e == 0 else "recall",
                "marcado_≥medio": _tasa(np.isin(niveles[m], ("medio", "alto"))),
                "cuarentena_alto": _tasa(niveles[m] == "alto")}
    return salida


def _fmt(t: dict) -> str:
    if t["tasa"] is None:
        return "      —      "
    lo, hi = t["ic95"]
    return f"{t['tasa']:6.3f} [{lo:.3f}–{hi:.3f}] (n={t['n']})"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--conjunto", choices=["ajuste", "prueba"], default="ajuste")
    ap.add_argument("--abrir-prueba-final", action="store_true")
    ap.add_argument("--solo-contenido", action="store_true",
                    help="quita los encabezados de recepción (Received, ARC, Authentication-Results, X-Gm-*, ...)")
    ap.add_argument("--regenerar-particion", action="store_true",
                    help="rehace la división por campaña (solo si la prueba no se ha abierto)")
    args = ap.parse_args()
    if args.conjunto == "prueba" and not args.abrir_prueba_final:
        raise SystemExit("El conjunto de prueba está sellado. Úsalo solo para la cifra final (--abrir-prueba-final).")

    filas, sinc = cc.sincronizar(origen_por_defecto=None)
    if sinc.sin_registrar:
        raise SystemExit(f"Hay {len(sinc.sin_registrar)} correo(s) sin registrar en el manifiesto (p. ej. "
                         f"{sinc.sin_registrar[0]}). Corre: uv run python -I scripts/manifiesto.py --origen <origen>")
    if not filas:
        raise SystemExit(f"No hay correos en {cc.DATOS}. Ver ml/GUIA_DATOS_COLOMBIA.md")
    for a in sinc.avisos:
        print(f"! {a}")
    if sinc.duplicados:
        print(f"! {len(sinc.duplicados)} archivo(s) idénticos a otro ya registrado: no se cuentan dos veces.")

    particion = cc.dividir(filas, regenerar=args.regenerar_particion)
    for a in particion.avisos:
        print(f"! {a}")
    repartidas = cc.campanas_repartidas(filas, particion.conjunto)
    if repartidas and not cc.prueba_abierta():
        raise SystemExit(f"Campañas repartidas entre ajuste y prueba: {repartidas[:5]}")

    crudos = {c.sha256: c.crudo for c in cc.explorar()[0]}
    elegidas = [f for f in filas if particion.conjunto.get(f["sha256"]) == args.conjunto]
    if not elegidas:
        raise SystemExit(f"El conjunto «{args.conjunto}» está vacío (hacen falta al menos 2 campañas).")

    c = construir(Configuracion(_env_file=ENV_BACKEND))
    inspector = InspectorReproducido(InspectorAdjuntos())
    lector = LectorCorreoMime(b"evaluacion", inspector)
    with c.uow() as uow:
        catalogo = uow.entidades.catalogo()
        modelos = {t: (m.id, m.version) if (m := uow.modelos.activo(t)) else None for t in ("contenido", "enlaces")}
    variantes = {"sistema_completo": MotorAnalisis(c.modelos),
                 "solo_reglas": MotorAnalisis(SoloAlgunosModelos(c.modelos, False, False)),
                 "reglas_y_enlaces": MotorAnalisis(SoloAlgunosModelos(c.modelos, False, True)),
                 "reglas_y_texto": MotorAnalisis(SoloAlgunosModelos(c.modelos, True, False))}

    correos = []
    for f in elegidas:
        crudo = crudos[f["sha256"]]
        if args.solo_contenido:
            crudo = sin_encabezados_de_recepcion(crudo)
        inspector.preparar(crudo)
        correos.append(lector.leer(crudo))
    y = np.array([1 if f["etiqueta"] == "phishing" else 0 for f in elegidas])
    resultados, errores, tiempos = {}, [], []
    niveles_completo = None
    for nombre, motor in variantes.items():
        niveles = []
        for f, correo in zip(elegidas, correos, strict=True):
            t0 = time.perf_counter()
            r = motor.analizar(correo, catalogo)
            if nombre == "sistema_completo":
                tiempos.append((time.perf_counter() - t0) * 1000)
                v = r.veredicto
                if (v.nivel.value != "bajo") != (f["etiqueta"] == "phishing"):
                    errores.append({"sha256": f["sha256"][:16], "archivo": f["archivo"], "etiqueta": f["etiqueta"],
                                    "categoria": f["categoria"], "origen": f["origen"], "campana": f["campana"],
                                    "nivel": v.nivel.value, "p_final": v.p_final, "p_texto": v.p_contenido,
                                    "p_enlaces": v.p_enlaces, "p_tecnico": v.p_tecnico,
                                    "razones": " | ".join(x.texto for x in (v.razones_visibles or v.razones[:3]))})
            niveles.append(r.veredicto.nivel.value)
        niveles = np.array(niveles)
        resultados[nombre] = {"cuarentena (ALTO)": metricas(y, niveles, "alto"),
                              "marcado (≥MEDIO)": metricas(y, niveles, "medio")}
        if nombre == "sistema_completo":
            niveles_completo = niveles

    auth_google = Counter(f["origen"] for f, co in zip(elegidas, correos, strict=True) if co.autenticacion.confiable)
    por_origen_n = Counter(f["origen"] for f in elegidas)
    informe = {
        "fecha": datetime.now().isoformat(timespec="seconds"), "conjunto": args.conjunto,
        "modo": "solo_contenido" if args.solo_contenido else "completo",
        "n": len(elegidas), "phishing": int(y.sum()), "legitimos": int((y == 0).sum()),
        "campanas": len({f["campana"] for f in elegidas}),
        "manifiesto_sha256": cc.sha256((cc.DATOS / "manifiesto.csv").read_bytes()),
        "particion_sha256": cc.sha256((cc.DATOS / "particion.csv").read_bytes()),
        "modelos_activos": modelos, "resultados": resultados,
        "por_origen": desglose([f["origen"] for f in elegidas], y, niveles_completo),
        "por_categoria": desglose([f["categoria"] for f in elegidas], y, niveles_completo),
        "con_autenticacion_de_google": {o: round(auth_google[o] / n, 4) for o, n in por_origen_n.items()},
        "adjuntos_reproducidos_de_la_importacion": inspector.reproducidas,
        "latencia_ms": {"p50": round(float(np.percentile(tiempos, 50)), 1), "p95": round(float(np.percentile(tiempos, 95)), 1)},
    }
    if args.conjunto == "prueba":
        cc.sellar_prueba()

    SALIDA.mkdir(exist_ok=True)
    sello = datetime.now().strftime("%Y%m%d-%H%M")
    sufijo = f"{args.conjunto}{'_solo-contenido' if args.solo_contenido else ''}_{sello}"
    (SALIDA / f"colombia_{sufijo}.json").write_text(json.dumps(informe, ensure_ascii=False, indent=2))
    with (cc.DATOS / f"errores_{sufijo}.csv").open("w", newline="", encoding="utf-8") as f:   # queda fuera de git
        w = csv.DictWriter(f, fieldnames=list(errores[0]) if errores else ["sha256"])
        w.writeheader()
        w.writerows(errores)

    print(f"Conjunto «{args.conjunto}» ({informe['modo']}): {informe['n']} correos de {informe['campanas']} campañas "
          f"({informe['phishing']} phishing, {informe['legitimos']} legítimos)")
    print(f"Modelos activos: {modelos}\n")
    print(f"{'variante':18s} {'umbral':18s} {'recall [IC95 Wilson]':>34s} {'FP en legítimos [IC95 Wilson]':>34s} {'precisión':>9s}")
    for nombre, porumbral in resultados.items():
        for umbral, mm in porumbral.items():
            print(f"{nombre:18s} {umbral:18s} {_fmt(mm['recall']):>34s} {_fmt(mm['fp_en_legitimos']):>34s} "
                  f"{mm['precision'] if mm['precision'] is not None else '—':>9}")
    for titulo, grupos in (("origen", informe["por_origen"]), ("categoría", informe["por_categoria"])):
        print(f"\nPor {titulo} (sistema completo; en legítimos = falsos positivos, en phishing = detección):")
        for g, d in grupos.items():
            print(f"  {g:32s} ≥medio {_fmt(d['marcado_≥medio']):>30s}   alto {_fmt(d['cuarentena_alto']):>30s}")
    print(f"\nCon autenticación de Google, por origen: {informe['con_autenticacion_de_google']}")
    print(f"Latencia por correo: p50 {informe['latencia_ms']['p50']} ms · p95 {informe['latencia_ms']['p95']} ms")
    print(f"Errores para revisar (sin cuerpos): {len(errores)} → datos/colombia/errores_{sufijo}.csv")


if __name__ == "__main__":
    main()
