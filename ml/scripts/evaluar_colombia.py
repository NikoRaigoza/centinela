"""Evaluación de Centinela con correos colombianos reales: el experimento central de la tesis.

Evalúa la configuración de PRODUCCIÓN (modelos activos del registro + catálogo de la BD + reglas) sobre correos que
nunca se usaron para entrenar. Formatos aceptados en datos/colombia/:

    legitimo/<categoria>/*.eml   y  legitimo/<categoria>/*.mbox   (export de Gmail o Google Takeout)
    phishing/<categoria>/*.eml   y  phishing/<categoria>/*.mbox
    reconstruidos.csv            ejemplos de alertas públicas sin .eml (columnas: etiqueta, categoria, remitente,
                                 asunto, cuerpo, enlaces[separados por ;])

Partición SELLADA: la primera vez se divide cada correo en "ajuste" (50 %) o "prueba" (50 %) por hash y se guarda en
datos/colombia/particion.csv. Ajuste = análisis de errores y mejoras. Prueba = cifra final de la tesis; solo se abre
con --abrir-prueba-final y nunca se usa para tomar decisiones.

    uv run python -I scripts/evaluar_colombia.py --conjunto ajuste
    uv run python -I scripts/evaluar_colombia.py --conjunto prueba --abrir-prueba-final
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mailbox
import time
from dataclasses import dataclass
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

import numpy as np

from centinela.adaptadores.salida.lector_correo import LectorCorreoMime
from centinela.aplicacion.casos_uso.analisis import MotorAnalisis
from centinela.config import Configuracion
from centinela.contenedor import construir

RAIZ_ML = Path(__file__).resolve().parents[1]
DATOS = RAIZ_ML / "datos" / "colombia"
SALIDA = RAIZ_ML / "resultados"
ENV_BACKEND = RAIZ_ML.parent / "backend" / ".env"
NIVELES = ("bajo", "medio", "alto")


@dataclass
class Muestra:
    id: str
    origen: str          # archivo (sin contenido)
    etiqueta: int        # 1 = phishing
    categoria: str
    tipo: str            # eml | mbox | reconstruido
    crudo: bytes


def _id(crudo: bytes) -> str:
    return hashlib.sha256(crudo).hexdigest()[:16]


def cargar() -> list[Muestra]:
    muestras: dict[str, Muestra] = {}
    for clase, etiqueta in (("legitimo", 0), ("phishing", 1)):
        base = DATOS / clase
        for ruta in sorted(base.rglob("*")) if base.exists() else []:
            categoria = ruta.parent.name if ruta.parent != base else "general"
            if ruta.suffix.lower() == ".eml":
                crudo = ruta.read_bytes()
                muestras.setdefault(_id(crudo), Muestra(_id(crudo), str(ruta.relative_to(DATOS)), etiqueta, categoria, "eml", crudo))
            elif ruta.suffix.lower() == ".mbox":
                for i, msg in enumerate(mailbox.mbox(ruta)):
                    crudo = msg.as_bytes()
                    muestras.setdefault(_id(crudo), Muestra(_id(crudo), f"{ruta.relative_to(DATOS)}#{i}", etiqueta,
                                                            categoria, "mbox", crudo))
    csv_ruta = DATOS / "reconstruidos.csv"
    if csv_ruta.exists():
        with csv_ruta.open(encoding="utf-8-sig") as f:
            for i, fila in enumerate(csv.DictReader(f)):
                m = EmailMessage()
                m["From"], m["To"], m["Subject"] = fila["remitente"], "usuario@gmail.com", fila["asunto"]
                m["Message-ID"] = f"<reconstruido-{i}@centinela.local>"
                enlaces = [e.strip() for e in (fila.get("enlaces") or "").split(";") if e.strip()]
                m.set_content(fila["cuerpo"])
                if enlaces:
                    m.add_alternative("<p>" + fila["cuerpo"] + "</p>" + "".join(f'<a href="{e}">{e}</a> ' for e in enlaces),
                                      subtype="html")
                crudo = m.as_bytes()
                etiqueta = 1 if fila["etiqueta"].strip().lower() in ("1", "phishing") else 0
                muestras.setdefault(_id(crudo), Muestra(_id(crudo), f"reconstruidos.csv#{i + 2}", etiqueta,
                                                        fila.get("categoria") or "general", "reconstruido", crudo))
    return list(muestras.values())


def particion(muestras: list[Muestra]) -> dict[str, str]:
    """Partición estable: una vez creada no cambia (los correos nuevos se agregan, los viejos conservan su conjunto)."""
    ruta = DATOS / "particion.csv"
    asignada: dict[str, str] = {}
    if ruta.exists():
        with ruta.open() as f:
            asignada = {r["id"]: r["conjunto"] for r in csv.DictReader(f)}
    for m in muestras:
        if m.id not in asignada:
            asignada[m.id] = "prueba" if int(m.id, 16) % 2 else "ajuste"
    with ruta.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "conjunto"])
        w.writerows(sorted(asignada.items()))
    return asignada


class SoloAlgunosModelos:
    """Para la ablación: deja pasar solo los modelos indicados."""

    def __init__(self, base, contenido: bool, enlaces: bool):
        self._base, self._c, self._e = base, contenido, enlaces

    def contenido(self):
        return self._base.contenido() if self._c else None

    def enlaces(self):
        return self._base.enlaces() if self._e else None


def _ic(valores: np.ndarray, estadistico, n=1000, semilla=7) -> list[float]:
    if len(valores) == 0:
        return [float("nan"), float("nan")]
    rng = np.random.default_rng(semilla)
    muestras = [estadistico(valores[rng.integers(0, len(valores), len(valores))]) for _ in range(n)]
    return [round(float(np.percentile(muestras, 2.5)), 4), round(float(np.percentile(muestras, 97.5)), 4)]


def metricas(y: np.ndarray, nivel: np.ndarray, desde: str) -> dict:
    pred = np.isin(nivel, NIVELES[NIVELES.index(desde):])
    leg, phi = pred[y == 0], pred[y == 1]
    tp, fp = int(phi.sum()), int(leg.sum())
    return {
        "recall": round(float(phi.mean()), 4) if len(phi) else None, "recall_ic95": _ic(phi.astype(float), np.mean),
        "fp_en_legitimos": round(float(leg.mean()), 4) if len(leg) else None, "fp_ic95": _ic(leg.astype(float), np.mean),
        "precision": round(tp / (tp + fp), 4) if tp + fp else None, "vp": tp, "fp": fp,
        "fn": int((~phi).sum()), "vn": int((~leg).sum()),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--conjunto", choices=["ajuste", "prueba", "todo"], default="ajuste")
    ap.add_argument("--abrir-prueba-final", action="store_true")
    args = ap.parse_args()
    if args.conjunto in ("prueba", "todo") and not args.abrir_prueba_final:
        raise SystemExit("El conjunto de prueba está sellado. Úsalo solo para la cifra final (--abrir-prueba-final).")

    muestras = cargar()
    if not muestras:
        raise SystemExit(f"No hay correos en {DATOS}. Ver ml/GUIA_DATOS_COLOMBIA.md")
    conjuntos = particion(muestras)
    elegidas = [m for m in muestras if args.conjunto == "todo" or conjuntos[m.id] == args.conjunto]

    c = construir(Configuracion(_env_file=ENV_BACKEND))
    lector = LectorCorreoMime(b"evaluacion")
    with c.uow() as uow:
        catalogo = uow.entidades.catalogo()
        modelos = {t: (m.id, m.version) if (m := uow.modelos.activo(t)) else None for t in ("contenido", "enlaces")}
    variantes = {"sistema_completo": MotorAnalisis(c.modelos),
                 "solo_reglas": MotorAnalisis(SoloAlgunosModelos(c.modelos, False, False)),
                 "reglas_y_enlaces": MotorAnalisis(SoloAlgunosModelos(c.modelos, False, True)),
                 "reglas_y_texto": MotorAnalisis(SoloAlgunosModelos(c.modelos, True, False))}

    correos = [lector.leer(m.crudo) for m in elegidas]
    y = np.array([m.etiqueta for m in elegidas])
    resultados, errores, tiempos = {}, [], []
    for nombre, motor in variantes.items():
        niveles = []
        for m, correo in zip(elegidas, correos, strict=True):
            t0 = time.perf_counter()
            r = motor.analizar(correo, catalogo)
            if nombre == "sistema_completo":
                tiempos.append((time.perf_counter() - t0) * 1000)
                v = r.veredicto
                if (v.nivel.value != "bajo") != bool(m.etiqueta):
                    errores.append({"id": m.id, "origen": m.origen, "etiqueta": "phishing" if m.etiqueta else "legitimo",
                                    "categoria": m.categoria, "nivel": v.nivel.value, "p_final": v.p_final,
                                    "p_texto": v.p_contenido, "p_enlaces": v.p_enlaces, "p_tecnico": v.p_tecnico,
                                    "razones": " | ".join(x.texto for x in (v.razones_visibles or v.razones[:3]))})
            niveles.append(r.veredicto.nivel.value)
        niveles = np.array(niveles)
        resultados[nombre] = {"cuarentena (ALTO)": metricas(y, niveles, "alto"), "marcado (≥MEDIO)": metricas(y, niveles, "medio")}
        if nombre == "sistema_completo":
            resultados[nombre]["por_categoria"] = {
                f"{'phishing' if e else 'legitimo'}/{cat}": {
                    "n": int(mask.sum()),
                    "marcados_≥medio": round(float(np.isin(niveles[mask], ("medio", "alto")).mean()), 4),
                    "alto": round(float((niveles[mask] == "alto").mean()), 4)}
                for (e, cat) in sorted({(m.etiqueta, m.categoria) for m in elegidas})
                for mask in [np.array([(m.etiqueta, m.categoria) == (e, cat) for m in elegidas])]}

    informe = {
        "fecha": datetime.now().isoformat(timespec="seconds"), "conjunto": args.conjunto,
        "n": len(elegidas), "phishing": int(y.sum()), "legitimos": int((y == 0).sum()),
        "por_tipo": {t: sum(m.tipo == t for m in elegidas) for t in ("eml", "mbox", "reconstruido")},
        "modelos_activos": modelos, "resultados": resultados,
        "latencia_ms": {"p50": round(float(np.percentile(tiempos, 50)), 1), "p95": round(float(np.percentile(tiempos, 95)), 1)},
    }
    SALIDA.mkdir(exist_ok=True)
    sello = datetime.now().strftime("%Y%m%d-%H%M")
    (SALIDA / f"colombia_{args.conjunto}_{sello}.json").write_text(json.dumps(informe, ensure_ascii=False, indent=2))
    with (DATOS / f"errores_{args.conjunto}_{sello}.csv").open("w", newline="", encoding="utf-8") as f:   # queda fuera de git
        w = csv.DictWriter(f, fieldnames=list(errores[0]) if errores else ["id"])
        w.writeheader()
        w.writerows(errores)

    print(f"Conjunto «{args.conjunto}»: {informe['n']} correos ({informe['phishing']} phishing, {informe['legitimos']} legítimos)")
    print(f"Modelos activos: {modelos}\n")
    print(f"{'variante':18s} {'umbral':18s} {'recall':>7s} {'IC95':>15s} {'FP legít':>9s} {'IC95':>15s} {'precisión':>9s}")
    for nombre, porumbral in resultados.items():
        for umbral, mm in porumbral.items():
            if umbral == "por_categoria":
                continue
            print(f"{nombre:18s} {umbral:18s} {mm['recall'] or 0:7.3f} {str(mm['recall_ic95']):>15s} "
                  f"{mm['fp_en_legitimos'] or 0:9.3f} {str(mm['fp_ic95']):>15s} {mm['precision'] or 0:9.3f}")
    print(f"\nLatencia por correo: p50 {informe['latencia_ms']['p50']} ms · p95 {informe['latencia_ms']['p95']} ms")
    print(f"Errores para revisar (sin cuerpos): {len(errores)} → datos/colombia/errores_{args.conjunto}_{sello}.csv")


if __name__ == "__main__":
    main()
