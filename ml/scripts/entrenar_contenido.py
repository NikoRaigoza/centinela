"""Entrena el modelo de contenido elegido en el experimento (M1: TF-IDF palabras 1-2 + regresión logística),
lo calibra (isotónica sobre predicciones fuera de pliegue), lo exporta al formato del backend y verifica que el
backend calcule exactamente lo mismo que scikit-learn (paridad).

Salida: backend/modelos/contenido/v2-corpus-combinado/{es.json, en.json, manifest.json}
"""
import json
import shutil
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

from centinela.adaptadores.salida.ml.clasificadores import ModeloTextoLineal
from centinela.adaptadores.salida.ml.registro import crear_manifiesto
from centinela.adaptadores.salida.ml.texto import VERSION_NORMALIZACION

RAIZ = Path(sys.argv[1])
BACKEND = Path(__file__).resolve().parents[2] / "backend"
DESTINO = BACKEND / "modelos" / "contenido" / "v2.1-corpus-combinado"
PROTOTIPO_EN = BACKEND / "modelos" / "contenido" / "v1-prototipo" / "en.json"
SEMILLA = 42

c = pd.read_csv(RAIZ / "corpus_v1.csv")
y, fuente, textos = c.etiqueta.to_numpy(), c.fuente.to_numpy(), c.texto.to_numpy()


def entrenar(idx):
    v = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=40000, sublinear_tf=True).fit(textos[idx])
    m = LogisticRegression(C=4.0, class_weight="balanced", max_iter=3000).fit(v.transform(textos[idx]), y[idx])
    return v, m


# 1) Predicciones fuera de pliegue (misma validación del experimento) → calibración isotónica
estratos = np.array([f"{f}_{e}" for f, e in zip(fuente, y, strict=True)])
oof = np.zeros(len(y))
for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=SEMILLA).split(textos, estratos, c.grupo):
    v, m = entrenar(tr)
    oof[te] = m.predict_proba(v.transform(textos[te]))[:, 1]
iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0).fit(oof, y)
cal = iso.predict(oof)


def operacion(p, umbral):
    pred = p >= umbral
    return {"fp_en_legitimos": round(float(pred[y == 0].mean()), 4),
            "recall_phishing_real": round(float(pred[(y == 1) & (fuente == "spaphish")].mean()), 4),
            "recall_spear": round(float(pred[(y == 1) & (fuente == "spearphishmx")].mean()), 4)}


# Punto de operación: el umbral más bajo con ≤1 % de falsos positivos en legítimos. Por encima de él, el texto
# SOLO ya justifica riesgo ALTO (cuarentena). Se guarda en el manifiesto: cada versión trae su propio umbral.
umbral_alto = next(round(u, 2) for u in np.arange(0.5, 1.0, 0.01) if (cal[y == 0] >= u).mean() <= 0.01)
umbral_medio = next(round(u, 2) for u in np.arange(0.3, 1.0, 0.01) if (cal[y == 0] >= u).mean() <= 0.05)
print("Umbrales del modelo — MEDIO (FP ≤ 5 %):", umbral_medio, "| ALTO (FP ≤ 1 %):", umbral_alto)

metricas = {
    "validacion": "StratifiedGroupKFold(5), predicciones fuera de pliegue",
    "pr_auc": round(average_precision_score(y, cal), 4), "roc_auc": round(roc_auc_score(y, cal), 4),
    "brier_sin_calibrar": round(brier_score_loss(y, oof), 4), "brier_calibrado": round(brier_score_loss(y, cal), 4),
    "umbral_0_5": operacion(cal, 0.5), "umbral_0_7": operacion(cal, 0.7),
    "umbral_medio_elegido": {"umbral": umbral_medio, **operacion(cal, umbral_medio)},
    "umbral_alto_elegido": {"umbral": umbral_alto, **operacion(cal, umbral_alto)},
}
print(json.dumps(metricas, ensure_ascii=False, indent=2))

# 2) Modelo final con todo el corpus
v, m = entrenar(np.arange(len(y)))
vocab = {t: int(i) for t, i in v.vocabulary_.items()}
DESTINO.mkdir(parents=True, exist_ok=True)
(DESTINO / "es.json").write_text(json.dumps({
    "nombre": "es", "vocab": vocab, "idf": v.idf_.round(8).tolist(), "coef": m.coef_[0].round(8).tolist(),
    "intercepto": float(m.intercept_[0]), "normalizacion": VERSION_NORMALIZACION,
    "calibracion": {"x": iso.X_thresholds_.round(6).tolist(), "y": iso.y_thresholds_.round(6).tolist()},
}, ensure_ascii=False))
shutil.copy(PROTOTIPO_EN, DESTINO / "en.json")      # inglés: se conserva el modelo del prototipo (Kaggle)

# 3) Paridad: el backend debe reproducir a scikit-learn
backend = ModeloTextoLineal(DESTINO / "es.json")
muestra = np.random.default_rng(SEMILLA).choice(len(y), 300, replace=False)
esperado = m.predict_proba(v.transform(textos[muestra]))[:, 1]
obtenido = np.array([backend.probabilidad_sin_calibrar(textos[i]) for i in muestra])
diferencia = float(np.abs(esperado - obtenido).max())
print(f"Paridad sklearn ↔ backend en 300 correos: diferencia máxima {diferencia:.2e}")
assert diferencia < 1e-6, "El backend no reproduce el modelo: revisar tokenización"

crear_manifiesto(DESTINO, {
    "tipo": "contenido", "formato": "texto-lineal-v2", "nombre": "TF-IDF (1-2 palabras) + regresión logística, calibrado",
    "version": "v2.1-corpus-combinado",
    "dataset": "Corpus combinado v1: SpaPhish completo + spear-phishing depurado de SpearPhishMX (2.938 correos)",
    "umbral_medio": umbral_medio, "umbral_alto": umbral_alto,
    "metricas": {**metricas, "paridad_backend": diferencia,
                 "eleccion": "Experimento v1: el más simple a ≤1,5 pts de PR-AUC del mejor (ver ml/resultados)"},
    "normalizacion": {"es": VERSION_NORMALIZACION, "en": None},
})
print("Modelo exportado en", DESTINO)
