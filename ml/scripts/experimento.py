"""Experimento comparativo del modelo de contenido (Fase 3b). Criterios fijados ANTES de ver resultados:

  * Validación: StratifiedGroupKFold (5) estratificado por fuente×clase y agrupado por plantilla.
  * Métricas: PR-AUC (principal), ROC-AUC, F1, recall con ≤5 % de falsos positivos, Brier, y por fuente:
    recall en phishing real (SpaPhish), recall en spear-phishing (SpearPhishMX) y falsos positivos en legítimos.
  * Elección: el modelo MÁS SIMPLE a menos de 1,5 puntos de PR-AUC del mejor.
  * Transferencia: entrenar solo con SpaPhish y medir cuánto spear-phishing detecta (¿aporta SpearPhishMX?).
Salida: resultados/experimento_v1.json
"""
import json
import sys
import time
import warnings
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
import xgboost as xgb
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, f1_score, roc_auc_score, roc_curve
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold
from sklearn.svm import LinearSVC

from centinela.adaptadores.salida.ml.texto import NOMBRES_RASGOS, rasgos

warnings.filterwarnings("ignore")
RAIZ = Path(sys.argv[1])
SALIDA = Path(__file__).resolve().parents[1] / "resultados"
SALIDA.mkdir(exist_ok=True)
SEMILLA = 42

c = pd.read_csv(RAIZ / "corpus_v1.csv")
y = c.etiqueta.to_numpy()
fuente = c.fuente.to_numpy()
R = np.array([rasgos(a, b) for a, b in zip(c.asunto.fillna(""), c.cuerpo.fillna(""), strict=True)])
textos = c.texto.to_numpy()


def tfidf_palabras():
    return TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=40000, sublinear_tf=True)


def tfidf_caracteres():
    return TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, max_features=40000, sublinear_tf=True)


def lr():
    return LogisticRegression(C=4.0, class_weight="balanced", max_iter=3000)


def ajustar_lr(tr):
    v = tfidf_palabras().fit(textos[tr])
    return v, lr().fit(v.transform(textos[tr]), y[tr])


def oof_texto(tr):
    """Probabilidad del texto fuera de pliegue (para entrenar la 2.ª etapa sin fuga)."""
    p = np.zeros(len(tr))
    for a, b in StratifiedKFold(5, shuffle=True, random_state=SEMILLA).split(tr, y[tr]):
        v, m = ajustar_lr(tr[a])
        p[b] = m.predict_proba(v.transform(textos[tr[b]]))[:, 1]
    return p


def apilar(tr, te, clasificador):
    p_tr = oof_texto(tr)
    v, m = ajustar_lr(tr)
    p_te = m.predict_proba(v.transform(textos[te]))[:, 1]
    x_tr, x_te = np.column_stack([p_tr, R[tr]]), np.column_stack([p_te, R[te]])
    return clasificador().fit(x_tr, y[tr]).predict_proba(x_te)[:, 1]


def xgb_cls():
    neg, pos = (y == 0).sum(), (y == 1).sum()
    return xgb.XGBClassifier(n_estimators=300, max_depth=3, learning_rate=0.05, subsample=0.9, colsample_bytree=0.9,
                             scale_pos_weight=neg / pos, eval_metric="logloss", random_state=SEMILLA, n_jobs=4)


def lgb_cls():
    return lgb.LGBMClassifier(n_estimators=300, num_leaves=15, learning_rate=0.05, class_weight="balanced",
                              random_state=SEMILLA, verbose=-1)


MODELOS = {   # en orden de simplicidad
    "M1 TF-IDF palabras + RL": lambda tr, te: (lambda v, m: m.predict_proba(v.transform(textos[te]))[:, 1])(*ajustar_lr(tr)),
    "M2 TF-IDF palabras + SVM lineal": lambda tr, te: (lambda v: 1 / (1 + np.exp(-LinearSVC(
        C=0.5, class_weight="balanced").fit(v.transform(textos[tr]), y[tr]).decision_function(v.transform(textos[te])))))(
        tfidf_palabras().fit(textos[tr])),
    "M3 TF-IDF palabras+caracteres + RL": lambda tr, te: (lambda vp, vc: lr().fit(
        hstack([vp.transform(textos[tr]), vc.transform(textos[tr])]).tocsr(), y[tr]).predict_proba(
        hstack([vp.transform(textos[te]), vc.transform(textos[te])]).tocsr())[:, 1])(
        tfidf_palabras().fit(textos[tr]), tfidf_caracteres().fit(textos[tr])),
    "M4 XGBoost solo rasgos (ablación)": lambda tr, te: xgb_cls().fit(R[tr], y[tr]).predict_proba(R[te])[:, 1],
    "M5 XGBoost dos etapas (texto + rasgos)": lambda tr, te: apilar(tr, te, xgb_cls),
    "M6 LightGBM dos etapas (texto + rasgos)": lambda tr, te: apilar(tr, te, lgb_cls),
}


def metricas(yt, p, ft):
    fpr, tpr, _ = roc_curve(yt, p)
    pred = p >= 0.5
    leg = (yt == 0)
    return {
        "pr_auc": average_precision_score(yt, p), "roc_auc": roc_auc_score(yt, p), "f1": f1_score(yt, pred),
        "recall_fpr_5": float(tpr[fpr <= 0.05].max()), "brier": brier_score_loss(yt, p),
        "fp_en_legitimos": float(pred[leg].mean()),
        "recall_phishing_real_spaphish": float(pred[(yt == 1) & (ft == "spaphish")].mean()),
        "recall_spear_spearphishmx": float(pred[(yt == 1) & (ft == "spearphishmx")].mean()),
    }


estratos = np.array([f"{f}_{e}" for f, e in zip(fuente, y, strict=True)])
pliegues = list(StratifiedGroupKFold(5, shuffle=True, random_state=SEMILLA).split(textos, estratos, c.grupo))
resultados, oof = {}, {}
for nombre, fn in MODELOS.items():
    t0 = time.time()
    p = np.zeros(len(y))
    por_pliegue = []
    for tr, te in pliegues:
        p[te] = fn(tr, te)
        por_pliegue.append(metricas(y[te], p[te], fuente[te]))
    oof[nombre] = p
    df = pd.DataFrame(por_pliegue)
    resultados[nombre] = {k: {"media": round(df[k].mean(), 4), "desv": round(df[k].std(), 4)} for k in df.columns}
    resultados[nombre]["segundos"] = round(time.time() - t0, 1)
    r = resultados[nombre]
    print(f"{nombre:42s} PR-AUC {r['pr_auc']['media']:.3f}±{r['pr_auc']['desv']:.3f}  F1 {r['f1']['media']:.3f}  "
          f"FP-legít {r['fp_en_legitimos']['media']:.3f}  recall real {r['recall_phishing_real_spaphish']['media']:.3f}  "
          f"recall spear {r['recall_spear_spearphishmx']['media']:.3f}  ({r['segundos']} s)", flush=True)

# Elección con el criterio fijado
mejor = max(resultados, key=lambda k: resultados[k]["pr_auc"]["media"])
umbral = resultados[mejor]["pr_auc"]["media"] - 0.015
elegido = next(k for k in MODELOS if resultados[k]["pr_auc"]["media"] >= umbral)
print(f"\nMejor PR-AUC: {mejor}. Elegido por el criterio (más simple a ≤1,5 pts): {elegido}")

# Transferencia: entrenar SOLO con SpaPhish y medir el spear-phishing de SpearPhishMX
spa_idx, spear_idx = np.where(fuente == "spaphish")[0], np.where(fuente == "spearphishmx")[0]
transfer = {}
for nombre in ("M1 TF-IDF palabras + RL", "M5 XGBoost dos etapas (texto + rasgos)"):
    p = MODELOS[nombre](spa_idx, spear_idx)
    transfer[nombre] = {"recall_spear_umbral_05": round(float((p >= 0.5).mean()), 4),
                        "mediana_probabilidad": round(float(np.median(p)), 4)}
    print(f"Transferencia SpaPhish→spear [{nombre}]: detecta {transfer[nombre]['recall_spear_umbral_05']:.1%}")

# Análisis complementario (no cambia la elección): solo correos REALES (SpaPhish, ambas clases)
solo_reales = {}
estr_spa = y[spa_idx]
pl_spa = list(StratifiedGroupKFold(5, shuffle=True, random_state=SEMILLA).split(spa_idx, estr_spa, c.grupo.to_numpy()[spa_idx]))
for nombre in ("M1 TF-IDF palabras + RL", "M2 TF-IDF palabras + SVM lineal", "M5 XGBoost dos etapas (texto + rasgos)",
               "M6 LightGBM dos etapas (texto + rasgos)"):
    filas = []
    for a, b in pl_spa:
        tr, te = spa_idx[a], spa_idx[b]
        filas.append(metricas(y[te], MODELOS[nombre](tr, te), fuente[te]))
    df = pd.DataFrame(filas)
    solo_reales[nombre] = {k: {"media": round(df[k].mean(), 4), "desv": round(df[k].std(), 4)}
                           for k in ("pr_auc", "roc_auc", "f1", "fp_en_legitimos", "recall_fpr_5")}
    r = solo_reales[nombre]
    print(f"[solo reales] {nombre:40s} PR-AUC {r['pr_auc']['media']:.3f}±{r['pr_auc']['desv']:.3f}  "
          f"F1 {r['f1']['media']:.3f}±{r['f1']['desv']:.3f}  FP-legít {r['fp_en_legitimos']['media']:.3f}"
          f"±{r['fp_en_legitimos']['desv']:.3f}  recall@FPR5% {r['recall_fpr_5']['media']:.3f}", flush=True)

# Importancia de los rasgos en la 2.ª etapa (modelo completo)
p_full = oof_texto(np.arange(len(y)))
imp = xgb_cls().fit(np.column_stack([p_full, R]), y).get_booster().get_score(importance_type="gain")
nombres = ["p_texto", *NOMBRES_RASGOS]
importancia = sorted(((nombres[int(k[1:])], round(v, 2)) for k, v in imp.items()), key=lambda t: -t[1])
print("Importancia (ganancia):", importancia[:8])

(SALIDA / "experimento_v1.json").write_text(json.dumps({
    "corpus": json.loads((RAIZ / "corpus_v1_informe.json").read_text()), "validacion": "StratifiedGroupKFold(5)",
    "resultados": resultados, "criterio": "más simple a ≤1,5 pts de PR-AUC del mejor", "mejor": mejor,
    "elegido": elegido, "transferencia_spaphish_a_spear": transfer, "solo_correos_reales": solo_reales, "importancia_2a_etapa": importancia,
}, ensure_ascii=False, indent=2))
