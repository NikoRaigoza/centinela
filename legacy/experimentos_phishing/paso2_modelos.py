import time, json, joblib, numpy as np, pandas as pd
import phishing as ph
import xgboost as xgb
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
                             average_precision_score, confusion_matrix, roc_curve)

X = np.load("X.npy"); d = pd.read_pickle("datos.pkl"); y = d.y.values
tr, va, te = (d.split == "train").values, (d.split == "val").values, (d.split == "test").values

# caracteristica de TLD calculada SOLO con entrenamiento (con suavizado)
prior = y[tr].mean(); k = 20
g = d[tr].groupby("tld").y.agg(["sum", "count"])
tld_tasa = ((g["sum"] + prior * k) / (g["count"] + k)).to_dict()
col_tld = d.tld.map(lambda t: tld_tasa.get(t, prior)).values.astype(np.float32)[:, None]
XF = np.hstack([X, col_tld]); NOMBRES = ph.NOMBRES + ["tld_tasa"]
np.save("XF.npy", XF); json.dump({"tld_tasa": tld_tasa, "prior": float(prior)}, open("tld_tasa.json", "w"))

def metricas(yt, p, umbral=0.5):
    pred = (p >= umbral).astype(int); tn, fp, fn, tp = confusion_matrix(yt, pred).ravel()
    fpr, tpr, _ = roc_curve(yt, p)
    rec_fpr = {f"recall_con_FPR_{int(f*100)}pct": round(float(np.interp(f, fpr, tpr)), 4) for f in (0.01, 0.02, 0.05)}
    return {"exactitud": round(accuracy_score(yt, pred), 4), "precision": round(precision_score(yt, pred), 4),
            "recall": round(recall_score(yt, pred), 4), "f1": round(f1_score(yt, pred), 4),
            "auc_roc": round(roc_auc_score(yt, p), 4), "auc_pr": round(average_precision_score(yt, p), 4),
            "falsos_positivos": int(fp), "falsos_negativos": int(fn), "tasa_falsos_positivos": round(fp / (fp + tn), 4), **rec_fpr}

res = {}; probas = {}
# 1) regresion logistica (linea base simple)
t = time.time(); lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=300, class_weight="balanced", n_jobs=1))
lr.fit(XF[tr], y[tr]); probas["Regresion logistica"] = lr.predict_proba(XF[te])[:, 1]; print("LR", round(time.time() - t), "s")
# 2) XGBoost
t = time.time()
bst = xgb.XGBClassifier(n_estimators=300, max_depth=7, learning_rate=0.1, subsample=0.8, colsample_bytree=0.8,
                        tree_method="hist", n_jobs=1, eval_metric="aucpr", random_state=42)
bst.fit(XF[tr], y[tr], eval_set=[(XF[va], y[va])], verbose=False); probas["XGBoost"] = bst.predict_proba(XF[te])[:, 1]
print("XGB", round(time.time() - t), "s")
for nombre, p in probas.items():
    res[nombre] = metricas(y[te], p); print(nombre, json.dumps(res[nombre]))
imp = sorted(zip(NOMBRES, bst.feature_importances_), key=lambda z: -z[1])[:15]
print("\nTop caracteristicas XGBoost:", [(n, round(float(v), 3)) for n, v in imp])
joblib.dump(bst, "xgb_tmp.pkl"); np.save("p_xgb_test.npy", probas["XGBoost"])
json.dump({"modelos": res, "importancia": [(n, float(v)) for n, v in imp]}, open("resultados_paso2.json", "w"), indent=1)
