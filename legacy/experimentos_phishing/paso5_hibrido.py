import json, numpy as np, pandas as pd, xgboost as xgb
import phishing as ph
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_curve, roc_auc_score, precision_score, recall_score, f1_score, accuracy_score

D = pd.read_pickle("D_v2.pkl"); XF = np.load("XF_v2.npy")
bst = xgb.XGBClassifier(); bst.load_model("modelo_phishing.json")
va, te = (D.split == "val").values, (D.split == "test").values
y = D.y.values

def conteos(urls):
    out = np.zeros((len(urls), 3), dtype=np.float32)
    for i, u in enumerate(urls):
        for g, _ in ph.razones(u): out[i, {"alta": 0, "media": 1, "baja": 2}[g]] += 1
    return out
Rva, Rte = conteos(D.url[va]), conteos(D.url[te])
pva, pte = bst.predict_proba(XF[va])[:, 1], bst.predict_proba(XF[te])[:, 1]
yva, yte = y[va], y[te]

def m(yt, pred):
    return {"precision": round(precision_score(yt, pred), 4), "recall": round(recall_score(yt, pred), 4), "f1": round(f1_score(yt, pred), 4), "exactitud": round(accuracy_score(yt, pred), 4)}
def rec_en_fpr(yt, p, f):
    fpr, tpr, _ = roc_curve(yt, p); return round(float(np.interp(f, fpr, tpr)), 4)

res = {}
# 1) solo reglas explicables: alarma si hay una senal alta o dos medias
reglas = ((Rte[:, 0] >= 1) | (Rte[:, 1] >= 2)).astype(int); res["solo_reglas"] = m(yte, reglas)
# 2) solo IA
res["solo_IA_umbral_0.5"] = m(yte, (pte >= 0.5).astype(int))
# 3) hibrido A: la IA decide, pero si hay una senal alta de las reglas se sube el riesgo (regla de seguridad)
pA = np.where((Rte[:, 0] >= 1) & (pte >= 0.15), np.maximum(pte, 0.6), pte); res["hibrido_A_regla_de_seguridad"] = m(yte, (pA >= 0.5).astype(int))
# 4) hibrido B: combinacion aprendida (regresion logistica sobre la salida de la IA y el conteo de senales), ajustada en validacion
lg = lambda p: np.log(np.clip(p, 1e-6, 1 - 1e-6) / (1 - np.clip(p, 1e-6, 1 - 1e-6)))
Fva, Fte = np.column_stack([lg(pva), Rva]), np.column_stack([lg(pte), Rte])
lr = LogisticRegression(max_iter=500).fit(Fva, yva); pB = lr.predict_proba(Fte)[:, 1]
res["hibrido_B_combinacion_aprendida"] = m(yte, (pB >= 0.5).astype(int))
res["pesos_hibrido_B"] = {"IA": round(float(lr.coef_[0][0]), 3), "senal_alta": round(float(lr.coef_[0][1]), 3), "senal_media": round(float(lr.coef_[0][2]), 3), "senal_baja": round(float(lr.coef_[0][3]), 3)}
# comparacion justa: recall a igual tasa de falsos positivos
res["recall_con_1pct_falsas_alarmas"] = {"IA": rec_en_fpr(yte, pte, 0.01), "hibrido_A": rec_en_fpr(yte, pA, 0.01), "hibrido_B": rec_en_fpr(yte, pB, 0.01)}
res["recall_con_2pct_falsas_alarmas"] = {"IA": rec_en_fpr(yte, pte, 0.02), "hibrido_A": rec_en_fpr(yte, pA, 0.02), "hibrido_B": rec_en_fpr(yte, pB, 0.02)}
res["auc_roc"] = {"IA": round(roc_auc_score(yte, pte), 4), "hibrido_A": round(roc_auc_score(yte, pA), 4), "hibrido_B": round(roc_auc_score(yte, pB), 4)}
# frecuencia con la que las reglas "rescatan" un phishing que la IA dejo pasar
perdidos = (yte == 1) & (pte < 0.5); res["phishing_que_la_IA_dejo_pasar"] = int(perdidos.sum()); res["de_esos_rescatados_por_reglas_alta"] = int((perdidos & (Rte[:, 0] >= 1)).sum())
buenos_marcados = (yte == 0) & (pte < 0.5) & (Rte[:, 0] >= 1); res["buenos_con_senal_alta_que_la_IA_no_marco"] = int(buenos_marcados.sum())
print(json.dumps(res, indent=1, ensure_ascii=False))
json.dump(res, open("resultados_hibrido.json", "w"), indent=1, ensure_ascii=False)
