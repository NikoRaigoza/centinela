import json, random, hashlib, joblib, numpy as np, pandas as pd, xgboost as xgb
import phishing as ph
from sklearn.metrics import roc_auc_score, average_precision_score, f1_score, precision_score, recall_score, accuracy_score
random.seed(11); np.random.seed(11)

d = pd.read_pickle("datos.pkl"); d["fuente"] = np.where(d.y == 1, "clasico_malo", "clasico_bueno")
split_reg = d.groupby("reg").split.first().to_dict()
def asignar(clave):
    if clave in split_reg: return split_reg[clave]
    h = int(hashlib.md5(clave.encode()).hexdigest(), 16) % 100
    return "train" if h < 70 else ("val" if h < 85 else "test")

# ---- phishing actual (Phishing.Database): maximo 3 enlaces por sitio, sitios de plataformas agrupados por subdominio ----
urls = [l.strip() for l in open("phishdb_activo.txt", encoding="utf-8", errors="ignore") if l.strip() and not l.lower().startswith("ftp")]
urls = list(dict.fromkeys(ph.limpiar(u) for u in urls)); random.shuffle(urls)
hosts = [ph.partir(u)[0] for u in urls]; regs = [ph.dominio_registrado(h) for h in hosts]
freq = pd.Series(regs).value_counts(); plataformas = set(freq[freq > 300].index)
filas, cont = [], {}
for u, h, r in zip(urls, hosts, regs):
    clave = h if r in plataformas else r
    if cont.get(clave, 0) >= 3 or not r: continue
    cont[clave] = cont.get(clave, 0) + 1; filas.append((u, 1, r, ph.tld_de(h), asignar(clave), "moderno_malo"))
    if len(filas) >= 90000: break
moderno = pd.DataFrame(filas, columns=["url", "y", "reg", "tld", "split", "fuente"])
# ---- paginas de inicio de sitios populares (top 100.000) ----
top = [l.strip().lower() for l in open("top1m.txt") if l.strip()][:100000]
filas = []
for dm in top:
    s = asignar(dm); filas.append((dm + "/", 0, ph.dominio_registrado(dm), ph.tld_de(dm), s, "popular_bueno"))
    if random.random() < 0.3: filas.append(("www." + dm + "/", 0, ph.dominio_registrado(dm), ph.tld_de(dm), s, "popular_bueno"))
popular = pd.DataFrame(filas, columns=["url", "y", "reg", "tld", "split", "fuente"])
print("filas nuevas:", len(moderno), "phishing moderno |", len(popular), "paginas de inicio populares")

D = pd.concat([d[["url", "y", "reg", "tld", "split", "fuente"]], moderno, popular], ignore_index=True)
Xn = np.array([ph.vector(u) for u in pd.concat([moderno.url, popular.url])], dtype=np.float32)
X = np.vstack([np.load("X.npy"), Xn])
tr, va, te = (D.split == "train").values, (D.split == "val").values, (D.split == "test").values
y = D.y.values; prior = float(y[tr].mean()); k = 20
g = D[tr].groupby("tld").y.agg(["sum", "count"]); tld_tasa = ((g["sum"] + prior * k) / (g["count"] + k)).to_dict()
XF = np.hstack([X, D.tld.map(lambda t: tld_tasa.get(t, prior)).values.astype(np.float32)[:, None]])
D.to_pickle("D_v2.pkl"); np.save("XF_v2.npy", XF)
print("particiones:", {s: int((D.split == s).sum()) for s in ("train", "val", "test")}, "| malos en train: %.1f%%" % (y[tr].mean() * 100))

bst = xgb.XGBClassifier(n_estimators=400, max_depth=7, learning_rate=0.1, subsample=0.8, colsample_bytree=0.8,
                        tree_method="hist", n_jobs=1, eval_metric="aucpr", random_state=42)
bst.fit(XF[tr], y[tr], eval_set=[(XF[va], y[va])], verbose=False)
p = bst.predict_proba(XF[te])[:, 1]; yt = y[te]; Dt = D[te].reset_index(drop=True)

# ---- version 1 (solo dataset clasico) evaluada sobre el MISMO conjunto de prueba, para comparar ----
bst1 = joblib.load("xgb_tmp.pkl"); T1 = json.load(open("tld_tasa.json"))
XF1 = np.hstack([X, D.tld.map(lambda t: T1["tld_tasa"].get(t, T1["prior"])).values.astype(np.float32)[:, None]])
p1 = bst1.predict_proba(XF1[te])[:, 1]

def resumen(nombre, p_, yt_, umbral=0.5):
    pred = (p_ >= umbral).astype(int)
    return {"exactitud": round(accuracy_score(yt_, pred), 4), "precision": round(precision_score(yt_, pred), 4),
            "recall": round(recall_score(yt_, pred), 4), "f1": round(f1_score(yt_, pred), 4),
            "auc_roc": round(roc_auc_score(yt_, p_), 4), "auc_pr": round(average_precision_score(yt_, p_), 4)}
sin_ruta = Dt.url.map(lambda u: ph.partir(u)[2] in ("/", "")).values
out = {"version2_global": resumen("v2", p, yt), "version1_global": resumen("v1", p1, yt), "por_grupo": {}}
for f in ["clasico_malo", "moderno_malo", "clasico_bueno", "popular_bueno"]:
    m = (Dt.fuente == f).values
    tasa = float((p[m] >= 0.5).mean()); tasa1 = float((p1[m] >= 0.5).mean())
    out["por_grupo"][f] = {"n": int(m.sum()), "marcados_phishing_v2": round(tasa, 4), "marcados_phishing_v1": round(tasa1, 4)}
m = sin_ruta  # solo enlaces sin ruta: phishing sin ruta vs inicio de sitios populares
out["solo_paginas_de_inicio"] = {"n": int(m.sum()), "malos": int(yt[m].sum()), "v2": resumen("v2", p[m], yt[m]), "v1": resumen("v1", p1[m], yt[m])}
print(json.dumps(out, indent=1, ensure_ascii=False))

# ---- guardar modelo en formato JSON (robusto entre versiones de xgboost) + metadatos ----
bst.save_model("modelo_phishing.json")
meta = {"version": "2", "nombres": ph.NOMBRES + ["tld_tasa"], "tld_tasa": tld_tasa, "prior": prior, "umbral_defecto": 0.5,
        "entrenamiento": {"filas_train": int(tr.sum()), "filas_val": int(va.sum()), "filas_test": int(te.sum())}, "metricas": out}
json.dump(meta, open("phishing_meta.json", "w"), ensure_ascii=False)
np.save("p_v2_test.npy", p); Dt.assign(p_v2=p, p_v1=p1).to_pickle("test_v2.pkl")
imp = sorted(zip(meta["nombres"], bst.feature_importances_), key=lambda z: -z[1])[:12]; print("top caracteristicas v2:", [(n, round(float(v), 3)) for n, v in imp])
