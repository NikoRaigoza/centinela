import json, random, joblib, numpy as np, pandas as pd
import phishing as ph
random.seed(7)
bst = joblib.load("xgb_tmp.pkl"); T = json.load(open("tld_tasa.json")); tld_tasa, prior = T["tld_tasa"], T["prior"]
d = pd.read_pickle("datos.pkl"); regs_train = set(d[d.split == "train"].reg)

def matriz(urls):
    X = np.array([ph.vector(u) for u in urls], dtype=np.float32)
    tld = np.array([[tld_tasa.get(ph.tld_de(ph.partir(u)[0]), prior)] for u in urls], dtype=np.float32)
    return np.hstack([X, tld])

# --- positivos externos: phishing actual (otra fuente, otra epoca) ---
urls = [l.strip() for l in open("phishdb_activo.txt", encoding="utf-8", errors="ignore") if l.strip()]
urls = [u for u in urls if ph.dominio_registrado(ph.partir(u)[0]) not in regs_train]       # dominios que el modelo no vio
urls = [u for u in urls if not u.lower().startswith("ftp")]
muestra = random.sample(urls, 30000)
p_pos = bst.predict_proba(matriz(muestra))[:, 1]
print(f"[EXTERNO] phishing actual (Phishing.Database), {len(muestra)} enlaces de dominios no vistos")
print("  recall (detectados) con umbral 0.5:", round(float((p_pos >= 0.5).mean()), 4), "| con umbral 0.3:", round(float((p_pos >= 0.3).mean()), 4))
reg = pd.Series([ph.dominio_registrado(ph.partir(u)[0]) for u in muestra])
top = reg.value_counts().head(6).index.tolist()
for r in top:
    m = (reg == r).values; print(f"   {r:22s} n={m.sum():5d}  detectados={float((p_pos[m] >= 0.5).mean()):.2f}")

# --- negativos externos: paginas de inicio de sitios muy populares ---
top1m = [l.strip() for l in open("top1m.txt") if l.strip()]
pop = [dm + "/" for dm in top1m[:20000]]
p_neg = bst.predict_proba(matriz(pop))[:, 1]
print(f"\n[EXTERNO] paginas de inicio de los 20.000 sitios mas populares (solo 'dominio/')")
print("  falsos positivos con umbral 0.5:", round(float((p_neg >= 0.5).mean()), 4), "| con umbral 0.3:", round(float((p_neg >= 0.3).mean()), 4))
print("  ejemplos marcados como phishing:", [pop[i] for i in np.argsort(-p_neg)[:8]])
print("  google.com/ ->", round(float(bst.predict_proba(matriz(["google.com/"]))[0, 1]), 3), "| bancolombia.com/ ->", round(float(bst.predict_proba(matriz(["bancolombia.com/"]))[0, 1]), 3))
