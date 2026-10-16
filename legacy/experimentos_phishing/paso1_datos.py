import time, json, numpy as np, pandas as pd
import phishing as ph
from sklearn.model_selection import GroupShuffleSplit

t0 = time.time()
df = pd.read_csv("phishing_site_urls.csv")
informe = {"filas_originales": int(len(df))}
df["url"] = df.URL.astype(str).map(ph.limpiar)                       # quita http(s):// (evita el truco del esquema)
df["y"] = (df.Label == "bad").astype(int)
df = df[df.url.str.len() > 3]
informe["con_esquema_http_en_malos"] = int(df.URL.str.contains("://").sum())
# duplicados y contradicciones
conflicto = df.groupby("url").y.nunique()
conflicto = set(conflicto[conflicto > 1].index)
informe["urls_en_ambas_clases"] = len(conflicto)
df = df[~df.url.isin(conflicto)]
antes = len(df); df = df.drop_duplicates("url"); informe["duplicados_eliminados"] = int(antes - len(df))
host = df.url.map(lambda u: ph.partir(u)[0])
df["reg"] = host.map(ph.dominio_registrado); df["tld"] = host.map(ph.tld_de)
df = df[df.reg.str.len() > 0].reset_index(drop=True)
informe["filas_limpias"] = int(len(df)); informe["malos"] = int(df.y.sum()); informe["buenos"] = int((1 - df.y).sum())
informe["dominios_distintos"] = int(df.reg.nunique())
# dominios que aparecen en ambas clases (sitios legitimos hackeados)
ambos = df.groupby("reg").y.nunique(); informe["dominios_en_ambas_clases"] = int((ambos > 1).sum())

# separacion por dominio: 70% entrenamiento / 15% validacion / 15% prueba
g1 = GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=42)
idx_trval, idx_test = next(g1.split(df, df.y, df.reg))
g2 = GroupShuffleSplit(n_splits=1, test_size=0.1765, random_state=42)
sub = df.iloc[idx_trval]; i_tr, i_va = next(g2.split(sub, sub.y, sub.reg))
split = np.array(["train"] * len(df), dtype=object)
split[sub.index[i_va]] = "val"; split[idx_test] = "test"
df["split"] = split
informe["por_particion"] = {s: {"filas": int((df.split == s).sum()), "malos_pct": round(float(df[df.split == s].y.mean() * 100), 1),
                                "dominios": int(df[df.split == s].reg.nunique())} for s in ("train", "val", "test")}
informe["dominios_compartidos_train_test"] = int(len(set(df[df.split == "train"].reg) & set(df[df.split == "test"].reg)))
print("limpieza lista en", round(time.time() - t0), "s"); t1 = time.time()
X = np.array([ph.vector(u) for u in df.url], dtype=np.float32)
print("caracteristicas:", X.shape, "en", round(time.time() - t1), "s")
np.save("X.npy", X); df[["url", "y", "reg", "tld", "split"]].to_pickle("datos.pkl")
json.dump(informe, open("informe_datos.json", "w"), indent=1, ensure_ascii=False)
print(json.dumps(informe, indent=1, ensure_ascii=False))
