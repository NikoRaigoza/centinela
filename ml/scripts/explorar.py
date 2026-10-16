"""Exploración inicial de SpearPhishMX y SpaPhish."""
import sys
from pathlib import Path

import pandas as pd

RAIZ = Path(sys.argv[1])
sp = pd.read_csv(RAIZ / "spearphishmx/SpearPhishMX_dataset_publico.csv", sep=";")
print("SpearPhishMX:", sp.shape)
print(sp.dtypes.to_string())
print("\netiquetas:\n", sp.etiqueta.value_counts().to_string())
print("\nnulos:\n", sp.isna().sum()[lambda s: s > 0].to_string())
print("\nduplicados exactos (asunto+cuerpo):", sp.duplicated(["asunto", "cuerpo_sanitizado"]).sum())
print("cuerpos duplicados:", sp.duplicated(["cuerpo_sanitizado"]).sum())
print("conflictos de etiqueta en cuerpos iguales:", (sp.groupby("cuerpo_sanitizado").etiqueta.nunique() > 1).sum())
largo = sp.cuerpo_sanitizado.str.len()
print("\nlargo cuerpo por clase:\n", largo.groupby(sp.etiqueta).describe().to_string())
for col in ["dirigido_a_persona_v2", "destinatario_tiene_apellido_v2"]:
    print(f"\n{col}:\n", pd.crosstab(sp[col], sp.etiqueta, normalize="columns").round(3).to_string())
print("\nconteo_urls por clase:\n", sp.groupby("etiqueta").conteo_urls.describe().to_string())
print("\nmarcadores:")
for m in ["<EMAIL>", "<TELEFONO>", "<RFC>", "<CLABE>", "hxxp", "[.]", "<URL>", "<NOMBRE>", "<"]:
    print(f"  {m!r}: " + ", ".join(f"clase {k}={v:.2%}" for k, v in sp.cuerpo_sanitizado.str.contains(m, regex=False).groupby(sp.etiqueta).mean().items()))
import re
print("\nmarcadores <...> distintos:", pd.Series(re.findall(r"<[A-Z_]{2,20}>", " ".join(sp.cuerpo_sanitizado))).value_counts().head(15).to_dict())
print("\nfecha no nula:", sp.fecha.notna().sum(), " otras columnas:", [c for c in sp.columns])
for e in (0, 1):
    print(f"\n=== EJEMPLOS clase {e} ===")
    for _, r in sp[sp.etiqueta == e].sample(3, random_state=1).iterrows():
        print("ASUNTO:", r.asunto, "\nCUERPO:", str(r.cuerpo_sanitizado)[:400].replace("\n", " "), "\nURLS:", r.urls_desactivadas, "\n---")

spa = pd.read_csv(RAIZ / "spaphish/Spaphish dataset - DiB.csv", sep=";")
print("\n\nSpaPhish:", spa.shape, "\n", spa.Label.value_counts().to_string())
print("columnas:", list(spa.columns)[:20])
inter = set(sp.cuerpo_sanitizado.str[:200]) & set(spa.body.astype(str).str[:200])
print("cuerpos (200 car.) compartidos con SpearPhishMX:", len(inter))
print("asuntos compartidos:", len(set(sp.asunto.dropna()) & set(spa.subject.dropna())))
