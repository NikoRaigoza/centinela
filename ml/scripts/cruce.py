import re, sys, unicodedata
from pathlib import Path
import pandas as pd
RAIZ = Path(sys.argv[1])
sp = pd.read_csv(RAIZ / "spearphishmx/SpearPhishMX_dataset_publico.csv", sep=";")
spa = pd.read_csv(RAIZ / "spaphish/Spaphish dataset - DiB.csv", sep=",", encoding="utf-8-sig")
print("SpaPhish:", spa.shape, spa.Label.value_counts().to_dict())

def norm(s):
    s = unicodedata.normalize("NFKD", str(s)).encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z]+", " ", s).strip()

sp["k_asunto"] = sp.asunto.map(norm); spa["k_asunto"] = spa.subject.map(norm)
# firma del cuerpo: 12 palabras de la mitad del cuerpo (evita el saludo inyectado y los marcadores)
def firma(s):
    w = [x for x in norm(s).split() if len(x) > 3]
    m = len(w) // 2
    return " ".join(w[m:m + 12]) if len(w) >= 20 else None
sp["k_cuerpo"] = sp.cuerpo_sanitizado.map(firma); spa["k_cuerpo"] = spa.body.map(firma)
idx_spa = spa.dropna(subset=["k_cuerpo"]).drop_duplicates("k_cuerpo").set_index("k_cuerpo").Label
sp["label_spaphish"] = sp.k_cuerpo.map(idx_spa)
print("\nSpearPhishMX con cuerpo encontrado en SpaPhish:", sp.label_spaphish.notna().sum())
print(pd.crosstab(sp.etiqueta, sp.label_spaphish.fillna(-1).astype(int), rownames=["etiqueta SpearPhishMX"],
                  colnames=["Label SpaPhish (-1 = no encontrado)"]).to_string())
asu = set(spa.k_asunto) - {""}
print("\nasunto encontrado en SpaPhish por clase SpearPhishMX:", sp.k_asunto.isin(asu).groupby(sp.etiqueta).mean().round(3).to_dict())
eje = sp[(sp.etiqueta == 0) & (sp.label_spaphish == 1)]
print("\nEjemplos 'legítimos' en SpearPhishMX que SpaPhish etiqueta como phishing:")
print(eje.asunto.head(12).to_string())

# Cruce por asunto: etiqueta de SpaPhish cuando el asunto es inequívoco (todas sus apariciones con la misma etiqueta)
por_asunto = spa[spa.k_asunto != ""].groupby("k_asunto").Label.agg(["nunique", "first", "size"])
inequivoco = por_asunto[por_asunto["nunique"] == 1]["first"]
sp["label_por_asunto"] = sp.k_asunto.map(inequivoco)
print("\n=== Cruce por asunto ===")
print(pd.crosstab(sp.etiqueta, sp.label_por_asunto.fillna(-1).astype(int), rownames=["etiqueta SpearPhishMX"],
                  colnames=["Label SpaPhish por asunto (-1 = sin cruce/ambiguo)"]).to_string())
c0 = sp[sp.etiqueta == 0]
print(f"\nDe los {len(c0)} 'legítimos' de SpearPhishMX, SpaPhish considera phishing a",
      int((c0.label_por_asunto == 1).sum()), f"({(c0.label_por_asunto == 1).mean():.1%})")
x = sp[(sp.etiqueta == 1) & (sp.label_por_asunto == 0)]
print("\n'spear-phishing' con asunto que SpaPhish tiene como legítimo — asuntos más comunes:")
print(x.asunto.value_counts().head(8).to_string())
print("\nejemplo de cuerpo:", x.cuerpo_sanitizado.iloc[0][:300].replace("\n", " "))
