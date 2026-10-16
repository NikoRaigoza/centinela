"""Construye el corpus combinado v1 (decisión de la tesis: ver hallazgos_calidad_datos.md).

  * SpaPhish completo: correos reales, phishing y legítimos.
  * SpearPhishMX: solo la clase spear-phishing, sin los registros cuyo asunto SpaPhish etiqueta (ruido o duplicado).
  * Se descarta la clase "legítimo" de SpearPhishMX (53 % es phishing según SpaPhish).
Salida: datos/corpus_v1.csv + datos/corpus_v1_informe.json
"""
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path

import pandas as pd

from centinela.adaptadores.salida.ml.texto import VERSION_NORMALIZACION, normalizar

RAIZ = Path(sys.argv[1])


def clave(s):
    s = unicodedata.normalize("NFKD", str(s)).encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z]+", " ", s).strip()


spa = pd.read_csv(RAIZ / "spaphish/Spaphish dataset - DiB.csv", sep=",", encoding="utf-8-sig")
sp = pd.read_csv(RAIZ / "spearphishmx/SpearPhishMX_dataset_publico.csv", sep=";")

spa["k"] = spa.subject.map(clave)
por_asunto = spa[spa.k != ""].groupby("k").Label.agg(["nunique", "first"])
etiqueta_spa = por_asunto[por_asunto["nunique"] == 1]["first"]
sp["etiqueta_spaphish"] = sp.asunto.map(clave).map(etiqueta_spa)

informe = {"version_normalizacion": VERSION_NORMALIZACION,
           "spaphish": {"total": len(spa), "phishing": int(spa.Label.sum()), "legitimos": int((spa.Label == 0).sum())}}
spear = sp[sp.etiqueta == 1]
informe["spearphishmx"] = {
    "total": len(sp), "clase_legitimo_descartada": int((sp.etiqueta == 0).sum()),
    "spear_total": len(spear),
    "spear_descartado_asunto_legitimo_en_spaphish": int((spear.etiqueta_spaphish == 0).sum()),
    "spear_descartado_duplicado_de_spaphish": int((spear.etiqueta_spaphish == 1).sum()),
}
spear = spear[spear.etiqueta_spaphish.isna()]

filas = [pd.DataFrame({"fuente": "spaphish", "id_fuente": spa.hash, "etiqueta": spa.Label,
                       "asunto": spa.subject.fillna(""), "cuerpo": spa.body.fillna("")}),
         pd.DataFrame({"fuente": "spearphishmx", "id_fuente": spear.hash, "etiqueta": 1,
                       "asunto": spear.asunto.fillna(""), "cuerpo": spear.cuerpo_sanitizado.fillna("")})]
c = pd.concat(filas, ignore_index=True)
c["texto"] = [normalizar(a, b) for a, b in zip(c.asunto, c.cuerpo, strict=True)]
c = c[c.texto.str.len() >= 20]
antes = len(c)
conflictos = c.groupby("texto").etiqueta.nunique()
c = c[~c.texto.isin(conflictos[conflictos > 1].index)].drop_duplicates("texto")
informe["eliminados_duplicados_o_contradictorios"] = antes - len(c)
# Grupo de casi-duplicados (plantillas): mismos 200 primeros caracteres sin números → nunca se separan en la validación
c["grupo"] = [hashlib.sha1(re.sub(r"znum", "", t)[:200].encode()).hexdigest()[:12] for t in c.texto]
c = c.reset_index(drop=True)
informe["corpus"] = {"total": len(c), "phishing": int(c.etiqueta.sum()), "legitimos": int((c.etiqueta == 0).sum()),
                     "por_fuente_y_clase": {f"{f}_{e}": int(n) for (f, e), n in c.groupby(["fuente", "etiqueta"]).size().items()},
                     "grupos": int(c.grupo.nunique())}
c.to_csv(RAIZ / "corpus_v1.csv", index=False)
(RAIZ / "corpus_v1_informe.json").write_text(json.dumps(informe, ensure_ascii=False, indent=2))
print(json.dumps(informe, ensure_ascii=False, indent=2))
