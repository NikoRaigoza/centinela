import re, sys
from pathlib import Path
import pandas as pd
RAIZ = Path(sys.argv[1])
sp = pd.read_csv(RAIZ / "spearphishmx/SpearPhishMX_dataset_publico.csv", sep=";")
t = (sp.asunto.fillna("") + " " + sp.cuerpo_sanitizado).str.lower()
grupos = {
    "estafa/sorteo/premio": r"ganador|premio|sorteo|felicidades|lotería|herencia|millones de dólares|querido amigo|transferencia de fondo",
    "boletín/publicidad (baja/unsubscribe)": r"darte de baja|unsubscribe|cancelar (la )?suscripción|dejar de recibir|no deseas seguir recibiendo",
    "pide credenciales/verificar": r"verific|contraseña|inicia sesión|iniciar sesión|credencial|actualiza tus datos|confirma tu",
    "urgencia": r"urgente|inmediat|24 horas|48 horas|plazo|suspend|bloquead",
}
for nombre, rx in grupos.items():
    print(f"{nombre:40s}", " ".join(f"clase {k}: {v:.1%}" for k, v in t.str.contains(rx).groupby(sp.etiqueta).mean().items()))
# saludo inyectado: el cuerpo empieza con 'Hola|Estimad' + nombre
inicio = sp.cuerpo_sanitizado.str.match(r"^\s*(Hola|Estimad[oa/]+|Querid[oa]|Buen[oa]s?)\s")
print("\nempieza con saludo:", inicio.groupby(sp.etiqueta).mean().round(3).to_dict())
# plantillas repetidas en clase 1
norm = sp.cuerpo_sanitizado.str.replace(r"\d+", "#", regex=True).str.replace(r"^[^,\n]{0,60},", "", regex=True).str[:120]
rep = norm[sp.etiqueta == 1].value_counts()
print("phishing: plantillas distintas (120 car. normalizados):", rep.size, "de", (sp.etiqueta == 1).sum(), "| top:", rep.head(3).to_dict())
dom = sp.urls_desactivadas.str.extract(r"hxxps?://(?:hxxps?://)?([^/\],]+)")[0].str.replace("[.]", ".", regex=False)
print("\ndominios más frecuentes en phishing:", dom[sp.etiqueta == 1].value_counts().head(8).to_dict())
print("dominios más frecuentes en legítimo:", dom[sp.etiqueta == 0].value_counts().head(8).to_dict())
ing = t.str.contains(r"\b(the|your|click|account|please|here)\b")
print("\ncontiene palabras en inglés:", ing.groupby(sp.etiqueta).mean().round(3).to_dict())
print("\n10 asuntos legítimos al azar:"); print(sp[sp.etiqueta == 0].asunto.sample(10, random_state=3).to_string())
print("\n10 asuntos phishing al azar:"); print(sp[sp.etiqueta == 1].asunto.sample(10, random_state=3).to_string())
