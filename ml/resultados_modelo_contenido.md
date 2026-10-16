# Modelo de contenido de Centinela: experimento y resultados (Fase 3b)

Generado desde `resultados/experimento_v1.json` y el manifiesto del modelo `v2.1-corpus-combinado` (activo).
Reproducible: `scripts/corpus.py` → `scripts/experimento.py` → `scripts/entrenar_contenido.py`.

## 1. Datos
Corpus combinado v1 (decisión documentada en `hallazgos_calidad_datos.md`): **2938 correos**,
2276 phishing y 662 legítimos. Por fuente y clase: {'spaphish_0': 662, 'spaphish_1': 684, 'spearphishmx_1': 1592}.
Se eliminaron duplicados y textos con etiquetas contradictorias; los casi-duplicados (plantillas) se agrupan
(2858 grupos) para que nunca queden a la vez en entrenamiento y prueba.

**Normalización común** (`backend/.../ml/texto.py`, versión 1): toda URL, correo,
teléfono e identificador se reemplaza por el mismo marcador y se quita el saludo inicial, en entrenamiento y en producción.
Así el modelo no puede aprender la forma de sanitizar de cada dataset.

## 2. Protocolo (fijado antes de ver resultados)
- Validación: StratifiedGroupKFold de 5 pliegues, estratificado por fuente × clase y agrupado por plantilla.
- Métrica principal: PR-AUC. Además F1, falsos positivos en legítimos, recall por fuente y Brier.
- Regla de elección: **el modelo más simple a ≤ 1,5 puntos de PR-AUC del mejor.**

## 3. Resultados (media ± desviación en 5 pliegues)
| Modelo | PR-AUC | F1 | FP en legítimos | Recall phishing real | Recall spear-phishing | Brier |
|---|---|---|---|---|---|---|
| M1 TF-IDF palabras + RL | 0.997 ± 0.001 | 0.969 ± 0.005 | 4.4 % | 88.8 % | 97.9 % | 0.040 |
| M2 TF-IDF palabras + SVM lineal | 0.997 ± 0.001 | 0.972 ± 0.005 | 4.4 % | 90.6 % | 97.9 % | 0.102 |
| M3 TF-IDF palabras+caracteres + RL | 0.997 ± 0.000 | 0.970 ± 0.005 | 5.3 % | 90.6 % | 97.8 % | 0.034 |
| M4 XGBoost solo rasgos (ablación) | 0.986 ± 0.005 | 0.918 ± 0.021 | 8.9 % | 71.1 % | 94.1 % | 0.087 |
| M5 XGBoost dos etapas (texto + rasgos) | 0.997 ± 0.001 | 0.971 ± 0.004 | 3.8 % | 89.9 % | 97.7 % | 0.034 |
| M6 LightGBM dos etapas (texto + rasgos) | 0.997 ± 0.000 | 0.971 ± 0.003 | 6.3 % | 92.2 % | 97.9 % | 0.034 |

Mejor PR-AUC: M5 XGBoost dos etapas (texto + rasgos). **Elegido por la regla: M1 TF-IDF palabras + RL.**

### Análisis complementario: solo correos reales (SpaPhish, ambas clases)
| Modelo | PR-AUC | F1 | FP en legítimos | Recall con FP ≤ 5 % |
|---|---|---|---|---|
| M1 TF-IDF palabras + RL | 0.992 ± 0.004 | 0.948 ± 0.022 | 2.0 % ± 0.9 % | 95.8 % |
| M2 TF-IDF palabras + SVM lineal | 0.994 ± 0.004 | 0.959 ± 0.017 | 1.7 % ± 1.0 % | 96.6 % |
| M5 XGBoost dos etapas (texto + rasgos) | 0.991 ± 0.005 | 0.949 ± 0.023 | 2.9 % ± 1.4 % | 95.2 % |
| M6 LightGBM dos etapas (texto + rasgos) | 0.990 ± 0.004 | 0.953 ± 0.013 | 5.3 % ± 1.9 % | 94.6 % |

### Transferencia: ¿aporta SpearPhishMX?
Entrenando **solo con SpaPhish**, el modelo detecta apenas **25.6 %**
(RL) y **31.0 %** (XGBoost) del spear-phishing de SpearPhishMX.
Con el corpus combinado, más del 97 %. El spear-phishing es un estilo distinto del phishing masivo: incluir
SpearPhishMX (depurado) es necesario.

### Ablación
Solo con rasgos de estilo e ingeniería social (sin el texto), el F1 baja a
0.918: el texto es la fuente principal de señal
(importancia en la 2.ª etapa: [['p_texto', 34.74], ['lex_urgencia', 6.33], ['log_largo', 1.64]]).

## 4. Interpretación
1. **Todos los modelos basados en texto empatan** (diferencias dentro de la desviación entre pliegues).
   XGBoost en dos etapas no supera de forma consistente a la regresión logística; con correos reales queda incluso
   un poco por debajo en falsos positivos. Por parsimonia se elige **TF-IDF + regresión logística**, que además
   explica de forma exacta (aporte de cada palabra). **XGBoost se mantiene en el modelo de enlaces**, donde sí
   trabaja sobre rasgos tabulares.
2. La PR-AUC está saturada (≈ 0,997) en el corpus combinado: el spear-phishing de SpearPhishMX parece generado con
   plantillas y es fácil de separar. Las cifras realistas son las de correos reales y las de falsos positivos.

## 5. Modelo final y punto de operación
Entrenado con todo el corpus y **calibrado** con regresión isotónica sobre predicciones fuera de pliegue
(Brier 0.040 → 0.032). Paridad backend ↔ scikit-learn: diferencia máxima
5.0e-09.

| Umbral del texto | FP en legítimos | Recall phishing real | Recall spear |
|---|---|---|---|
| 0,50 | 9.8 % | 95.6 % | 98.1 % |
| 0,70 | 3.8 % | 88.3 % | 97.9 % |
| **0.59 (MEDIO elegido, FP ≤ 5 %)** | **3.8 %** | **88.3 %** | **97.9 %** |
| **0.86 (ALTO elegido, FP ≤ 1 %)** | **0.9 %** | **76.0 %** | **97.0 %** |

**Regla de operación:** los dos umbrales salen de la validación y se guardan en el manifiesto del modelo. Una función por tramos los lleva a la escala común del sistema (MEDIO = 0,30, ALTO = 0,70). El texto **por sí solo** marca un correo como sospechoso desde 0.59 y lo lleva a riesgo ALTO (cuarentena) por encima de
0.86, el umbral con ≤ 1 % de falsos positivos en legítimos. Si el texto coincide con otras señales
(remitente, enlaces, adjuntos), el correo llega antes a ALTO por la combinación de fuentes.

## 6. Sesgo detectado con pruebas de comportamiento (y correcciones)
La validación cruzada no muestra un sesgo que sí aparece con **pruebas de comportamiento** (sondas escritas a mano,
al estilo de CheckList, Ribeiro et al. 2020; ilustrativas, **no** son una evaluación):

- **Correos legítimos cortos y cercanos** («Listo, ya te envié el informe…») recibían probabilidades altas.
  Causa: los legítimos del corpus son casi todos boletines e institucionales largos (las palabras que más empujan a
  "legítimo" son conectores: *que, la, los, el*), y el spear-phishing de SpearPhishMX son mensajes internos cortos.
  Ponderar menos SpearPhishMX no lo corrigió: es un **hueco de datos** (faltan correos legítimos cortos en español).
- **Mitigación aplicada:** umbrales del texto derivados de la validación (MEDIO con FP ≤ 5 %, ALTO con FP ≤ 1 %) en lugar
  de 0,30 fijo. En las sondas, 5 de 6 legítimos quedan en BAJO y los 4 phishing en ALTO (incluido un fraude interno
  sin enlaces); queda 1 falso positivo en MEDIO (solo etiqueta, sin cuarentena).
- **Error corregido en el camino:** el detector de idioma heredado del prototipo tenía listas de palabras muy cortas;
  con correos breves devolvía "otro idioma" y el modelo de texto **no se ejecutaba**.
- **Corrección de fondo pendiente:** un conjunto de correos legítimos reales en español (idealmente colombianos y cortos)
  para el entrenamiento y, sobre todo, para la evaluación.

## 7. Limitaciones
- Los datos son de México; el contexto colombiano lo aportan las reglas (catálogo de entidades y pretextos).
  Falta el **conjunto de evaluación colombiano propio**, que es el experimento central pendiente.
- La probabilidad calibrada refleja la proporción de phishing del corpus (77 %), mucho mayor que en un buzón real;
  por eso las decisiones se toman por punto de operación (falsos positivos), no por la probabilidad bruta.
- El fraude sin enlaces ni adjuntos (tipo BEC) solo se detecta por el texto y queda, en general, en riesgo MEDIO.
- El modelo en inglés sigue siendo el del prototipo (Kaggle).
