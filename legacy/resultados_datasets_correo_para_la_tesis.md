# Datasets de correo y primer experimento: ¿se transfiere un modelo entre fuentes e idiomas?

## 1. Datasets revisados
**SpaPhish** (Bustio-Martínez et al., 2026; Mendeley Data, DOI 10.17632/hz2d6gz7pc). 1.395 correos en español (731 de phishing y 664 legítimos), de 2014 a 2025, tomados de los buzones de los autores y anonimizados. Trae asunto, texto, enlaces, adjuntos (tipo y tamaño), número de saltos del correo y anotaciones de persuasión. **No trae los encabezados completos**, por lo que no permite aprender señales de SPF, DKIM y DMARC.

**Phishing Email Dataset** (Kaggle, Naser Abdullah Alam; citar a Al-Subaiey et al., 2024, arXiv 2405.11619). 82.486 correos en inglés (42.891 de spam o phishing y 39.595 legítimos) que mezclan seis corpus: CEAS-08 (39.154), Enron (29.767), SpamAssassin (5.809), Nigerian Fraud (3.332), Ling (2.859) y Nazario (1.565). Tras quitar duplicados quedan 82.439.
Observaciones: Nazario y Nigerian Fraud solo contienen phishing (la fuente delata la etiqueta); los correos legítimos de Enron son de 2001; los ejemplos de "phishing" son en buena parte spam clásico (por ejemplo, de medicamentos). Es un corpus antiguo y con sesgo de fuente.

## 2. Método
Representación TF-IDF de palabras (1 y 2 gramas) sobre asunto y cuerpo, y regresión logística. Se eligió un modelo simple a propósito: la prueba mide la transferencia entre datos, no la potencia del algoritmo.

## 3. Resultados
| Experimento | AUC | F1 | Precisión | Recall |
|---|---|---|---|---|
| Kaggle a Kaggle, separación al azar 80/20 | 0,999 | 0,990 | 0,988 | 0,991 |
| Kaggle, se deja fuera CEAS-08 y se prueba en ella | 0,965 | 0,906 | 0,913 | 0,900 |
| Kaggle, se deja fuera Enron y se prueba en ella | 0,927 | 0,837 | 0,796 | 0,882 |
| Kaggle, se deja fuera SpamAssassin y se prueba en ella | 0,990 | 0,868 | 0,783 | 0,973 |
| Kaggle, se deja fuera Ling y se prueba en ella | 0,984 | 0,867 | 0,848 | 0,886 |
| **Kaggle (inglés) a SpaPhish (español)** | **0,673** | **0,689** | **0,528** | **0,993** |
| SpaPhish (español) a Kaggle (inglés) | 0,560 | 0,340 | 0,642 | 0,231 |
| SpaPhish a SpaPhish, validación cruzada de 5 pliegues | 0,992 | 0,951 (±0,008) | 0,975 | 0,930 |

En la prueba de inglés a español, el modelo marcó como phishing el **97,7% de los correos legítimos en español** (y detectó el 99,3% del phishing): en la práctica, llama phishing a casi todo lo que está en español.

## 4. Interpretación
1. **La separación al azar infla el resultado** (F1 0,990). Con fuentes que el modelo no vio, en inglés, cae a entre 0,84 y 0,91.
2. **El cambio de idioma lo hace inservible:** un modelo entrenado solo en inglés no sirve para correos en español.
3. **Hay que entrenar con datos en español.** El rendimiento interno de SpaPhish es alto, pero eso no prueba que funcione con correos de otra fuente. La validación cruzada puede estar inflada por plantillas de campañas parecidas y porque todos los correos vienen de los mismos autores.
4. **Experimento central de la tesis:** medir cuánto rinde el modelo entrenado con SpaPhish sobre correos colombianos que nunca vio (corpus propio), con falsos positivos y tiempo de respuesta.

## 5. Limitaciones
- Un solo tipo de modelo de texto (TF-IDF con regresión logística), sin ajuste fino.
- Idioma y país de SpaPhish no verificados por correo; fueron recolectados por sus autores en sus buzones.
- Las etiquetas son las de cada dataset; no se revisaron una por una.
- Kaggle no tiene fuente separada para correos legítimos modernos.

## 6. Evaluación temporal con SpaPhish (¿cuánto aguanta el modelo con el tiempo?)
**Limitación previa.** Los correos de phishing de SpaPhish se concentran en los últimos años: de 2014 a 2022 hay unos 38 de phishing entre más de 400 correos (9%), mientras que en 2024 y 2025 son el 76%. Por eso no se puede entrenar "con lo más viejo" desde 2014: se usan cortes en 2024 y 2025, y el resultado está limitado por pocos correos legítimos recientes (192 en 2024 y 2025, y 88 en 2025).

**Método.** TF-IDF con regresión logística, igual que antes. Se compara con y sin pesos balanceados por clase, porque el entrenamiento viejo tiene mucho menos phishing que la prueba. Intervalos de confianza al 95% por remuestreo (1.000 repeticiones).

| Prueba | Entrenamiento | Prueba | AUC | F1 (IC 95%) | Precisión | Recall | Legítimos marcados |
|---|---|---|---|---|---|---|---|
| Validación cruzada al azar | n/a | n/a | 0,992 | 0,951 | 0,975 | 0,930 | n/a |
| A: hasta 2023 a 2024-2025, normal | 565 (16% phishing) | 806 (76%) | 0,951 | 0,358 (0,311 a 0,401) | 1,000 | 0,218 | 0% |
| A: hasta 2023 a 2024-2025, balanceado | 565 (16%) | 806 (76%) | 0,952 | **0,856** (0,835 a 0,879) | 0,985 | 0,757 | 3,6% |
| B: hasta 2024 a 2025, normal | 860 (33%) | 511 (83%) | 0,969 | 0,815 (0,782 a 0,844) | 1,000 | 0,688 | 0% |
| B: hasta 2024 a 2025, balanceado | 860 (33%) | 511 (83%) | 0,969 | **0,858** (0,831 a 0,883) | 1,000 | 0,752 | 0% |

Ventana creciente (balanceado): 2023, AUC 0,851 y F1 0,277 (solo 9% de phishing en el entrenamiento); 2024, AUC 0,965 y F1 0,890; 2025, AUC 0,969 y F1 0,858.

**Interpretación.**
1. Con el paso del tiempo el F1 baja de 0,95 a cerca de 0,86 y el recall del phishing nuevo cae a cerca del 75%. Aun así el AUC se mantiene alto (0,95 a 0,97): el modelo sigue ordenando bien los correos, pero un umbral fijo ya no es adecuado. Hay que reentrenar o recalibrar periódicamente y usar niveles de riesgo en lugar de un único corte.
2. Sin pesos balanceados el modelo "se queda corto" (F1 0,358 en la prueba A): es el efecto del desbalance entre épocas.
3. **Atajos detectados.** Las palabras que más empujan hacia "legítimo" incluyen `mx`, `dr`, `www` y artículos comunes del español; hacia "phishing", `2023`, `regalo`, `cuenta`, `cliente`, `paquete`. Esto sugiere que el modelo también aprende rasgos propios del origen de los buzones (por ejemplo, correos institucionales de México) y del año, no solo señales de engaño. Es una razón más para probar con correos colombianos.
4. Solo el 7,3% de los correos de prueba tiene un casi-duplicado (similitud 0,8 o más) en el entrenamiento. Sin ellos, el resultado se mantiene (AUC 0,945; F1 0,842; recall 0,736), así que no depende de plantillas repetidas.

## 7. Analizador de correos (versión 1): diseño y resultados
**Qué combina.** (1) El texto del mensaje, con un modelo en español (entrenado con SpaPhish) o en inglés (entrenado con Kaggle), ambos TF-IDF con regresión logística y pesos balanceados por clase; las palabras que más pesaron se explican de forma exacta (aporte de cada palabra). (2) Los enlaces. (3) Señales técnicas explicables: autenticación (SPF, DKIM, DMARC) leída de los encabezados, remitente (dominio que imita una marca o entidad, respuesta a otro dominio), enlaces engañosos (el texto muestra un sitio y lleva a otro, enlaces acortados) y adjuntos peligrosos (ejecutables, doble extensión, macros, páginas web, comprimidos).
**Regla de combinación:** resultado = el mayor entre el texto, 0,6 por el riesgo de enlaces y las señales técnicas, más 0,05 por cada componente adicional con riesgo de 0,5 o más. Niveles: bajo (menos de 0,30), medio (0,30 a 0,70) y alto (0,70 o más). Los pesos de las señales técnicas (alta 0,45, media 0,20, baja 0,07, combinadas como probabilidades independientes) son criterio de experto, no aprendidos.

**Hallazgo: el modelo de enlaces de páginas web no sirve para los enlaces dentro de correos.** Aplicado a los enlaces de SpaPhish, marcó como phishing entre el 59% y el 78% de los correos legítimos (los boletines y notificaciones traen enlaces de seguimiento largos que se parecen a los de un engaño). Su AUC fue de 0,73 a 0,78 y, sumado sin cuidado al texto, bajó el F1 de 0,948 (solo texto) a 0,80 o 0,83.
**Recalibración.** Se entrenó un modelo de enlaces con los 5.860 enlaces reales de SpaPhish (537 dominios distintos):
| Validación | AUC | F1 | Precisión | Recall |
|---|---|---|---|---|
| Separación por correo | 0,971 | 0,933 | 0,973 | 0,897 |
| **Separación estricta por dominio** | **0,818** | **0,545** | 0,891 | 0,392 |
La diferencia muestra que en buena parte aprendía los dominios de los remitentes. Sumado al texto, el aporte real es marginal (F1 0,953 frente a 0,948 con solo texto, separación estricta). Por eso los enlaces **apoyan pero no mandan**: con peso 0,6 solos solo pueden llevar a riesgo medio.
La señal "menciona una marca pero el dominio no es el oficial", aplicada a los enlaces, aparece en el 55,8% de los correos de phishing pero también en el 16,0% de los legítimos, así que no se usa como señal fuerte en enlaces de correos (sí se usa para el dominio del remitente).

**Prueba de humo con 412 correos de phishing reales** (repositorio Phishing Pot, casi todos en inglés y portugués; el idioma se detectó automáticamente): 54% con riesgo alto, 33% medio y 14% bajo, es decir, el 87% con riesgo medio o alto. En inglés, el 99% (79% alto); en español (9 correos), el 100%; en portugués y en correos de idioma no identificado, donde no hay modelo de texto y solo actúan las señales técnicas y los enlaces, el 58% (en ambos grupos). La prueba mide solo cuántos phishing se detectan: no estima falsas alarmas. Procesar los 412 correos tomó 3,6 segundos.
De los 409 correos con encabezados de autenticación, 47 fallaron DMARC, 51 fallaron SPF y 196 **pasaron** SPF: pasar la autenticación no garantiza que un correo sea seguro.

**Limitaciones.**
- No se pudo medir las falsas alarmas de las señales técnicas con correos legítimos que traigan encabezados completos (SpaPhish no los incluye).
- El modelo en español depende de un corpus recolectado en los buzones de sus autores; en la evaluación temporal bajó de un F1 de 0,95 a cerca de 0,86. Aún no se ha medido con correos colombianos.
- El modelo en inglés no se transfiere al español (sección 3). No hay modelo para portugués ni otros idiomas.
- Un correo enviado desde una cuenta legítima que fue hackeada puede pasar SPF, DKIM y DMARC.
- No se analizan imágenes (por ejemplo, códigos QR) ni el contenido de los adjuntos.
- **Privacidad:** el análisis ocurre localmente. Del correo solo se guarda el remitente, el asunto, las razones y los puntajes, nunca el mensaje. La dirección del remitente es un dato personal (Ley 1581 de 2012): debe tratarse con finalidad de seguridad y puede enmascararse si la empresa lo exige.

## 8. Conector de correo con Gmail: diseño y pruebas
**Qué hace.** Se conecta a un buzón de Gmail de prueba por IMAP (imap.gmail.com, puerto 993) con una contraseña de aplicación. Revisa los correos nuevos de la bandeja de entrada sin marcarlos como leídos, los analiza con el analizador de correos y, en modo "cuarentena automática", los de riesgo alto se copian a la carpeta «Centinela/Cuarentena» y se sacan de la bandeja. En modo "solo avisar" no mueve nada. Cada correo sospechoso queda como incidente en el Historial (estado «En cuarentena» o «Nuevo»), y desde el incidente se puede **liberar** el correo de vuelta a la bandeja (estado «Liberado»).

**Decisiones de seguridad y privacidad.**
- **Nunca se borra un correo.** La cuarentena copia el mensaje a otra carpeta y lo saca de la bandeja (en Gmail, solo quita esa etiqueta; el correo sigue guardado). Se usa la orden que saca únicamente ese mensaje (UID EXPUNGE) para no tocar otros.
- La contraseña de aplicación vive solo en la memoria de la sesión: no se guarda en la base de datos ni en archivos. Se usa una cuenta de Gmail de prueba, no un correo personal.
- Del correo solo se guarda remitente, asunto, razones, puntajes y el identificador del mensaje (necesario para liberarlo); no se guarda el contenido.
- Un registro de correos ya procesados (por identificador del mensaje) evita crear incidentes repetidos si se reinicia la sesión.
- Si el correo no trae identificador, Centinela avisa pero no lo mueve (no podría liberarlo después).

**Pruebas.** El conector se probó con un buzón IMAP simulado que imita las respuestas de imaplib, no con un Gmail real: contraseña incorrecta, sin internet, clave con espacios, lectura de correos nuevos (incluida la particularidad de IMAP de devolver siempre el último mensaje), correos gigantes, cuarentena sin pérdida de mensajes, liberación y correo no encontrado. La primera prueba contra un Gmail real debe hacerse con el botón «Probar conexión».
**Limitaciones.** Revisa el buzón solo mientras la pantalla esté abierta (cada 30 segundos); un servicio permanente en segundo plano queda como trabajo futuro. La contraseña de aplicación exige verificación en dos pasos y puede no estar disponible en cuentas de trabajo o con protección avanzada. Una falsa alarma deja un correo legítimo en cuarentena hasta que alguien lo libere.
