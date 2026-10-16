# Calidad de los datos: SpearPhishMX y SpaPhish (hallazgos para la tesis)

Fecha del análisis: 16 de octubre de 2026. Scripts reproducibles en `ml/scripts/`.

## 1. SpearPhishMX en cifras
- 3.006 correos en español (México): 1.891 etiquetados *spear-phishing* (1) y 1.115 *legítimos* (0).
- Columnas útiles: `asunto`, `cuerpo_sanitizado`, `conteo_urls`, rasgos de personalización (`dirigido_a_persona_v2`,
  `destinatario_tiene_apellido_v2`). Sin encabezados, sin URLs reales, sin adjuntos (`conteo_adjuntos` y `conteo_saltos`
  son marcadores vacíos, según su propio README). `fecha` está vacía en el 100 % de los registros.
- Sanitización: `<EMAIL>`, `<TELEFONO>`, `<RFC>`, `<CLABE>` y URLs desactivadas (`hxxp`, `[.]`).

## 2. Problema 1: la clase "legítimo" contiene phishing
El 93 % de los asuntos de la clase 0 aparece en SpaPhish (mismo grupo de investigación). Cruzando por asunto
inequívoco con las etiquetas de SpaPhish:

| | SpaPhish: legítimo | SpaPhish: phishing | sin cruce o ambiguo |
|---|---|---|---|
| SpearPhishMX "legítimo" (1.115) | 442 | **593 (53,2 %)** | 80 |
| SpearPhishMX "spear-phishing" (1.891) | 204 | 44 | 1.643 |

Ejemplos etiquetados como *legítimos*: "Su paquete está listo para enviar", "¡TODAS TUS FOTOS SERÁN BORRADAS!",
"Cheque de compensación", "Tu cuenta de Netflix…", sorteos de SHEIN y una estafa nigeriana ("Querido amigo").
**Interpretación:** SpearPhishMX separa *spear-phishing* de *todo lo demás* (incluido el phishing masivo), no
*phishing* de *legítimo*. Entrenar Centinela solo con estas etiquetas le enseñaría que el phishing masivo
(paquetes retenidos, bloqueo de cuenta) es legítimo: justo lo que más reciben los usuarios colombianos.

## 3. Problema 2: ruido en la clase "spear-phishing"
204 correos *spear-phishing* tienen asuntos que SpaPhish considera legítimos (boletines de SURA, entrevistas,
convocatorias universitarias). Además, la clase 1 parece generada con plantillas: 1.867 cuerpos distintos pero con
pretextos corporativos repetitivos ("Actualización de Política de BYOD", dominios como `9779[.]info` repetidos 134 veces).

## 4. Problema 3: artefactos que delatan la clase (atajos)
| Rasgo | Legítimo | Spear-phishing |
|---|---|---|
| `[.]` en el cuerpo (URL desactivada) | 15,6 % | 73,8 % |
| `<EMAIL>` en el cuerpo | 23,9 % | 0,3 % |
| Empieza con saludo ("Hola Nombre Apellido,") | 98,6 % | 84,6 % |
| Mediana de URLs | 3 | 1 |
| Mediana de largo del cuerpo | 769 car. | 260 car. |

El saludo personalizado se insertó también en correos masivos ("Hola Berenice Quezada García, CLICK BELOW to read…"),
por lo que la "personalización" es mayor en los legítimos: lo contrario de lo esperado. Un modelo aprendería
la forma de sanitizar y el largo, no el engaño.

## 5. Consecuencias para el diseño
1. No usar las etiquetas de SpearPhishMX tal cual.
2. Normalizar igual en entrenamiento y en producción: reemplazar toda URL (con o sin `[.]`), correo y teléfono por
   el mismo marcador, y quitar la línea de saludo inicial.
3. Evaluar con validación entre fuentes (entrenar en una, probar en otra) para medir los atajos.
4. Evaluar en un conjunto colombiano propio, nunca usado para entrenar.
