# Detector de phishing por enlace: método y resultados (listos para la tesis)

## 1. Datos
- **Fuente principal:** dataset público "Phishing Site URLs" (549.346 enlaces: 392.924 buenos y 156.422 de phishing).
- **Fuente externa y actual:** lista abierta Phishing.Database (789.054 enlaces de phishing activos, mayormente en plataformas como workers.dev, pages.dev, github.io, vercel.app) y la lista de los 100.000 dominios más populares (para páginas de inicio legítimas).

## 2. Limpieza (para que el resultado sea honesto)
| Problema encontrado | Acción |
|---|---|
| 42.153 enlaces duplicados (27% de los de phishing) | Eliminados: duplicados inflan la precisión porque el modelo "memoriza" |
| 1 enlace con etiqueta contradictoria (en ambas clases) | Eliminado |
| 1.081 enlaces con `http(s)://` visible (casi todos malos) | Se quita el esquema en todos: el modelo no puede usarlo como truco |
| Mismos sitios en entrenamiento y prueba | **Separación por dominio** (70/15/15): 0 dominios compartidos entre entrenamiento y prueba |

Resultado: 507.183 enlaces limpios, 150.724 dominios distintos. Dominios presentes en ambas clases: 347 (sitios legítimos hackeados).

## 3. Características
58 variables calculadas solo con el texto del enlace (no se abre el sitio ni se consulta internet): longitud, puntos, guiones, dígitos, entropía, subdominios, IP en lugar de nombre, símbolo @, palabras típicas de engaño (login, verify, account...), marca suplantada (menciona una marca pero el dominio no es el oficial), acortadores, punycode, WordPress, redirecciones, dominio dentro de la ruta, y la tasa de phishing por terminación de dominio (calculada solo con entrenamiento).

## 4. Modelos comparados (conjunto de prueba, 87.271 enlaces de dominios nunca vistos)
| Modelo | Exactitud | Precisión | Recall | F1 | AUC-ROC |
|---|---|---|---|---|---|
| Regresión logística (línea base) | 91,56% | 78,40% | 83,55% | 0,809 | 0,954 |
| XGBoost | 95,36% | 92,83% | 84,85% | 0,887 | 0,980 |

## 5. Validación externa (versión 1, solo dataset clásico)
- Phishing actual de otra fuente (30.000 enlaces de dominios no vistos): **detecta 87,7%**.
- Páginas de inicio de los 20.000 sitios más populares: **marca 11,3% como sospechosas** (debilidad: en el entrenamiento todos los enlaces buenos traían ruta).

## 6. Versión 2 (se agrega phishing actual y páginas de inicio populares)
Conjunto de prueba común: 120.177 enlaces, dominios no vistos.
| Métrica | Versión 1 | Versión 2 |
|---|---|---|
| Exactitud global | 92,36% | **95,79%** |
| Precisión | 85,47% | **94,07%** |
| Recall | 85,97% | **89,89%** |
| F1 | 0,857 | **0,919** |
| AUC-ROC | 0,970 | **0,985** |
| Phishing actual detectado | 87,5% | **95,3%** |
| Phishing del dataset clásico detectado | 84,9% | 86,0% |
| Falsas alarmas en sitios buenos del dataset clásico | 1,8% | 2,6% |
| Falsas alarmas en páginas de inicio populares | 17,8% | **0,15%** |
| Solo enlaces sin ruta: F1 (precisión) | 0,705 (58,8%) | **0,918 (97,7%)** |

## 7. Motor híbrido: ¿las reglas ayudan? (prueba de ablación, 120.177 enlaces)
| Configuración | Precisión | Recall | F1 |
|---|---|---|---|
| Solo reglas explicables | 95,67% | 22,88% | 0,369 |
| Solo IA | 94,07% | 89,89% | 0,919 |
| Híbrido A (regla de seguridad) | 93,82% | 89,96% | 0,919 |
| Híbrido B (combinación aprendida) | 95,06% | 89,08% | 0,920 |

De 3.243 phishing que la IA dejó pasar, las reglas de señal alta solo "rescatan" 34 (1%), y generarían 254 falsas alarmas.
**Conclusión:** en phishing, la IA ya captura las mismas señales que las reglas; las reglas aportan **explicabilidad** (el usuario ve por qué se marcó), no más detección.
En tráfico de red (NSL-KDD), una regla simple de escalada de privilegios sí sube la detección de ese ataque de 10% a 49% (a cambio de 21 falsas alarmas más de 9.711 eventos normales), mientras que la regla de fuerza bruta no sirve con esos datos. Por eso el motor híbrido de Centinela usa reglas como red de seguridad solo donde se demostró utilidad y como explicación en el resto.

## 8. Limitaciones (para el capítulo de limitaciones)
- Solo analiza el texto del enlace: no ve el contenido de la página ni el certificado.
- Los datos tienen sesgos de origen (listas de phishing reportado; sitios populares como ejemplos "fáciles" de legitimidad).
- Phishing con dominio de apariencia limpia y sin ruta es más difícil de detectar.
- La lista de dominios oficiales de marcas es parcial: puede marcar por error sitios regionales legítimos (por ejemplo, variantes de bancos en otros países).
- El phishing cambia con el tiempo: el modelo debe reentrenarse periódicamente.
- No es un reemplazo de navegadores o filtros de correo: es una capa adicional de apoyo.
