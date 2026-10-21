# Guía: conjunto de correos colombianos para evaluar Centinela

Este conjunto es el **experimento central de la tesis**: medir Centinela con correos colombianos reales que el modelo
nunca vio. Los correos quedan solo en tu equipo (`ml/datos/` está fuera de git) y los informes no copian el cuerpo
de ningún correo.

## 1. Qué reunir

| Grupo | Mínimo | Ideal | Ejemplos |
|---|---|---|---|
| **Legítimos** | 200 | 400+ | ver categorías abajo |
| **Phishing** | 100 | 200+ | ver categorías abajo |

**¿Por qué tantos legítimos?** Para afirmar "menos de 1 % de correos legítimos en cuarentena" con confianza
estadística, la mitad de prueba necesita unos 200 legítimos. Con 50, un solo error ya mueve la cifra 2 puntos.

### Legítimos: lo más importante es la variedad
Crea una carpeta por categoría dentro de `ml/datos/colombia/legitimo/`:

| Carpeta | Qué poner | Por qué importa |
|---|---|---|
| `personal/` | correos de familia y amigos, **sobre todo cortos** («listo, ya te envié…») | es el sesgo conocido del modelo |
| `laboral/` | correos de trabajo o universidad: reuniones, informes, solicitudes | |
| `entidades/` | **notificaciones reales** de Bancolombia, Davivienda, Nequi, DIAN, Servientrega, etc. | son los que más se parecen al phishing: no deben ir a cuarentena |
| `facturas/` | facturas electrónicas, recibos de servicios públicos, compras | se parecen mucho a fraudes de cobro |
| `boletines/` | boletines y promociones legítimas | |
| `cuentas/` | avisos de Google, Microsoft, redes sociales (inicio de sesión, seguridad) | |

### Phishing
Crea una carpeta por categoría dentro de `ml/datos/colombia/phishing/`: `bancos/`, `gobierno/` (DIAN, comparendos,
Fiscalía), `logistica/` (paquetes retenidos), `billeteras/` (Nequi, Daviplata), `cuentas/` (Microsoft, Netflix…),
`fraude_interno/` (pedidos de pago o transferencia sin enlaces) y `otros/`.

**La mejor fuente es tu carpeta de Spam de Gmail:** son correos reales y conservan los encabezados de autenticación.

## 2. Cómo exportarlos

**Uno por uno (.eml):** abre el correo en Gmail → menú ⋮ → **Descargar mensaje**. Guarda el `.eml` en la carpeta
de su categoría.

**En bloque (.mbox), recomendado:**
1. En Gmail, crea dos etiquetas: `centinela-legitimo` y `centinela-phishing`, y aplícalas a los correos elegidos.
   El spam no se puede etiquetar directamente: muévelo primero a la bandeja de entrada.
2. Entra a <https://takeout.google.com> → desmarca todo → marca **Correo** → *Todos los datos de Correo incluidos* →
   elige solo esas dos etiquetas → exporta.
3. Pon cada `.mbox` en la carpeta de su clase (por ejemplo `legitimo/general/` o una por categoría).

**Ejemplos publicados sin archivo** (alertas de la DIAN, los bancos o transportadoras): escríbelos en
`ml/datos/colombia/reconstruidos.csv`:

```csv
etiqueta,categoria,remitente,asunto,cuerpo,enlaces,url_fuente,entidad,fecha
phishing,gobierno,DIAN <notificaciones@dian-cobros.com>,Proceso de embargo,"Usted tiene un proceso...",http://enlace1;http://enlace2,https://www.dian.gov.co/...,DIAN,2026-09-30
```

Estos se reportan aparte (origen `reconstruido`), porque no traen encabezados de autenticación.

**Sandboxes públicos (ANY.RUN, MalwareBazaar):** sus `.zip` (clave `infected`) traen correos reales con **malware de
verdad** en los adjuntos. **Nunca los descomprimas.** Impórtalos con el script, que los abre en memoria y escribe una
copia sin el contenido de los adjuntos (conserva nombre, tipo, tamaño, sha256 y lo que vio el inspector de Centinela):

```bash
uv run python -I scripts/importar_sandbox.py ~/Downloads/tarea.zip --origen anyrun --categoria bancos \
    --url-fuente https://app.any.run/tasks/<id>
uv run python -I scripts/importar_sandbox.py ~/Downloads/<sha256>.zip --origen malwarebazaar --categoria otros
```

Después borra los `.zip`. En los sandboxes predomina el malware en inglés de otros países: **filtra solo correos en
español que suplanten entidades colombianas** (DIAN, SIMIT, Fiscalía, bancos…). Aun así, el informe se desglosa por
origen y categoría para mostrar que el resultado no depende de la procedencia.

## 2b. Registrar los correos (manifiesto)

Cada correo queda en `datos/colombia/manifiesto.csv` (archivo, sha256, etiqueta, categoria, origen, url_fuente,
fecha, campana). Los de sandbox se registran solos; los demás, después de copiarlos a su carpeta:

```bash
uv run python -I scripts/manifiesto.py                          # origen gmail_propio (tu buzón)
uv run python -I scripts/manifiesto.py --origen contribuido     # correos que te prestaron (con autorización)
uv run python -I scripts/manifiesto.py --origen sintetico       # escritos por ti como ejemplo
```

- **Duplicados:** dos archivos idénticos (mismo sha256) se cuentan una sola vez.
- **Campañas:** correos casi iguales (mismo asunto normalizado y remitente, o texto casi idéntico por simhash) quedan
  en la misma campaña `auto-...`. Puedes corregirla a mano en el CSV con cualquier nombre (p. ej.
  `dian-embargo-2026`); los nombres escritos a mano nunca se recalculan.
- Origen, url_fuente y fecha también se pueden corregir a mano. La carpeta manda sobre etiqueta y categoría.

## 3. Reglas para etiquetar
- **Phishing:** intenta robar datos, dinero o instalar algo, haciéndose pasar por alguien.
- **Legítimo:** el remitente es quien dice ser, aunque sea publicidad molesta.
- **Spam comercial** que no engaña (publicidad no deseada pero real): ponlo en `legitimo/boletines/`. Centinela
  detecta phishing, no spam.
- Si dudas de un correo, **no lo incluyas**.

## 4. Privacidad y consentimiento (Ley 1581 de 2012)
- Usa tus propios correos. Si alguien te comparte los suyos, pide su autorización por escrito; sirve como anexo de
  la tesis.
- Los archivos no salen de tu equipo, no se suben a git y los informes no contienen el cuerpo de los correos.
- Al terminar la tesis, borra `ml/datos/colombia/`.

## 5. Cómo se usa (protocolo)
```bash
cd ml
uv run python -I scripts/evaluar_colombia.py                            # ajuste: análisis de errores
uv run python -I scripts/evaluar_colombia.py --solo-contenido           # ajuste, sin encabezados de recepción
uv run python -I scripts/evaluar_colombia.py --conjunto prueba --abrir-prueba-final    # cifra final, UNA vez
```
1. La primera ejecución divide **por campaña** en **ajuste (50 %)** y **prueba (50 %)**, estratificado por clase:
   una campaña nunca queda repartida (si no, el sistema "vería" la prueba). La división queda en `particion.csv`.
   Los correos nuevos siguen a su campaña; las campañas nuevas van al conjunto con menos correos de su clase.
2. Con **ajuste** se analizan los errores y se mejora el sistema. Los legítimos de ajuste también pueden sumarse
   al entrenamiento para cerrar el hueco de correos cortos.
3. **Prueba** se abre una sola vez, al final, para las cifras de la tesis. Al abrirla se crea `prueba_abierta.json`
   y la división se congela: los correos que lleguen después van a «posterior» y no cuentan. Si después se cambia el
   modelo, se reporta como un experimento nuevo.
4. **Sesgo de procedencia:** los legítimos de Gmail traen la autenticación de Google y los de sandbox no. Reporta
   siempre las dos corridas (completa y `--solo-contenido`) y el desglose por origen y categoría. Una autenticación
   ausente cuenta como "desconocida", nunca como phishing.
5. **Cifra principal:** la tasa de falsos positivos en legítimos con su intervalo de Wilson al 95 % (con 0 errores en
   200 legítimos, el límite superior es 1,9 %), además de detección y precisión. No uses la exactitud (accuracy).
