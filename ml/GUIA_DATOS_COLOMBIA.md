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
etiqueta,categoria,remitente,asunto,cuerpo,enlaces
phishing,gobierno,DIAN <notificaciones@dian-cobros.com>,Proceso de embargo,"Usted tiene un proceso...",http://enlace1;http://enlace2
```

Estos se reportan aparte, porque no traen encabezados de autenticación.

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
uv run python -I scripts/evaluar_colombia.py --conjunto ajuste                         # análisis de errores
uv run python -I scripts/evaluar_colombia.py --conjunto prueba --abrir-prueba-final    # cifra final, UNA vez
```
1. La primera ejecución divide los correos en **ajuste (50 %)** y **prueba (50 %)**, y esa división queda fija.
2. Con **ajuste** se analizan los errores y se mejora el sistema. Los legítimos de ajuste también pueden sumarse
   al entrenamiento para cerrar el hueco de correos cortos.
3. **Prueba** se abre una sola vez, al final, para las cifras de la tesis. Si después se cambia el modelo, se
   reporta como un experimento nuevo.
