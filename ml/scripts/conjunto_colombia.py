"""Conjunto colombiano: manifiesto, campañas y división ajuste/prueba (lo usan evaluar_colombia.py,
importar_sandbox.py y manifiesto.py).

    datos/colombia/manifiesto.csv   una fila por correo ÚNICO (sha256): de dónde salió, su clase y su campaña
    datos/colombia/particion.csv    a qué conjunto (ajuste | prueba | posterior) va cada correo
    datos/colombia/prueba_abierta.json  existe desde que se abrió la prueba final: la división queda congelada

Campañas: correos casi duplicados (misma plantilla, mismo remitente) se agrupan para que una campaña nunca quede
repartida entre ajuste y prueba (sería una fuga: el modelo "vería" la prueba). Una campaña cuyo nombre NO empieza por
"auto-" la escribió una persona y nunca se recalcula.
"""
from __future__ import annotations

import csv
import hashlib
import json
import mailbox
import math
import re
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path

RAIZ_ML = Path(__file__).resolve().parents[1]
DATOS = RAIZ_ML / "datos" / "colombia"

CATEGORIAS = {
    "legitimo": ("personal", "laboral", "entidades", "facturas", "boletines", "cuentas"),
    "phishing": ("bancos", "gobierno", "logistica", "billeteras", "cuentas", "fraude_interno", "otros"),
}
ORIGENES = ("gmail_propio", "contribuido", "anyrun", "malwarebazaar", "reconstruido", "sintetico")
COLUMNAS_MANIFIESTO = ("archivo", "sha256", "etiqueta", "categoria", "origen", "url_fuente", "fecha", "campana")
COLUMNAS_RECONSTRUIDOS = ("etiqueta", "categoria", "remitente", "asunto", "cuerpo", "enlaces", "url_fuente", "entidad",
                          "fecha")
SEMILLA = 20261021

# Proveedores de correo gratuito: ahí el dominio no identifica al remitente (todos son gmail.com)
CORREO_GRATUITO = {"gmail.com", "googlemail.com", "hotmail.com", "hotmail.es", "outlook.com", "outlook.es", "live.com",
                   "yahoo.com", "yahoo.es", "icloud.com", "me.com", "aol.com", "protonmail.com", "proton.me", "gmx.com"}
MIN_ASUNTO = 8         # asuntos más cortos ("hola", "re:") no bastan para decir que dos correos son la misma campaña
MIN_PALABRAS_SIMHASH = 25
MAX_DISTANCIA_SIMHASH = 6     # de 64 bits; dos textos al azar difieren en ~32


# ---------------------------------------------------------------------------------------------- lectura de correos
@dataclass
class Correo:
    archivo: str          # ruta relativa a datos/colombia (con #n para mbox y reconstruidos.csv)
    sha256: str
    etiqueta: str         # legitimo | phishing
    categoria: str
    crudo: bytes
    origen: str | None = None          # solo reconstruidos.csv lo sabe de antemano
    url_fuente: str = ""
    fecha: str = ""


def sha256(crudo: bytes) -> str:
    return hashlib.sha256(crudo).hexdigest()


def fecha_de(crudo: bytes) -> str:
    try:
        msg = BytesParser(policy=policy.default).parsebytes(crudo, headersonly=True)
        return parsedate_to_datetime(str(msg.get("Date") or "")).date().isoformat()
    except (TypeError, ValueError, IndexError):
        return ""


def correo_reconstruido(fila: dict, i: int) -> bytes:
    """Arma un .eml a partir de una fila de reconstruidos.csv. Determinista: el mismo texto da el mismo sha256."""
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = fila["remitente"], "usuario@gmail.com", fila["asunto"]
    huella = sha256(json.dumps([fila.get(k, "") for k in COLUMNAS_RECONSTRUIDOS[:6]], ensure_ascii=False).encode())
    m["Message-ID"] = f"<reconstruido-{huella[:20]}@centinela.local>"
    if fila.get("fecha"):
        m["Date"] = fila["fecha"]
    enlaces = [e.strip() for e in (fila.get("enlaces") or "").split(";") if e.strip()]
    m.set_content(fila["cuerpo"])
    if enlaces:
        m.add_alternative("<p>" + fila["cuerpo"] + "</p>" + "".join(f'<a href="{e}">{e}</a> ' for e in enlaces),
                          subtype="html")
        m.set_boundary(f"centinela-{huella[:24]}")          # sin esto el límite MIME es aleatorio y cambia el sha256
    return m.as_bytes()


def explorar(datos: Path | None = None) -> tuple[list[Correo], list[str]]:
    """Todos los correos del árbol (eml, mbox y reconstruidos.csv). Devuelve también los avisos (duplicados, etc.)."""
    datos = datos or DATOS
    correos: list[Correo] = []
    avisos: list[str] = []
    for etiqueta in ("legitimo", "phishing"):
        base = datos / etiqueta
        for ruta in sorted(base.rglob("*")) if base.exists() else []:
            if not ruta.is_file() or ruta.suffix.lower() not in (".eml", ".mbox"):
                if ruta.is_file() and not ruta.name.startswith("."):
                    avisos.append(f"Ignorado (no es .eml ni .mbox): {ruta.relative_to(datos)}")
                continue
            categoria = ruta.relative_to(base).parts[0] if len(ruta.relative_to(base).parts) > 1 else "general"
            if categoria not in CATEGORIAS[etiqueta]:
                avisos.append(f"Categoría desconocida «{categoria}» en {ruta.relative_to(datos)}")
            rel = str(ruta.relative_to(datos))
            if ruta.suffix.lower() == ".eml":
                crudo = ruta.read_bytes()
                correos.append(Correo(rel, sha256(crudo), etiqueta, categoria, crudo, fecha=fecha_de(crudo)))
            else:
                for i, msg in enumerate(mailbox.mbox(ruta)):
                    crudo = msg.as_bytes()
                    correos.append(Correo(f"{rel}#{i}", sha256(crudo), etiqueta, categoria, crudo, fecha=fecha_de(crudo)))
    ruta_csv = datos / "reconstruidos.csv"
    if ruta_csv.exists():
        with ruta_csv.open(encoding="utf-8-sig") as f:
            for i, fila in enumerate(csv.DictReader(f)):
                etiqueta = "phishing" if fila["etiqueta"].strip().lower() in ("1", "phishing") else "legitimo"
                crudo = correo_reconstruido(fila, i)
                correos.append(Correo(f"reconstruidos.csv#{i + 2}", sha256(crudo), etiqueta,
                                      (fila.get("categoria") or "general").strip(), crudo, origen="reconstruido",
                                      url_fuente=(fila.get("url_fuente") or "").strip(),
                                      fecha=(fila.get("fecha") or "").strip()))
    return correos, avisos


# ------------------------------------------------------------------------------------------------------- campañas
def _plano(s: str) -> str:
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode().lower()
    return re.sub(r"\s+", " ", re.sub(r"\d+", "0", s)).strip()


def asunto_normalizado(asunto: str) -> str:
    s = _plano(asunto)
    while (n := re.sub(r"^\s*(re|rv|fw|fwd|reenviar|reenviado|tr|aw|wg)\s*:\s*", "", s)) != s:
        s = n
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0 ]+", " ", s)).strip()


def remitente_clave(remitente: str) -> str:
    """El dominio del remitente; en correos gratuitos (gmail.com…), la dirección completa."""
    _, direccion = parseaddr(remitente)
    direccion = direccion.lower()
    dominio = direccion.rsplit("@", 1)[-1] if "@" in direccion else ""
    return direccion if dominio in CORREO_GRATUITO else dominio


def simhash(texto: str, bits: int = 64) -> int | None:
    """Simhash de trigramas de palabras: textos casi iguales quedan a pocos bits de distancia."""
    palabras = re.findall(r"[a-z0]+", _plano(texto))
    if len(palabras) < MIN_PALABRAS_SIMHASH:
        return None
    pesos = [0] * bits
    for tri in (" ".join(palabras[i:i + 3]) for i in range(len(palabras) - 2)):
        h = int.from_bytes(hashlib.blake2b(tri.encode(), digest_size=8).digest(), "big")
        for b in range(bits):
            pesos[b] += 1 if h >> b & 1 else -1
    return sum(1 << b for b in range(bits) if pesos[b] > 0)


@dataclass
class Huella:
    asunto: str
    remitente: str
    simhash: int | None


def huella(crudo: bytes) -> Huella:
    from centinela.adaptadores.salida.lector_correo import LectorCorreoMime  # sin inspector: solo hace falta el texto

    c = LectorCorreoMime(b"campanas").leer(crudo)
    remitente = f"{c.remitente_nombre} <{c.remitente_correo}>"
    return Huella(asunto_normalizado(c.asunto), remitente_clave(remitente), simhash(f"{c.asunto} {c.cuerpo}"))


class _Union:
    def __init__(self, n: int):
        self.padre = list(range(n))

    def raiz(self, i: int) -> int:
        while self.padre[i] != i:
            self.padre[i] = self.padre[self.padre[i]]
            i = self.padre[i]
        return i

    def unir(self, a: int, b: int) -> None:
        self.padre[self.raiz(a)] = self.raiz(b)


def agrupar(etiquetas: list[str], huellas: list[Huella]) -> list[int]:
    """Grupo de cada correo. Se unen (siempre dentro de la misma clase) si comparten asunto normalizado y remitente,
    o si sus textos son casi idénticos (simhash a ≤ MAX_DISTANCIA_SIMHASH bits)."""
    u = _Union(len(huellas))
    por_clave: dict[tuple, int] = {}
    for i, (e, h) in enumerate(zip(etiquetas, huellas, strict=True)):
        if len(h.asunto) >= MIN_ASUNTO and h.remitente:
            k = (e, h.asunto, h.remitente)
            if k in por_clave:
                u.unir(i, por_clave[k])
            else:
                por_clave[k] = i
    # Simhash: k+1 bandas; dos huellas a ≤ k bits de distancia coinciden en al menos una banda (palomar)
    n_bandas = MAX_DISTANCIA_SIMHASH + 1
    cortes = [round(64 * b / n_bandas) for b in range(n_bandas + 1)]
    for banda in range(n_bandas):
        ancho = cortes[banda + 1] - cortes[banda]
        cubetas: dict[tuple, list[int]] = defaultdict(list)
        for i, (e, h) in enumerate(zip(etiquetas, huellas, strict=True)):
            if h.simhash is not None:
                cubetas[(e, banda, h.simhash >> cortes[banda] & ((1 << ancho) - 1))].append(i)
        for miembros in cubetas.values():
            for a in range(len(miembros)):
                for b in range(a + 1, len(miembros)):
                    i, j = miembros[a], miembros[b]
                    if (huellas[i].simhash ^ huellas[j].simhash).bit_count() <= MAX_DISTANCIA_SIMHASH:
                        u.unir(i, j)
    return [u.raiz(i) for i in range(len(huellas))]


def es_manual(campana: str) -> bool:
    return bool(campana) and not campana.startswith("auto-")


# ---------------------------------------------------------------------------------------------------- manifiesto
def leer_manifiesto(datos: Path | None = None) -> list[dict]:
    datos = datos or DATOS
    ruta = datos / "manifiesto.csv"
    if not ruta.exists():
        return []
    with ruta.open(encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def escribir_manifiesto(filas: list[dict], datos: Path | None = None) -> None:
    datos = datos or DATOS
    with (datos / "manifiesto.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNAS_MANIFIESTO, extrasaction="ignore")
        w.writeheader()
        w.writerows(sorted(filas, key=lambda r: r["archivo"]))


@dataclass
class Sincronizacion:
    nuevos: int = 0
    retirados: list[str] = field(default_factory=list)
    duplicados: list[tuple[str, str]] = field(default_factory=list)     # (archivo repetido, archivo que se conserva)
    sin_registrar: list[str] = field(default_factory=list)
    avisos: list[str] = field(default_factory=list)


def sincronizar(origen_por_defecto: str | None = "gmail_propio", metadatos: dict[str, dict] | None = None,
                recalcular_campanas: bool = False, datos: Path | None = None) -> tuple[list[dict], Sincronizacion]:
    """Pone el manifiesto al día con los archivos: agrega los nuevos, quita los que ya no existen, deduplica por
    sha256 y asigna campaña a quien no la tenga. Las correcciones a mano (origen, url, fecha, campaña) se respetan.

    metadatos: {archivo: {origen, url_fuente, fecha, campana}} para los correos nuevos (lo usa importar_sandbox.py).
    origen_por_defecto=None: los archivos nuevos sin metadatos NO se agregan (quedan en res.sin_registrar)."""
    datos = datos or DATOS
    if origen_por_defecto is not None and origen_por_defecto not in ORIGENES:
        raise ValueError(f"Origen desconocido: {origen_por_defecto}")
    metadatos = metadatos or {}
    correos, avisos = explorar(datos)
    previo = {r["sha256"]: r for r in leer_manifiesto(datos)}
    res = Sincronizacion(avisos=avisos)
    filas: dict[str, dict] = {}
    crudos: dict[str, bytes] = {}
    for c in correos:
        if c.sha256 in filas:
            res.duplicados.append((c.archivo, filas[c.sha256]["archivo"]))
            continue
        crudos[c.sha256] = c.crudo
        if c.sha256 in previo:
            fila = dict(previo[c.sha256])
            fila.update(archivo=c.archivo, etiqueta=c.etiqueta, categoria=c.categoria)    # la carpeta manda
        else:
            meta = metadatos.get(c.archivo, {})
            origen = meta.get("origen") or c.origen or origen_por_defecto
            if origen is None:
                res.sin_registrar.append(c.archivo)
                del crudos[c.sha256]
                continue
            fila = {"archivo": c.archivo, "sha256": c.sha256, "etiqueta": c.etiqueta, "categoria": c.categoria,
                    "origen": origen, "url_fuente": meta.get("url_fuente") or c.url_fuente,
                    "fecha": meta.get("fecha") or c.fecha, "campana": meta.get("campana") or ""}
            res.nuevos += 1
        if fila["origen"] not in ORIGENES:
            res.avisos.append(f"Origen desconocido «{fila['origen']}» en {fila['archivo']}")
        filas[c.sha256] = fila
    res.retirados = sorted(r["archivo"] for s, r in previo.items() if s not in filas)

    lista = list(filas.values())
    if recalcular_campanas:
        for f in lista:
            if not es_manual(f["campana"]):
                f["campana"] = ""
    if any(not f["campana"] for f in lista):
        _asignar_campanas(lista, crudos)
    escribir_manifiesto(lista, datos)
    return lista, res


def _asignar_campanas(filas: list[dict], crudos: dict[str, bytes]) -> None:
    grupos = agrupar([f["etiqueta"] for f in filas], [huella(crudos[f["sha256"]]) for f in filas])
    miembros: dict[int, list[dict]] = defaultdict(list)
    for f, g in zip(filas, grupos, strict=True):
        miembros[g].append(f)
    for grupo in miembros.values():
        sin = [f for f in grupo if not f["campana"]]
        if not sin:
            continue
        conocidas = Counter(f["campana"] for f in grupo if f["campana"])
        manuales = [c for c, _ in conocidas.most_common() if es_manual(c)]
        nombre = (manuales or [c for c, _ in conocidas.most_common()] or
                  ["auto-" + min(f["sha256"] for f in grupo)[:10]])[0]
        for f in sin:
            f["campana"] = nombre


# ------------------------------------------------------------------------------------------------------- división
@dataclass
class Particion:
    conjunto: dict[str, str]                 # sha256 -> ajuste | prueba | posterior
    regenerada: bool
    avisos: list[str]


def prueba_abierta(datos: Path | None = None) -> bool:
    datos = datos or DATOS
    return (datos / "prueba_abierta.json").exists()


def _leer_particion(datos: Path) -> tuple[dict[str, str], bool]:
    """(sha256 -> conjunto, formato_actual). El formato antiguo (por hash, sin campaña) se marca para regenerar."""
    ruta = datos / "particion.csv"
    if not ruta.exists():
        return {}, True
    with ruta.open() as f:
        filas = list(csv.DictReader(f))
    if filas and "campana" not in filas[0]:
        return {r["id"]: r["conjunto"] for r in filas}, False
    return {r["sha256"]: r["conjunto"] for r in filas}, True


def _division_completa(filas: list[dict]) -> dict[str, str]:
    """50/50 por campaña, estratificada por clase en lo posible (StratifiedGroupKFold con 2 pliegues)."""
    from sklearn.model_selection import StratifiedGroupKFold

    campanas = sorted({f["campana"] for f in filas})
    if len(campanas) < 2:
        return {f["sha256"]: "ajuste" for f in filas}
    y = [f["etiqueta"] for f in filas]
    grupos = [f["campana"] for f in filas]
    clases = Counter(y)
    # StratifiedGroupKFold exige al menos 2 ejemplos por clase; si no, la división es solo por campaña
    if min(clases.values()) >= 2 and len(clases) == 2:
        corte = StratifiedGroupKFold(n_splits=2, shuffle=True, random_state=SEMILLA)
    else:
        from sklearn.model_selection import GroupKFold
        corte = GroupKFold(n_splits=2)
    _, prueba = next(iter(corte.split(filas, y, grupos)))
    en_prueba = {grupos[i] for i in prueba}
    return {f["sha256"]: "prueba" if f["campana"] in en_prueba else "ajuste" for f in filas}


def dividir(filas: list[dict], regenerar: bool = False, datos: Path | None = None) -> Particion:
    """Asigna cada correo a ajuste o prueba sin partir campañas. Estable: los correos ya asignados no cambian de
    conjunto (salvo al regenerar). Con la prueba ya abierta, todo correo nuevo va a "posterior" y no cuenta."""
    datos = datos or DATOS
    abierta = prueba_abierta(datos)
    previo, formato_actual = _leer_particion(datos)
    avisos: list[str] = []
    if regenerar and abierta:
        raise SystemExit("La prueba final ya se abrió: la división no se puede regenerar.")
    if not formato_actual:
        if abierta:
            raise SystemExit("La división es del formato antiguo y la prueba ya se abrió: no se puede corregir.")
        avisos.append("La división anterior no respetaba campañas: se regeneró por campaña (la prueba no se había abierto).")
        regenerar = True

    if regenerar or not previo:
        asignado = _division_completa(filas)
        regenerada = True
    else:
        regenerada = False
        asignado = {}
        por_campana: dict[str, list[dict]] = defaultdict(list)
        for f in filas:
            por_campana[f["campana"]].append(f)
        conteo = Counter((previo[f["sha256"]], f["etiqueta"]) for f in filas if previo.get(f["sha256"]) in ("ajuste", "prueba"))
        for campana in sorted(por_campana, key=lambda c: min(f["sha256"] for f in por_campana[c])):
            grupo = por_campana[campana]
            antes = {previo[f["sha256"]] for f in grupo if f["sha256"] in previo} - {"posterior"}
            if abierta:
                for f in grupo:
                    asignado[f["sha256"]] = previo.get(f["sha256"], "posterior")
                if len(antes) > 1:
                    avisos.append(f"La campaña «{campana}» está en ajuste y en prueba (se unió después de abrir la prueba).")
                continue
            if len(antes) == 1:
                destino = antes.pop()
            elif len(antes) > 1:
                destino = "ajuste"
                avisos.append(f"La campaña «{campana}» estaba repartida (¿se unieron campañas a mano?): pasa entera a ajuste.")
            else:                            # campaña nueva: al conjunto con menos correos de su clase
                clase = Counter(f["etiqueta"] for f in grupo).most_common(1)[0][0]
                destino = "ajuste" if conteo[("ajuste", clase)] <= conteo[("prueba", clase)] else "prueba"
            for f in grupo:
                asignado[f["sha256"]] = destino
                conteo[(destino, f["etiqueta"])] += 1
        if abierta and any(v == "posterior" for v in asignado.values()):
            avisos.append("Hay correos nuevos después de abrir la prueba: van a «posterior» y no cuentan en ninguna cifra.")

    campana_de = {f["sha256"]: f["campana"] for f in filas}
    with (datos / "particion.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sha256", "campana", "conjunto"])
        w.writerows(sorted((s, campana_de[s], c) for s, c in asignado.items()))
    return Particion(asignado, regenerada, avisos)


def campanas_repartidas(filas: list[dict], conjunto: dict[str, str]) -> list[str]:
    vistos: dict[str, set[str]] = defaultdict(set)
    for f in filas:
        if conjunto.get(f["sha256"]) in ("ajuste", "prueba"):
            vistos[f["campana"]].add(conjunto[f["sha256"]])
    return sorted(c for c, s in vistos.items() if len(s) > 1)


def sellar_prueba(datos: Path | None = None) -> None:
    """Deja constancia de que la prueba final se abrió: desde ahí la división queda congelada."""
    datos = datos or DATOS
    ruta = datos / "prueba_abierta.json"
    if not ruta.exists():
        ruta.write_text(json.dumps({"fecha": datetime.now().isoformat(timespec="seconds"),
                                    "particion_sha256": sha256((datos / "particion.csv").read_bytes())}, indent=2))


# ------------------------------------------------------------------------------------------------- estadísticas
def wilson(k: int, n: int, z: float = 1.96) -> list[float | None]:
    """Intervalo de confianza de Wilson al 95 % para una proporción k/n. A diferencia del bootstrap, no colapsa a
    [0, 0] cuando no hubo ningún error (con 0 de 200 falsos positivos el límite superior es ~1,9 %, no 0 %)."""
    if n == 0:
        return [None, None]
    p = k / n
    denom = 1 + z * z / n
    centro = (p + z * z / (2 * n)) / denom
    margen = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return [round(max(0.0, centro - margen), 4), round(min(1.0, centro + margen), 4)]


def crear_arbol(datos: Path | None = None) -> list[str]:
    """Carpetas de GUIA_DATOS_COLOMBIA.md y los CSV con sus encabezados (no toca los que ya tienen datos)."""
    datos = datos or DATOS
    hechos = []
    for etiqueta, categorias in CATEGORIAS.items():
        for c in categorias:
            (datos / etiqueta / c).mkdir(parents=True, exist_ok=True)
    for nombre, columnas in (("manifiesto.csv", COLUMNAS_MANIFIESTO), ("reconstruidos.csv", COLUMNAS_RECONSTRUIDOS)):
        ruta = datos / nombre
        if ruta.exists():
            with ruta.open(encoding="utf-8-sig") as f:
                lineas = f.read().splitlines()
            actuales = next(csv.reader(lineas[:1]), [])
            if len(lineas) > 1:
                faltan = [c for c in columnas if c not in actuales]
                if faltan:
                    hechos.append(f"{nombre} ya tiene datos y le faltan columnas {faltan}: agrégalas a mano")
                continue
            if actuales == list(columnas):
                continue
        with ruta.open("w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(columnas)
        hechos.append(f"{nombre}: encabezados {', '.join(columnas)}")
    return hechos
