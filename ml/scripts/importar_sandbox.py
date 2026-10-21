"""Importa correos de phishing de sandboxes públicos (ANY.RUN, MalwareBazaar) SIN dejar malware en el disco.

Los .zip de estos servicios traen .eml reales con adjuntos maliciosos (protegidos con la clave "infected"). Este
script los abre EN MEMORIA (pyzipper: ZipCrypto o AES) y escribe en datos/colombia/phishing/<categoria>/ una copia
saneada de cada correo:

  * Se conservan todos los encabezados y los cuerpos text/plain y text/html.
  * Cada adjunto (y cada correo reenviado, message/rfc822) queda como una parte VACÍA que conserva nombre de
    archivo y Content-Type, y agrega X-Centinela-Retirado: tamano=<bytes>; sha256=<del original>.
  * Antes de vaciarlo, el adjunto pasa por el mismo inspector de Centinela que se usa en producción (en memoria) y
    su resultado (tipo real, señales, archivos internos, enlaces y QR, todo texto) queda en X-Centinela-Inspeccion.
    Así la evaluación mide lo mismo que vería producción sin necesitar el archivo.
  * En los cuerpos se retira todo bloque base64 de 2 KB o más (técnica de "HTML smuggling": un .zip o un programa
    escondido dentro del HTML), dejando una marca con su tamaño y sha256.
  * Antes de escribir se vuelve a leer el resultado: si algún adjunto conserva contenido o queda un ejecutable o un
    comprimido en un cuerpo, ese correo NO se escribe.

    uv run python -I scripts/importar_sandbox.py ~/Downloads/tarea.zip --origen anyrun --categoria bancos \\
        --url-fuente https://app.any.run/tasks/<id>
    uv run python -I scripts/importar_sandbox.py ~/Downloads/<sha256>.zip --origen malwarebazaar --categoria otros

Después de importar, borra los .zip descargados.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import sys
from dataclasses import dataclass, field
from email import policy
from email.generator import BytesGenerator
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

import pyzipper

sys.path.insert(0, str(Path(__file__).resolve().parent))      # python -I no agrega la carpeta del script
import conjunto_colombia as cc

# Conserva los encabezados tal como vienen (sin volver a plegarlos)
POLITICA = policy.default.clone(refold_source="none")
MAX_MIEMBRO = 50 * 1024 * 1024
MAX_TOTAL = 300 * 1024 * 1024
MIN_BLOQUE_B64 = 2048
_RE_BLOQUE_B64 = re.compile(rb"[A-Za-z0-9+/]{" + str(MIN_BLOQUE_B64).encode() + rb",}={0,2}")
_RE_BLOQUE_B64_TEXTO = re.compile(r"[A-Za-z0-9+/]{" + str(MIN_BLOQUE_B64) + r",}={0,2}")
ENCABEZADO_RETIRADO = "X-Centinela-Retirado"
ENCABEZADO_INSPECCION = "X-Centinela-Inspeccion"
FIRMAS_PELIGROSAS = {b"MZ": "ejecutable de Windows", b"\x7fELF": "ejecutable de Linux", b"PK\x03\x04": "zip",
                     b"Rar!": "rar", b"7z\xbc\xaf": "7z", b"\xcf\xfa\xed\xfe": "ejecutable de Mac",
                     b"\xd0\xcf\x11\xe0": "documento OLE", b"%PDF": "pdf"}
FIRMAS_IMAGEN = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"BM")
URL_MALWAREBAZAAR = "https://bazaar.abuse.ch/sample/{}/"


class CorreoInseguro(Exception):
    """El correo saneado aún conserva algo que no debe llegar al disco."""


@dataclass
class Retirado:
    nombre: str
    tipo: str
    tamano: int
    sha256: str


@dataclass
class Saneado:
    crudo: bytes
    retirados: list[Retirado] = field(default_factory=list)
    bloques_b64: int = 0
    imagenes_conservadas: int = 0


# ------------------------------------------------------------------------------------------------------ saneamiento
def _es_cuerpo(parte: EmailMessage) -> bool:
    """Igual que el lector de Centinela: solo text/plain y text/html sin nombre y no marcados como adjunto."""
    return (parte.get_content_type() in ("text/plain", "text/html") and parte.get_content_disposition() != "attachment"
            and not parte.get_filename())


def _es_imagen_raster(datos: bytes, tipo: str) -> bool:
    return tipo.startswith("image/") and tipo != "image/svg+xml" and (
        datos.startswith(FIRMAS_IMAGEN) or (datos[:4] == b"RIFF" and datos[8:12] == b"WEBP"))


def _bytes_de(parte: EmailMessage) -> bytes:
    if parte.get_content_type() == "message/rfc822" and parte.is_multipart():
        return parte.get_payload(0).as_bytes(policy=POLITICA)
    return parte.get_payload(decode=True) or b""


def _sin_bloques(texto: str) -> tuple[str, int]:
    n = 0

    def marca(m: re.Match) -> str:
        nonlocal n
        n += 1
        bloque = m.group(0)
        return f"[centinela: bloque base64 retirado, {len(bloque)} caracteres, sha256 {hashlib.sha256(bloque.encode()).hexdigest()}]"

    return _RE_BLOQUE_B64_TEXTO.sub(marca, texto), n


def _inspeccion(inspector, parte: EmailMessage, datos: bytes) -> dict:
    tipo = parte.get_content_type()
    if tipo.startswith("image/") and parte.get_content_disposition() != "attachment":
        return {"qr": list(inspector.qr_de_imagen(datos))}      # imagen del cuerpo: el lector solo le busca QR
    nombre = (parte.get_filename() or "(sin nombre)")[:255]
    i = inspector.inspeccionar(nombre, tipo, datos)
    return {"tipo_real": i.tipo_real, "senales": [s.value for s in i.senales], "contenido": list(i.contenido),
            "enlaces": list(i.enlaces), "qr": list(i.qr)}


def sanear(crudo: bytes, inspector=None, conservar_imagenes: bool = False) -> Saneado:
    """Devuelve el correo sin el contenido de sus adjuntos. No escribe nada en disco."""
    if inspector is None:
        from centinela.adaptadores.salida.inspector_adjuntos import InspectorAdjuntos
        inspector = InspectorAdjuntos()
    msg = BytesParser(policy=POLITICA).parsebytes(crudo)
    res = Saneado(b"")

    def visitar(parte: EmailMessage) -> None:
        tipo = parte.get_content_type()
        if parte.is_multipart() and tipo != "message/rfc822":
            for sub in parte.iter_parts():
                visitar(sub)
            return
        if not parte.is_multipart() and _es_cuerpo(parte):
            try:
                texto = parte.get_content()
            except Exception:  # noqa: BLE001 - codificación rota: se revisa en bruto
                texto = (parte.get_payload(decode=True) or b"").decode("utf-8", "replace")
            limpio, n = _sin_bloques(texto)
            if n:
                parte.set_content(limpio, subtype=tipo.split("/")[1], charset="utf-8")
                res.bloques_b64 += n
            return
        datos = _bytes_de(parte)
        if conservar_imagenes and not parte.is_multipart() and _es_imagen_raster(datos, tipo):
            res.imagenes_conservadas += 1
            return
        huella = hashlib.sha256(datos).hexdigest()
        res.retirados.append(Retirado(parte.get_filename() or "(sin nombre)", tipo, len(datos), huella))
        inspeccion = json.dumps(_inspeccion(inspector, parte, datos), ensure_ascii=True, separators=(",", ":"))
        parte.set_payload("")
        del parte["Content-Transfer-Encoding"]
        parte[ENCABEZADO_RETIRADO] = f"tamano={len(datos)}; sha256={huella}"
        # base64 para que ningún plegado de línea altere el JSON
        parte[ENCABEZADO_INSPECCION] = base64.b64encode(inspeccion.encode()).decode()

    visitar(msg)
    res.crudo = _serializar(crudo, msg)
    verificar(res.crudo, conservar_imagenes)
    return res


def _corte(crudo: bytes) -> tuple[int, bytes] | None:
    """Posición y separador donde terminan los encabezados principales."""
    cortes = [(i, sep) for sep in (b"\r\n\r\n", b"\n\n") if (i := crudo.find(sep)) >= 0]
    return min(cortes) if cortes else None


def _serializar(original: bytes, msg: EmailMessage) -> bytes:
    """Genera el correo saneado. Si el mensaje principal es multipart, sus encabezados se copian byte a byte del
    original (el generador de Python los volvería a plegar) y solo se regenera el cuerpo."""
    corte = _corte(original)
    fin_de_linea = "\r\n" if corte and corte[1] == b"\r\n\r\n" else "\n"
    salida = io.BytesIO()
    BytesGenerator(salida, mangle_from_=False, policy=POLITICA.clone(linesep=fin_de_linea)).flatten(msg)
    generado = salida.getvalue()
    corte_generado = _corte(generado)
    if not (msg.is_multipart() and corte and corte_generado):
        return generado
    return original[:corte[0]] + corte[1] + generado[corte_generado[0] + len(corte_generado[1]):]


def verificar(crudo: bytes, conservar_imagenes: bool = False) -> None:
    """Relee el correo saneado y comprueba que no quede contenido peligroso. Lanza CorreoInseguro si algo falla."""
    msg = BytesParser(policy=POLITICA).parsebytes(crudo)
    for parte in msg.walk():
        tipo = parte.get_content_type()
        if tipo == "message/rfc822":
            interno = parte.get_payload(0) if parte.is_multipart() else None
            if parte[ENCABEZADO_RETIRADO] is None or (interno is not None and len(interno.as_bytes().strip()) > 0):
                raise CorreoInseguro("un correo reenviado conserva su contenido")
            continue
        if parte.is_multipart():
            continue
        datos = parte.get_payload(decode=True) or b""
        if _es_cuerpo(parte):
            if _RE_BLOQUE_B64.search(datos):
                raise CorreoInseguro("un cuerpo conserva un bloque base64 largo")
            for firma, que in FIRMAS_PELIGROSAS.items():
                if datos.lstrip().startswith(firma):
                    raise CorreoInseguro(f"un cuerpo es en realidad un {que}")
            continue
        if conservar_imagenes and _es_imagen_raster(datos, tipo):
            continue
        if datos or parte[ENCABEZADO_RETIRADO] is None:
            raise CorreoInseguro(f"el adjunto «{parte.get_filename()}» conserva contenido")


# ------------------------------------------------------------------------------------------------------------- zip
def parece_correo(datos: bytes) -> bool:
    cabeza = datos[:8192]
    if b"\x00" in cabeza:
        return False
    msg = BytesParser(policy=policy.compat32).parsebytes(cabeza, headersonly=True)
    return msg.get("From") is not None and (msg.get("Subject") is not None or msg.get("Date") is not None)


def correos_del_zip(ruta: Path, clave: str) -> tuple[list[tuple[str, bytes]], list[str]]:
    """[(nombre, bytes)] de los correos del zip, leídos en memoria. Los demás archivos se omiten (y se informan)."""
    correos, omitidos, total = [], [], 0
    with pyzipper.AESZipFile(io.BytesIO(ruta.read_bytes())) as z:
        z.setpassword(clave.encode())
        for info in z.infolist():
            if info.is_dir():
                continue
            if info.file_size > MAX_MIEMBRO or total + info.file_size > MAX_TOTAL:
                omitidos.append(f"{info.filename} (demasiado grande: {info.file_size} bytes)")
                continue
            total += info.file_size
            nombre = info.filename.lower()
            if nombre.endswith((".msg", ".oft")):
                omitidos.append(f"{info.filename} (formato Outlook .msg: expórtalo como .eml)")
                continue
            datos = z.read(info)                                   # en memoria: nunca se extrae a disco
            if nombre.endswith(".eml") or parece_correo(datos):
                correos.append((info.filename, datos))
            else:
                omitidos.append(f"{info.filename} (no es un correo)")
            del datos
    return correos, omitidos


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("zips", nargs="+", type=Path)
    ap.add_argument("--origen", required=True, choices=["anyrun", "malwarebazaar"])
    ap.add_argument("--categoria", required=True, choices=cc.CATEGORIAS["phishing"])
    ap.add_argument("--clave", default="infected", help="contraseña de los .zip (por defecto: infected)")
    ap.add_argument("--url-fuente", default="", help="página de la tarea o muestra (MalwareBazaar se completa solo)")
    ap.add_argument("--fecha", default="", help="AAAA-MM-DD; por defecto, la fecha del encabezado Date")
    ap.add_argument("--campana", default="", help="nombre de campaña (si sabes que todos son de la misma)")
    ap.add_argument("--conservar-imagenes", action="store_true",
                    help="no vaciar imágenes PNG/JPEG/GIF/WEBP/BMP verificadas (para que la evaluación lea sus QR)")
    ap.add_argument("--simular", action="store_true", help="solo muestra lo que haría, sin escribir nada")
    args = ap.parse_args()

    from centinela.adaptadores.salida.inspector_adjuntos import InspectorAdjuntos

    inspector = InspectorAdjuntos()
    destino = cc.DATOS / "phishing" / args.categoria
    cc.crear_arbol()
    conocidos = {r["sha256"] for r in cc.leer_manifiesto()}
    metadatos: dict[str, dict] = {}
    escritos = repetidos = rechazados = 0
    for ruta in args.zips:
        try:
            correos, omitidos = correos_del_zip(ruta, args.clave)
        except (RuntimeError, pyzipper.BadZipFile) as e:
            print(f"✗ {ruta.name}: no se pudo abrir ({e}). ¿La clave es correcta?")
            continue
        for o in omitidos:
            print(f"  · {ruta.name}: omitido {o}")
        for nombre, crudo in correos:
            original = hashlib.sha256(crudo).hexdigest()
            try:
                s = sanear(crudo, inspector, args.conservar_imagenes)
            except CorreoInseguro as e:
                print(f"✗ {nombre}: NO se escribió ({e})")
                rechazados += 1
                continue
            huella = cc.sha256(s.crudo)
            archivo = destino / f"{args.origen}-{huella[:16]}.eml"
            if huella in conocidos or archivo.exists():
                repetidos += 1
                print(f"= {nombre}: ya estaba en el conjunto")
                continue
            url = args.url_fuente or (URL_MALWAREBAZAAR.format(original) if args.origen == "malwarebazaar" else "")
            detalle = ", ".join(f"{r.nombre} ({r.tipo}, {r.tamano} B)" for r in s.retirados) or "sin adjuntos"
            extra = f"; {s.bloques_b64} bloque(s) base64 retirados del cuerpo" if s.bloques_b64 else ""
            print(f"✓ {nombre} → {archivo.relative_to(cc.DATOS)}  [retirados: {detalle}{extra}]")
            if not args.simular:
                archivo.write_bytes(s.crudo)
                metadatos[str(archivo.relative_to(cc.DATOS))] = {
                    "origen": args.origen, "url_fuente": url, "fecha": args.fecha or cc.fecha_de(s.crudo),
                    "campana": args.campana}
            conocidos.add(huella)
            escritos += 1

    if not args.simular and escritos:
        _, sinc = cc.sincronizar(origen_por_defecto=None, metadatos=metadatos)
        for a in sinc.sin_registrar:
            print(f"  ! {a} no está en el manifiesto: regístralo con scripts/manifiesto.py --origen ...")
    print(f"\n{escritos} correo(s) {'por importar' if args.simular else 'importados'}, {repetidos} repetidos, "
          f"{rechazados} rechazados por seguridad. Ahora puedes borrar los .zip descargados.")


if __name__ == "__main__":
    main()
