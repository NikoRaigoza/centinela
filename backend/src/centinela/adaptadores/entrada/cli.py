"""Consola de administración del servidor.

    uv run centinela crear-admin --correo admin@ejemplo.co --nombre "Administración"
    uv run centinela api            # levanta la API en http://localhost:8000
    uv run centinela worker         # revisa los buzones conectados cada 30 s
"""
from __future__ import annotations

import argparse
import getpass
import sys

from centinela.dominio.errores import ErrorCentinela


def _crear_admin(args: argparse.Namespace) -> int:
    from centinela.contenedor import construir

    clave = getpass.getpass("Contraseña del administrador: ")
    if clave != getpass.getpass("Repite la contraseña: "):
        print("Las contraseñas no coinciden.", file=sys.stderr)
        return 1
    try:
        admin = construir().crear_administrador.ejecutar(args.correo, args.nombre, clave)
    except ErrorCentinela as e:
        print(e.mensaje, file=sys.stderr)
        return 1
    print(f"Administrador creado (id {admin.id}). Al iniciar sesión deberá configurar el doble factor.")
    return 0


def _api(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("centinela.adaptadores.entrada.api.app:crear_app", factory=True, host=args.host, port=args.puerto,
                reload=args.recargar)
    return 0


def _worker(args: argparse.Namespace) -> int:
    import logging
    import signal
    import threading
    import time

    from centinela.contenedor import construir

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("centinela.worker")
    c = construir()
    if not c.config.gmail_configurado:
        print("Falta configurar Gmail (CENTINELA_GMAIL_CLIENT_ID y CENTINELA_GMAIL_CLIENT_SECRET).", file=sys.stderr)
        return 1
    parar = threading.Event()
    for senal in (signal.SIGINT, signal.SIGTERM):
        signal.signal(senal, lambda *_: parar.set())

    log.info("Worker iniciado: revisa cada buzón cada %s s", c.revisar_pendientes.intervalo_segundos())
    while not parar.is_set():
        inicio = time.monotonic()
        try:
            for r in c.revisar_pendientes.ejecutar():
                # Solo cifras: los registros nunca incluyen remitentes ni asuntos (privacidad).
                if r.nuevos or r.error:
                    log.info("buzón %s: %s nuevos, %s omitidos, estado=%s", r.buzon_id, r.nuevos, r.omitidos, r.estado)
        except Exception:
            log.exception("Falló un ciclo de revisión; se reintenta en el siguiente")
        if args.una_vez:
            break
        parar.wait(max(1.0, args.pausa - (time.monotonic() - inicio)))
    log.info("Worker detenido")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="centinela", description="Administración de Centinela")
    sub = p.add_subparsers(dest="comando", required=True)

    a = sub.add_parser("crear-admin", help="Crea una cuenta de administrador")
    a.add_argument("--correo", required=True)
    a.add_argument("--nombre", required=True)
    a.set_defaults(fn=_crear_admin)

    s = sub.add_parser("api", help="Levanta la API")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--puerto", type=int, default=8000)
    s.add_argument("--recargar", action="store_true")
    s.set_defaults(fn=_api)

    w = sub.add_parser("worker", help="Revisa periódicamente los buzones conectados")
    w.add_argument("--pausa", type=float, default=5.0, help="segundos entre ciclos (cada buzón respeta su intervalo)")
    w.add_argument("--una-vez", action="store_true", help="hace un solo ciclo y termina")
    w.set_defaults(fn=_worker)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
