"""Consola de administración del servidor.

    uv run centinela crear-admin --correo admin@ejemplo.co --nombre "Administración"
    uv run centinela api            # levanta la API en http://localhost:8000
    uv run centinela worker         # revisa los buzones conectados cada 30 s y entrega los avisos
    uv run centinela generar-vapid --contacto mailto:admin@ejemplo.co   # llaves de las notificaciones push
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
    despertar = threading.Event()                # lo activa una señal de parada o un aviso de Gmail en tiempo real

    def detener(*_):
        parar.set()
        despertar.set()

    for senal in (signal.SIGINT, signal.SIGTERM):
        signal.signal(senal, detener)

    tiempo_real = c.renovar_vigilancias.activo
    if tiempo_real:
        from centinela.adaptadores.salida.postgres.despertador import Despertador

        Despertador(c.config.bd_url, despertar, parar).iniciar()
        log.info("Worker iniciado con avisos de Gmail en tiempo real (revisión de respaldo cada %s s)",
                 c.revisar_pendientes.intervalo_respaldo_segundos())
    else:
        log.info("Worker iniciado: revisa cada buzón cada %s s", c.revisar_pendientes.intervalo_segundos())
    proxima_renovacion = 0.0
    while not parar.is_set():
        inicio = time.monotonic()
        despertar.clear()
        try:
            if tiempo_real and inicio >= proxima_renovacion:
                if renovados := c.renovar_vigilancias.ejecutar():
                    log.info("Avisos en tiempo real activados o renovados en %s buzón(es)", renovados)
                proxima_renovacion = inicio + 60
            for r in c.revisar_pendientes.ejecutar():
                # Solo cifras: los registros nunca incluyen remitentes ni asuntos (privacidad).
                if r.nuevos or r.error:
                    log.info("buzón %s: %s nuevos, %s omitidos, estado=%s", r.buzon_id, r.nuevos, r.omitidos, r.estado)
            if enviados := c.enviar_avisos.ejecutar():
                log.info("%s aviso(s) entregados", enviados)
        except Exception:
            log.exception("Falló un ciclo de revisión; se reintenta en el siguiente")
        if args.una_vez:
            break
        despertar.wait(max(1.0, args.pausa - (time.monotonic() - inicio)))
    log.info("Worker detenido")
    return 0


def _generar_vapid(args: argparse.Namespace) -> int:
    from centinela.adaptadores.salida.push import generar_llaves_vapid

    if not args.contacto.startswith(("mailto:", "https://")):
        print("El contacto debe empezar por mailto: o https://", file=sys.stderr)
        return 1
    privada, publica = generar_llaves_vapid()
    print("# Agrega estas líneas a backend/.env (la llave privada es un secreto: no la compartas ni la subas a git).")
    print("# Si la cambias después, cada persona deberá activar de nuevo los avisos en sus dispositivos.")
    print(f"CENTINELA_VAPID_CLAVE_PRIVADA={privada}")
    print(f"CENTINELA_VAPID_CONTACTO={args.contacto}")
    print(f"# Llave pública (el panel la obtiene sola de la API): {publica}")
    return 0


def _modelos(args: argparse.Namespace) -> int:
    from pathlib import Path

    from centinela.adaptadores.salida.ml.registro import MANIFIESTO, leer_manifiesto, sha256_archivo, verificar
    from centinela.aplicacion.puertos import ModeloRegistrado
    from centinela.contenedor import construir

    c = construir()
    if args.accion == "listar":
        with c.uow() as uow:
            for m in uow.modelos.listar():
                print(f"{'● activo' if m.activo else '  -     '}  #{m.id} {m.tipo:9s} {m.version:16s} {m.nombre}")
        return 0
    carpeta = Path(args.carpeta).resolve()
    try:
        ruta = carpeta.relative_to(c.config.dir_modelos.resolve())
    except ValueError:
        print(f"La carpeta debe estar dentro de {c.config.dir_modelos}", file=sys.stderr)
        return 1
    sha = sha256_archivo(carpeta / MANIFIESTO)
    verificar(carpeta, sha)                       # todos los archivos coinciden con el manifiesto
    m = leer_manifiesto(carpeta)
    with c.uow() as uow:
        registrado = uow.modelos.registrar(ModeloRegistrado(
            id=0, tipo=m["tipo"], nombre=m["nombre"], version=m["version"], ruta=str(ruta), sha256=sha,
            dataset=m["dataset"], umbral_medio=m["umbral_medio"], umbral_alto=m["umbral_alto"], activo=args.activar,
            metricas=m.get("metricas", {})), activar=args.activar)
        uow.confirmar()
    print(f"Modelo registrado (#{registrado.id}, {registrado.tipo} {registrado.version})"
          + (" y activado." if args.activar else "."))
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

    v = sub.add_parser("generar-vapid", help="Genera las llaves para las notificaciones push")
    v.add_argument("--contacto", required=True, help="mailto:tu@correo.co o https://tu-sitio.co")
    v.set_defaults(fn=_generar_vapid)

    m = sub.add_parser("modelos", help="Registro de modelos de ML")
    msub = m.add_subparsers(dest="accion", required=True)
    msub.add_parser("listar", help="Lista los modelos registrados")
    r = msub.add_parser("registrar", help="Registra la versión de una carpeta con manifest.json")
    r.add_argument("carpeta")
    r.add_argument("--activar", action="store_true", help="la deja como versión activa de su tipo")
    m.set_defaults(fn=_modelos)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
