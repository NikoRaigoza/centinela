#!/usr/bin/env bash
# Demo en este Mac: API + worker contra la base real y, con --tunel, una URL https pública (Cloudflare Quick Tunnel)
# para abrir el panel y recibir notificaciones push en celulares. Ctrl+C detiene todo.
#
#   despliegue/demo_local.sh            # solo en este computador: http://localhost:8000
#   despliegue/demo_local.sh --tunel    # además imprime la URL https://….trycloudflare.com
#
# La URL del túnel cambia cada vez que se arranca: inícialo una vez antes de la presentación y no lo reinicies
# (en un iPhone la app instalada en la pantalla de inicio queda ligada a esa URL). HTTP/2 (TCP) y no QUIC (UDP):
# muchas redes universitarias bloquean UDP y, tras una suspensión, QUIC no logra reconectarse.
# Gmail se conecta desde este Mac (http://localhost:8000): el redirect de OAuth está registrado para localhost.
set -euo pipefail
cd "$(dirname "$0")/../backend"

pids=()
terminar() { kill "${pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true; }
trap terminar EXIT INT TERM

uv run centinela verificar-config >/dev/null 2>&1 || true
# --proxy: el túnel entrega la IP real en X-Forwarded-For; seguro porque la API solo escucha en 127.0.0.1.
uv run centinela api --proxy & pids+=($!)
uv run centinela worker & pids+=($!)

if [[ "${1:-}" == "--tunel" ]]; then
  registro=$(mktemp -t centinela-tunel)
  cloudflared tunnel --no-autoupdate --protocol http2 --url http://localhost:8000 >"$registro" 2>&1 & pids+=($!)
  for _ in $(seq 60); do
    url=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$registro" | head -1 || true)
    [[ -n "$url" ]] && break
    sleep 1
  done
  echo
  echo "Panel en este Mac:      http://localhost:8000"
  echo "Panel para celulares:   ${url:-(no se obtuvo la URL; revisa $registro)}"
  echo
fi
wait
