#!/bin/sh
# Respaldo diario de la base de datos (corre dentro del servicio «respaldo» de docker-compose.prod.yml).
#   * pg_dump en formato personalizado (comprimido), cifrado con AES-256 (openssl, clave CENTINELA_CLAVE_RESPALDOS).
#   * Se guarda en ./respaldos del servidor y se conservan los últimos CENTINELA_DIAS_RESPALDO días.
#   * Hace uno al arrancar y luego uno cada día a la hora CENTINELA_HORA_RESPALDO_UTC.
# Para respaldar ya: docker compose -f docker-compose.prod.yml exec respaldo sh /scripts/respaldo.sh --una-vez
set -eu
DIR=/respaldos
DIAS="${CENTINELA_DIAS_RESPALDO:-14}"
HORA="${CENTINELA_HORA_RESPALDO_UTC:-08:00}"
: "${CENTINELA_CLAVE_RESPALDOS:?Falta CENTINELA_CLAVE_RESPALDOS}"

respaldar() {
    fecha=$(date -u +%Y%m%dT%H%M%SZ)
    temporal="$DIR/.centinela-$fecha.dump"
    destino="$DIR/centinela-$fecha.dump.enc"
    pg_dump -h bd -U centinela_owner -d centinela --format=custom --compress=6 --file="$temporal"
    openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass env:CENTINELA_CLAVE_RESPALDOS \
        -in "$temporal" -out "$destino"
    rm -f "$temporal"
    # Verificación: el archivo cifrado se puede abrir y pg_restore reconoce su contenido
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:CENTINELA_CLAVE_RESPALDOS -in "$destino" \
        | pg_restore --list > /dev/null
    find "$DIR" -name 'centinela-*.dump.enc' -mtime +"$DIAS" -delete
    echo "$(date -u +%FT%TZ) respaldo listo: $(basename "$destino") ($(du -h "$destino" | cut -f1))"
}

mkdir -p "$DIR"
if [ "${1:-}" = "--una-vez" ]; then
    respaldar
    exit 0
fi
respaldar || echo "$(date -u +%FT%TZ) ERROR: falló el respaldo inicial" >&2
while true; do
    ahora=$(date -u +%s)
    siguiente=$(date -u -d "$HORA" +%s)
    [ "$siguiente" -le "$ahora" ] && siguiente=$((siguiente + 86400))
    sleep $((siguiente - ahora))
    respaldar || echo "$(date -u +%FT%TZ) ERROR: falló el respaldo" >&2
done
