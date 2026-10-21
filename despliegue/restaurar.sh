#!/bin/sh
# Restaura un respaldo cifrado. Por defecto en una base APARTE (centinela_restaurada) para comprobar que el respaldo
# sirve sin tocar la de producción:
#   docker compose -f docker-compose.prod.yml exec respaldo sh /scripts/restaurar.sh centinela-AAAAMMDDTHHMMSSZ.dump.enc
# Para reemplazar la base de producción (desastre): detén api y worker y agrega «--produccion» al final.
set -eu
ARCHIVO="/respaldos/${1:?Indica el archivo: centinela-....dump.enc}"
DESTINO=centinela_restaurada
[ "${2:-}" = "--produccion" ] && DESTINO=centinela
[ -f "$ARCHIVO" ] || { echo "No existe $ARCHIVO" >&2; exit 1; }
export PGPASSWORD="$POSTGRES_PASSWORD"          # superusuario: crear o vaciar la base de destino

if [ "$DESTINO" = "centinela" ]; then
    echo "Reemplazando la base de PRODUCCIÓN con $(basename "$ARCHIVO")..."
    psql -h bd -U postgres -d postgres -v ON_ERROR_STOP=1 \
        -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'centinela' AND pid <> pg_backend_pid()" \
        -c "DROP DATABASE centinela" -c "CREATE DATABASE centinela OWNER centinela_owner TEMPLATE template0" \
        -c "REVOKE ALL ON DATABASE centinela FROM PUBLIC" -c "GRANT CONNECT ON DATABASE centinela TO centinela_owner, centinela_app"
else
    psql -h bd -U postgres -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS $DESTINO" \
        -c "CREATE DATABASE $DESTINO OWNER centinela_owner TEMPLATE template0"
fi
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:CENTINELA_CLAVE_RESPALDOS -in "$ARCHIVO" \
    | pg_restore -h bd -U postgres -d "$DESTINO" --exit-on-error
psql -h bd -U postgres -d "$DESTINO" -At -c \
    "SELECT 'Restaurado en $DESTINO: ' || (SELECT count(*) FROM centinela.usuario) || ' usuarios, ' ||
            (SELECT count(*) FROM centinela.mensaje_analizado) || ' correos analizados, ' ||
            (SELECT count(*) FROM centinela.caso) || ' casos, migración ' || (SELECT version_num FROM public.alembic_version)"
