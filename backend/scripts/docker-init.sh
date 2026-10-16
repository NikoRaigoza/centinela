#!/bin/sh
# Lo ejecuta el contenedor de PostgreSQL la PRIMERA vez que arranca (volumen vacío).
set -e
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres \
     -v clave_owner="$CENTINELA_CLAVE_OWNER" -v clave_app="$CENTINELA_CLAVE_APP" \
     -f /scripts/crear_bd.sql
