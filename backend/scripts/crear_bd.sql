-- Crea los roles y las bases de datos de Centinela. Se ejecuta UNA vez como superusuario:
--   psql -d postgres -v clave_owner='...' -v clave_app='...' -f scripts/crear_bd.sql
--
--   centinela_owner : dueño del esquema; solo lo usan las migraciones (Alembic).
--   centinela_app   : lo usa la aplicación; solo lee y escribe datos (no puede cambiar el esquema
--                     ni modificar la auditoría).
\set ON_ERROR_STOP on

SELECT format('CREATE ROLE centinela_owner LOGIN PASSWORD %L', :'clave_owner')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'centinela_owner') \gexec
SELECT format('CREATE ROLE centinela_app LOGIN PASSWORD %L', :'clave_app')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'centinela_app') \gexec

SELECT 'CREATE DATABASE centinela OWNER centinela_owner ENCODING ''UTF8'' TEMPLATE template0'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'centinela') \gexec
SELECT 'CREATE DATABASE centinela_pruebas OWNER centinela_owner ENCODING ''UTF8'' TEMPLATE template0'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'centinela_pruebas') \gexec

REVOKE ALL ON DATABASE centinela FROM PUBLIC;
GRANT CONNECT ON DATABASE centinela TO centinela_owner, centinela_app;
REVOKE ALL ON DATABASE centinela_pruebas FROM PUBLIC;
GRANT CONNECT ON DATABASE centinela_pruebas TO centinela_owner, centinela_app;
