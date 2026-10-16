"""Entorno de Alembic. Usa el rol dueño del esquema (CENTINELA_BD_URL_MIGRACIONES)."""
from alembic import context
from sqlalchemy import create_engine, pool

from centinela.adaptadores.salida.postgres.tablas import ESQUEMA, Base
from centinela.config import ConfiguracionMigraciones

config = context.config
url = config.attributes.get("url") or ConfiguracionMigraciones().bd_url_migraciones


def incluir(objeto, nombre, tipo, reflejado, comparado) -> bool:
    if tipo == "schema":
        return nombre == ESQUEMA
    return True


def ejecutar() -> None:
    motor = create_engine(url, poolclass=pool.NullPool)
    with motor.connect() as conexion:
        context.configure(connection=conexion, target_metadata=Base.metadata, include_schemas=True,
                          include_name=incluir, version_table_schema="public", compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


ejecutar()
