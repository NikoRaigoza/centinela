"""La base de datos real: migración, sincronía con el código, permisos y restricciones."""
import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from centinela.adaptadores.salida.postgres.tablas import ESQUEMA, Base
from tests.integracion.conftest import CP

pytestmark = pytest.mark.integracion


def test_esquema_sincronizado_con_el_codigo(motor_owner):
    """Las clases SQLAlchemy coinciden con lo que creó la migración (tablas, columnas, tipos, índices, llaves)."""
    with motor_owner.connect() as c:
        ctx = MigrationContext.configure(c, opts={
            "include_schemas": True, "compare_type": True,
            "include_name": lambda nombre, tipo, _p: tipo != "schema" or nombre == ESQUEMA})
        diferencias = compare_metadata(ctx, Base.metadata)
    assert diferencias == []


def test_contenido_inicial(motor_owner):
    with motor_owner.connect() as c:
        tablas = c.scalar(text("SELECT count(*) FROM information_schema.tables "
                               "WHERE table_schema='centinela' AND table_type='BASE TABLE'"))
        vistas = c.scalar(text("SELECT count(*) FROM information_schema.views WHERE table_schema='centinela'"))
        dominio = c.scalar(text("SELECT e.nombre FROM centinela.dominio_oficial d "
                                "JOIN centinela.entidad_suplantada e ON e.id = d.entidad_id WHERE d.dominio='dian.gov.co'"))
    assert (tablas, vistas, dominio) == (21, 3, "DIAN")


def test_rol_de_la_app_tiene_permisos_minimos(bd_migrada, limpiar):
    app = create_engine(CP.bd_url_pruebas)
    with app.begin() as c:
        c.execute(text("INSERT INTO centinela.auditoria (accion) VALUES ('prueba')"))
    for sql in ("UPDATE centinela.auditoria SET accion = 'x'",          # bitácora inmutable
                "DELETE FROM centinela.auditoria",
                "CREATE TABLE centinela.intrusa (id int)",            # no puede cambiar el esquema
                "DROP TABLE centinela.usuario"):
        with pytest.raises(DBAPIError), app.begin() as c:
            c.execute(text(sql))
    app.dispose()


def test_restricciones_de_integridad(motor_owner, limpiar):
    with motor_owner.begin() as c:
        c.execute(text("INSERT INTO centinela.usuario (correo, nombre, clave_hash) VALUES ('a@b.co', 'Ana', 'x')"))
    casos = [
        "INSERT INTO centinela.usuario (correo, nombre, clave_hash) VALUES ('a@b.co', 'Otra', 'x')",
        "INSERT INTO centinela.usuario (correo, nombre, clave_hash) VALUES ('A@B.CO', 'Ana', 'x')",
        "INSERT INTO centinela.usuario (correo, nombre, clave_hash, totp_activo) VALUES ('c@b.co', 'Ana', 'x', true)",
        "INSERT INTO centinela.buzon (usuario_id, correo_gmail) "
        "VALUES ((SELECT id FROM centinela.usuario LIMIT 1), 'a@gmail.com')",
    ]
    for sql in casos:
        with pytest.raises(IntegrityError), motor_owner.begin() as c:
            c.execute(text(sql))
