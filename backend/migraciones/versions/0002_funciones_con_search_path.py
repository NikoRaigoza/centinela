"""Funciones con esquema explícito y search_path fijo.

El trigger que limita a 3 las razones visibles nombraba la tabla `razon` sin esquema: funcionaba solo si la sesión
tenía `centinela` en su search_path. La aplicación se conecta con el search_path por defecto, así que fallaba.
Lo detectaron las pruebas de integración. Además se fija el search_path de todas las funciones del esquema
(buena práctica de seguridad: evita que una sesión las haga usar objetos de otro esquema).

Revisión: 0002
Anterior: 0001
Fecha: 2026-10-16
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE OR REPLACE FUNCTION centinela.validar_max_razones() RETURNS trigger
        LANGUAGE plpgsql SET search_path = centinela, pg_temp AS $$
        BEGIN
            IF NEW.mostrada AND (SELECT count(*) FROM centinela.razon
                                 WHERE veredicto_id = NEW.veredicto_id AND mostrada AND id <> NEW.id) >= 3 THEN
                RAISE EXCEPTION 'Un veredicto no puede mostrar más de 3 razones (veredicto %)', NEW.veredicto_id
                    USING ERRCODE = 'check_violation';
            END IF;
            RETURN NEW;
        END $$""")
    op.execute("ALTER FUNCTION centinela.fijar_actualizado_en() SET search_path = centinela, pg_temp")
    op.execute("ALTER FUNCTION centinela.auditoria_inmutable() SET search_path = centinela, pg_temp")


def downgrade() -> None:
    op.execute("ALTER FUNCTION centinela.fijar_actualizado_en() RESET search_path")
    op.execute("ALTER FUNCTION centinela.auditoria_inmutable() RESET search_path")
    op.execute("ALTER FUNCTION centinela.validar_max_razones() RESET search_path")
