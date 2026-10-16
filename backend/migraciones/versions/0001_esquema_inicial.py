"""Esquema inicial: 20 tablas, tipos, índices, triggers, vistas y datos iniciales.

Revisión: 0001
Anterior: ninguna
Fecha: 2026-10-16
"""
from pathlib import Path

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

SQL = Path(__file__).with_name("0001_esquema_inicial.sql").read_text(encoding="utf-8")


def upgrade() -> None:
    # El SQL trae funciones con ';' internos: se ejecuta completo con el driver (sin parámetros).
    op.get_bind().connection.driver_connection.execute(SQL)


def downgrade() -> None:
    op.execute("DROP SCHEMA centinela CASCADE")
