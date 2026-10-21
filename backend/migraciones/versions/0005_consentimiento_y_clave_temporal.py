"""Ley 1581 de 2012 y recuperación de acceso.

* usuario.consentimiento_version / consentimiento_en: qué versión de la Política de tratamiento de datos aceptó la
  persona al registrarse y cuándo (prueba de la autorización, art. 9 de la Ley 1581 y Decreto 1377 de 2013).
* usuario.debe_cambiar_clave: el administrador le asignó una contraseña temporal; al entrar debe cambiarla antes de
  poder usar el panel.

Revisión: 0005
Anterior: 0004
Fecha: 2026-10-20
"""
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE centinela.usuario
            ADD COLUMN consentimiento_version text CHECK (length(consentimiento_version) <= 40),
            ADD COLUMN consentimiento_en      timestamptz,
            ADD COLUMN debe_cambiar_clave     boolean NOT NULL DEFAULT false,
            ADD CONSTRAINT usuario_consentimiento_completo
                CHECK ((consentimiento_version IS NULL) = (consentimiento_en IS NULL))""")


def downgrade() -> None:
    op.execute("""
        ALTER TABLE centinela.usuario
            DROP CONSTRAINT usuario_consentimiento_completo,
            DROP COLUMN consentimiento_version,
            DROP COLUMN consentimiento_en,
            DROP COLUMN debe_cambiar_clave""")
