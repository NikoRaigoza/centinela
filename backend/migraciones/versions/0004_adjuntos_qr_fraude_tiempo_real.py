"""Adjuntos y códigos QR, fraude sin enlaces y avisos de Gmail en tiempo real.

* area_razon gana el valor 'fraude': razones del detector de fraudes sin enlaces (suplantación de un jefe o
  proveedor, tarjetas de regalo, cambio de cuenta bancaria, extorsión).
* enlace_analizado.origen: de dónde salió el enlace (cuerpo del correo, código QR de una imagen o un adjunto).
* buzon.vigilancia_expira_en: hasta cuándo Gmail avisa a Centinela de los correos nuevos (users.watch, ~7 días).
* buzon.revision_solicitada_en: Gmail avisó que llegó algo; el worker lo revisa de inmediato y borra la marca.
* Índice (buzon_id, remitente_correo): saber rápido si un remitente ya había escrito antes a un buzón.
* configuracion 'analisis.intervalo_respaldo_s': con avisos en tiempo real, cada cuánto se revisa igual por si un
  aviso de Gmail se perdió.

Revisión: 0004
Anterior: 0003
Fecha: 2026-10-20
"""
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE centinela.area_razon ADD VALUE IF NOT EXISTS 'fraude'")
    op.execute("""
        ALTER TABLE centinela.enlace_analizado
            ADD COLUMN origen text NOT NULL DEFAULT 'cuerpo'
                CONSTRAINT enlace_origen_valido CHECK (origen IN ('cuerpo', 'qr', 'adjunto'))""")
    op.execute("""
        ALTER TABLE centinela.buzon
            ADD COLUMN vigilancia_expira_en   timestamptz,
            ADD COLUMN revision_solicitada_en timestamptz""")
    op.execute("CREATE INDEX mensaje_buzon_remitente_idx ON centinela.mensaje_analizado (buzon_id, remitente_correo)")
    op.execute("""
        INSERT INTO centinela.configuracion (clave, valor, descripcion) VALUES
            ('analisis.intervalo_respaldo_s', '300',
             'Con avisos de Gmail en tiempo real: segundos entre revisiones de respaldo de cada buzón')
        ON CONFLICT (clave) DO NOTHING""")


def downgrade() -> None:
    op.execute("DELETE FROM centinela.configuracion WHERE clave = 'analisis.intervalo_respaldo_s'")
    op.execute("DROP INDEX centinela.mensaje_buzon_remitente_idx")
    op.execute("ALTER TABLE centinela.buzon DROP COLUMN vigilancia_expira_en, DROP COLUMN revision_solicitada_en")
    op.execute("ALTER TABLE centinela.enlace_analizado DROP COLUMN origen")
    # PostgreSQL no permite quitar un valor de un enum (y una vista depende de razon.area): el valor 'fraude' se
    # queda en el tipo, sin uso. Volver a subir a 0004 no falla gracias al IF NOT EXISTS.
    op.execute("DELETE FROM centinela.razon WHERE area = 'fraude'")
