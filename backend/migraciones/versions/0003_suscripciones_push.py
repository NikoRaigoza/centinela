"""Suscripciones a notificaciones push (Web Push) de cada dispositivo del usuario.

Cada navegador donde la persona activa los avisos crea una suscripción: una dirección del servicio push del
navegador (Google, Mozilla, Apple, Microsoft) y dos llaves públicas para cifrar el aviso de punta a punta.
Las suscripciones quedan ligadas a la llave VAPID del servidor: con solo leer esta tabla no se pueden enviar avisos.

Revisión: 0003
Anterior: 0002
Fecha: 2026-10-19
"""
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE centinela.suscripcion_push (
            id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            usuario_id       bigint      NOT NULL REFERENCES centinela.usuario (id) ON DELETE CASCADE,
            endpoint         text        NOT NULL CHECK (endpoint LIKE 'https://%' AND length(endpoint) <= 1024),
            p256dh           text        NOT NULL CHECK (length(p256dh) BETWEEN 80 AND 100),  -- punto P-256 (65 bytes)
            auth             text        NOT NULL CHECK (length(auth) BETWEEN 16 AND 32),     -- secreto de 16 bytes
            dispositivo      text        CHECK (length(dispositivo) <= 80),                    -- «Chrome en Windows»
            creado_en        timestamptz NOT NULL DEFAULT now(),
            ultimo_envio_en  timestamptz,
            CONSTRAINT suscripcion_endpoint_unico UNIQUE (endpoint)
        )""")
    op.execute("CREATE INDEX suscripcion_usuario_idx ON centinela.suscripcion_push (usuario_id)")


def downgrade() -> None:
    op.execute("DROP TABLE centinela.suscripcion_push")
