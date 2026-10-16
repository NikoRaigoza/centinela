"""Sesión del panel: se identifica con un token de renovación del que solo se guarda el hash."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass
class Sesion:
    usuario_id: int
    token_hash: bytes
    creada_en: datetime
    expira_en: datetime
    ip: str | None = None
    agente: str | None = None
    revocada_en: datetime | None = None
    id: UUID | None = None

    def vigente(self, ahora: datetime) -> bool:
        return self.revocada_en is None and self.expira_en > ahora

    def revocar(self, ahora: datetime) -> None:
        if self.revocada_en is None:
            self.revocada_en = ahora
