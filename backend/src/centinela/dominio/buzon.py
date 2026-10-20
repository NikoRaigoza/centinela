"""Buzón de Gmail conectado: estado de la conexión, avance de la lectura y política de cuarentena."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from centinela.dominio.errores import AccesoDenegado, TransicionInvalida

MAX_ERRORES_CONSECUTIVOS = 5


class EstadoBuzon(StrEnum):
    ACTIVO = "activo"
    PAUSADO = "pausado"
    REVOCADO = "revocado"
    ERROR = "error"


class ModoCuarentena(StrEnum):
    SOLO_AVISAR = "solo_avisar"
    CUARENTENA_AUTOMATICA = "cuarentena_automatica"


@dataclass(frozen=True)
class EtiquetasCentinela:
    cuarentena_id: str
    sospechoso_id: str


@dataclass
class Buzon:
    usuario_id: int
    correo_gmail: str
    refresh_token_cifrado: bytes | None
    conectado_en: datetime
    alcances: list[str] = field(default_factory=list)
    estado: EstadoBuzon = EstadoBuzon.ACTIVO
    modo: ModoCuarentena = ModoCuarentena.CUARENTENA_AUTOMATICA
    avisar_por_correo: bool = True
    ultimo_history_id: int | None = None
    etiqueta_cuarentena_id: str | None = None
    etiqueta_sospechoso_id: str | None = None
    ultima_revision_en: datetime | None = None
    errores_consecutivos: int = 0
    ultimo_error: str | None = None
    desconectado_en: datetime | None = None
    vigilancia_expira_en: datetime | None = None    # hasta cuándo Gmail avisa en tiempo real de los correos nuevos
    id: int | None = None

    @classmethod
    def conectar(cls, usuario_id: int, correo_gmail: str, token_cifrado: bytes, alcances: list[str],
                 history_id: int, etiquetas: EtiquetasCentinela, ahora: datetime) -> Buzon:
        """Se empieza a vigilar DESDE AHORA: los correos anteriores a la conexión no se analizan."""
        b = cls(usuario_id=usuario_id, correo_gmail=correo_gmail.lower(), refresh_token_cifrado=None, conectado_en=ahora)
        b.reconectar(token_cifrado, alcances, history_id, etiquetas, ahora)
        return b

    def reconectar(self, token_cifrado: bytes, alcances: list[str], history_id: int,
                   etiquetas: EtiquetasCentinela, ahora: datetime) -> None:
        self.refresh_token_cifrado = token_cifrado
        self.alcances = list(alcances)
        self.ultimo_history_id = history_id
        self.etiqueta_cuarentena_id = etiquetas.cuarentena_id
        self.etiqueta_sospechoso_id = etiquetas.sospechoso_id
        self.estado = EstadoBuzon.ACTIVO
        self.errores_consecutivos, self.ultimo_error = 0, None
        self.conectado_en, self.desconectado_en = ahora, None
        self.vigilancia_expira_en = None          # el worker vuelve a pedir los avisos en tiempo real

    # ------------------------------------------------------------------ consultas
    @property
    def revisable(self) -> bool:
        return self.estado is EstadoBuzon.ACTIVO and self.refresh_token_cifrado is not None

    def en_tiempo_real(self, ahora: datetime) -> bool:
        return self.revisable and self.vigilancia_expira_en is not None and self.vigilancia_expira_en > ahora

    def verificar_dueno(self, usuario_id: int) -> None:
        if self.usuario_id != usuario_id:
            raise AccesoDenegado("Este buzón no es tuyo.")

    # ------------------------------------------------------------------ cambios por el dueño
    def pausar(self) -> None:
        if self.estado is not EstadoBuzon.ACTIVO:
            raise TransicionInvalida("Solo se puede pausar un buzón activo.")
        self.estado = EstadoBuzon.PAUSADO

    def reanudar(self) -> None:
        if self.estado not in (EstadoBuzon.PAUSADO, EstadoBuzon.ERROR) or self.refresh_token_cifrado is None:
            raise TransicionInvalida("Este buzón no se puede reanudar. Vuelve a conectarlo.")
        self.estado = EstadoBuzon.ACTIVO
        self.errores_consecutivos, self.ultimo_error = 0, None

    def desconectar(self, ahora: datetime) -> None:
        self.refresh_token_cifrado = None
        self.estado = EstadoBuzon.REVOCADO
        self.desconectado_en = ahora
        self.vigilancia_expira_en = None

    def registrar_vigilancia(self, expira_en: datetime | None) -> None:
        """Gmail confirmó (o dejó de confirmar, con None) que avisará de los correos nuevos hasta esa fecha."""
        self.vigilancia_expira_en = expira_en

    # ------------------------------------------------------------------ resultado de cada revisión
    def registrar_revision(self, history_id: int, ahora: datetime) -> None:
        self.ultimo_history_id = history_id
        self.ultima_revision_en = ahora
        self.errores_consecutivos, self.ultimo_error = 0, None

    def registrar_error(self, mensaje: str, ahora: datetime) -> None:
        """Errores pasajeros (red, cuotas): tras varios seguidos el buzón queda en ERROR y se avisa al dueño."""
        self.errores_consecutivos += 1
        self.ultimo_error = mensaje[:500]
        self.ultima_revision_en = ahora
        if self.errores_consecutivos >= MAX_ERRORES_CONSECUTIVOS:
            self.estado = EstadoBuzon.ERROR

    def marcar_acceso_revocado(self, ahora: datetime) -> None:
        """Google ya no acepta el permiso (el usuario lo quitó o cambió su contraseña)."""
        self.desconectar(ahora)
        self.ultimo_error = "Google retiró el permiso de Centinela. Vuelve a conectar el buzón."
