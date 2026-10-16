"""Configuración por variables de entorno (prefijo CENTINELA_). Nunca se escriben secretos en el código."""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Configuracion(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CENTINELA_", env_file=(".env", "../.env"), extra="ignore")

    entorno: Literal["desarrollo", "pruebas", "produccion"] = "desarrollo"

    # Base de datos: la app usa un rol con permisos mínimos; las migraciones, el dueño del esquema
    bd_url: str = "postgresql+psycopg://centinela_app:centinela_app@localhost:5432/centinela"
    bd_url_migraciones: str = "postgresql+psycopg://centinela_owner:centinela_owner@localhost:5432/centinela"

    # Secretos (obligatorios: sin valor por defecto)
    jwt_secreto: SecretStr = Field(min_length=32)
    # Llave Fernet. Se genera con:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    llave_cifrado: SecretStr

    minutos_token_acceso: int = 15
    minutos_desafio_2fa: int = 5
    origenes_cors: list[str] = ["http://localhost:5173"]

    @property
    def cookies_seguras(self) -> bool:
        return self.entorno == "produccion"


class ConfiguracionMigraciones(BaseSettings):
    """Lo único que necesita Alembic: no exige los secretos de la aplicación."""
    model_config = SettingsConfigDict(env_prefix="CENTINELA_", env_file=(".env", "../.env"), extra="ignore")
    bd_url_migraciones: str = Configuracion.model_fields["bd_url_migraciones"].default


@lru_cache
def obtener_configuracion() -> Configuracion:
    return Configuracion()
