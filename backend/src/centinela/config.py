"""Configuración por variables de entorno (prefijo CENTINELA_). Nunca se escriben secretos en el código."""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

_TEMA_PUBSUB = re.compile(r"^projects/[a-z][-a-z0-9]{4,28}[a-z0-9]/topics/[A-Za-z][-A-Za-z0-9_.~+%]{2,254}$")


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

    # Gmail (OAuth2). Se crean en Google Cloud Console > APIs y servicios > Credenciales (aplicación web).
    gmail_client_id: str | None = None
    gmail_client_secret: SecretStr | None = None
    gmail_redirect_uri: str = "http://localhost:8000/api/gmail/callback"
    url_panel: str = "http://localhost:5173"

    # Avisos de Gmail en tiempo real (Google Cloud Pub/Sub). Sin esto, el worker revisa cada buzón cada 30 s.
    # Pasos en backend/README.md («Gmail en tiempo real»). Requiere que la API sea accesible por HTTPS desde internet.
    pubsub_tema: str | None = None               # projects/<proyecto>/topics/<tema>
    pubsub_audiencia: str | None = None          # audiencia del token en la suscripción push (p. ej. la URL del endpoint)
    pubsub_cuenta_servicio: str | None = None    # cuenta de servicio con la que Pub/Sub firma cada entrega

    # Asistente de IA (Google Gemini). Sin clave, el asistente responde en modo local con reglas.
    # La clave se crea en https://aistudio.google.com/apikey
    gemini_clave: SecretStr | None = None
    gemini_modelo: str = "gemini-flash-latest"

    # Notificaciones push (Web Push + VAPID). Las llaves se generan con: uv run centinela generar-vapid
    vapid_clave_privada: SecretStr | None = None
    vapid_contacto: str | None = None          # mailto:... o https://...: los servicios push lo usan si hay abuso

    # Carpeta de los modelos de ML registrados (ver adaptadores/salida/ml/registro.py)
    dir_modelos: Path = Path(__file__).resolve().parents[2] / "modelos"

    # Panel React compilado (frontend/dist). Si existe, la API también lo sirve: un solo proceso en producción.
    dir_panel: Path | None = Path(__file__).resolve().parents[3] / "frontend" / "dist"

    minutos_token_acceso: int = 15
    minutos_desafio_2fa: int = 5
    origenes_cors: list[str] = ["http://localhost:5173"]

    @property
    def cookies_seguras(self) -> bool:
        return self.entorno == "produccion"

    @property
    def gmail_configurado(self) -> bool:
        return bool(self.gmail_client_id and self.gmail_client_secret)

    @property
    def push_configurado(self) -> bool:
        return bool(self.vapid_clave_privada and self.vapid_clave_privada.get_secret_value() and self.vapid_contacto)

    @property
    def tiempo_real_configurado(self) -> bool:
        return bool(self.gmail_configurado and self.pubsub_tema and _TEMA_PUBSUB.match(self.pubsub_tema)
                    and self.pubsub_audiencia and self.pubsub_cuenta_servicio)

    @property
    def ia_configurada(self) -> bool:
        return bool(self.gemini_clave and self.gemini_clave.get_secret_value())


class ConfiguracionMigraciones(BaseSettings):
    """Lo único que necesita Alembic: no exige los secretos de la aplicación."""
    model_config = SettingsConfigDict(env_prefix="CENTINELA_", env_file=(".env", "../.env"), extra="ignore")
    bd_url_migraciones: str = Configuracion.model_fields["bd_url_migraciones"].default


@lru_cache
def obtener_configuracion() -> Configuracion:
    return Configuracion()
