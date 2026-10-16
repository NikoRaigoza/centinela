"""Pruebas de integración: usan la base REAL `centinela_pruebas` (nunca la de desarrollo)."""
from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import create_engine, text

from centinela.config import Configuracion

RAIZ = Path(__file__).resolve().parents[2]


class ConfigPruebas(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CENTINELA_", env_file=RAIZ / ".env", extra="ignore")
    bd_url_pruebas: str | None = None
    bd_url_pruebas_migraciones: str | None = None
    jwt_secreto: str = "secreto-de-pruebas-" + "x" * 32
    llave_cifrado: str = "q1oJ7mFsZ0F5n2Qk4vHq8cX6b9Wl3tYz-uDx0rPaEiM="


CP = ConfigPruebas()
pytestmark = pytest.mark.integracion


def _alembic(url: str) -> Config:
    cfg = Config(str(RAIZ / "alembic.ini"))
    cfg.attributes["url"] = url
    return cfg


@pytest.fixture(scope="session")
def url_owner() -> str:
    if not CP.bd_url_pruebas_migraciones or "pruebas" not in CP.bd_url_pruebas_migraciones:
        pytest.skip("Configura CENTINELA_BD_URL_PRUEBAS_MIGRACIONES apuntando a una base *_pruebas")
    return CP.bd_url_pruebas_migraciones


@pytest.fixture(scope="session")
def bd_migrada(url_owner):
    """Prueba la migración de ida y vuelta y deja el esquema listo."""
    cfg = _alembic(url_owner)
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    return url_owner


@pytest.fixture
def motor_owner(bd_migrada):
    motor = create_engine(bd_migrada)
    yield motor
    motor.dispose()


@pytest.fixture
def limpiar(motor_owner):
    """Deja las tablas de datos vacías (conserva catálogo y configuración iniciales)."""
    with motor_owner.begin() as c:
        c.execute(text("TRUNCATE centinela.usuario, centinela.auditoria RESTART IDENTITY CASCADE"))
    yield


@pytest.fixture
def config(bd_migrada) -> Configuracion:
    return Configuracion(entorno="pruebas", bd_url=CP.bd_url_pruebas, bd_url_migraciones=bd_migrada,
                         jwt_secreto=CP.jwt_secreto, llave_cifrado=CP.llave_cifrado)
