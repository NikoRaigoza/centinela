"""Raíz de composición: el único lugar donde se conectan los puertos con sus adaptadores concretos."""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Engine

from centinela.adaptadores.entrada.api.tokens import EmisorTokens
from centinela.adaptadores.salida.postgres.uow import FabricaUnidadDeTrabajoSql, crear_motor
from centinela.adaptadores.salida.seguridad import CifradorFernet, HasherArgon2, RelojSistema, ServicioTotpPyotp
from centinela.aplicacion.casos_uso import acceso
from centinela.aplicacion.puertos import FabricaUnidadDeTrabajo, Reloj
from centinela.config import Configuracion, obtener_configuracion


@dataclass
class Contenedor:
    config: Configuracion
    motor: Engine
    uow: FabricaUnidadDeTrabajo
    reloj: Reloj
    tokens: EmisorTokens
    solicitar_registro: acceso.SolicitarRegistro
    crear_administrador: acceso.CrearAdministrador
    iniciar_sesion: acceso.IniciarSesion
    verificar_2fa: acceso.VerificarSegundoFactor
    iniciar_config_2fa: acceso.IniciarConfiguracion2FA
    confirmar_config_2fa: acceso.ConfirmarConfiguracion2FA
    renovar_sesion: acceso.RenovarSesion
    cerrar_sesion: acceso.CerrarSesion
    obtener_usuario: acceso.ObtenerUsuario
    cambiar_clave: acceso.CambiarClave
    listar_usuarios: acceso.ListarUsuarios
    cambiar_estado_cuenta: acceso.CambiarEstadoCuenta


def construir(config: Configuracion | None = None) -> Contenedor:
    config = config or obtener_configuracion()
    motor = crear_motor(config.bd_url)
    uow = FabricaUnidadDeTrabajoSql(motor)
    reloj = RelojSistema()
    hasher = HasherArgon2()
    cifrador = CifradorFernet(config.llave_cifrado.get_secret_value())
    totp = ServicioTotpPyotp()
    return Contenedor(
        config=config, motor=motor, uow=uow, reloj=reloj,
        tokens=EmisorTokens(config.jwt_secreto.get_secret_value(), config.minutos_token_acceso,
                            config.minutos_desafio_2fa, reloj),
        solicitar_registro=acceso.SolicitarRegistro(uow, reloj, hasher),
        crear_administrador=acceso.CrearAdministrador(uow, reloj, hasher),
        iniciar_sesion=acceso.IniciarSesion(uow, reloj, hasher),
        verificar_2fa=acceso.VerificarSegundoFactor(uow, reloj, totp, cifrador),
        iniciar_config_2fa=acceso.IniciarConfiguracion2FA(uow, reloj, totp, cifrador),
        confirmar_config_2fa=acceso.ConfirmarConfiguracion2FA(uow, reloj, totp, cifrador),
        renovar_sesion=acceso.RenovarSesion(uow, reloj),
        cerrar_sesion=acceso.CerrarSesion(uow, reloj),
        obtener_usuario=acceso.ObtenerUsuario(uow, reloj),
        cambiar_clave=acceso.CambiarClave(uow, reloj, hasher),
        listar_usuarios=acceso.ListarUsuarios(uow, reloj),
        cambiar_estado_cuenta=acceso.CambiarEstadoCuenta(uow, reloj),
    )
