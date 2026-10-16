"""Raíz de composición: el único lugar donde se conectan los puertos con sus adaptadores concretos."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

import httpx
from sqlalchemy import Engine

from centinela.adaptadores.entrada.api.tokens import EmisorTokens
from centinela.adaptadores.salida.avisos import RedactorAvisosMime
from centinela.adaptadores.salida.gmail import AutorizacionGoogle, ProveedorGmail
from centinela.adaptadores.salida.lector_correo import LectorCorreoMime
from centinela.adaptadores.salida.ml.registro import ProveedorModelosRegistrados
from centinela.adaptadores.salida.postgres.uow import FabricaUnidadDeTrabajoSql, crear_motor
from centinela.adaptadores.salida.seguridad import CifradorFernet, HasherArgon2, RelojSistema, ServicioTotpPyotp
from centinela.aplicacion.casos_uso import acceso, analisis, buzones, casos
from centinela.aplicacion.puertos import (
    AutorizacionCorreo,
    Cifrador,
    FabricaUnidadDeTrabajo,
    LectorCorreo,
    ProveedorCorreo,
    ProveedorModelos,
    Reloj,
)
from centinela.config import Configuracion, obtener_configuracion


@dataclass
class Contenedor:
    config: Configuracion
    motor: Engine
    uow: FabricaUnidadDeTrabajo
    reloj: Reloj
    cifrador: Cifrador
    tokens: EmisorTokens
    # acceso
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
    # buzones
    iniciar_conexion_gmail: buzones.IniciarConexionGmail
    completar_conexion_gmail: buzones.CompletarConexionGmail
    desconectar_buzon: buzones.DesconectarBuzon
    listar_buzones: buzones.ListarBuzones
    listar_todos_los_buzones: buzones.ListarTodosLosBuzones
    actualizar_buzon: buzones.ActualizarBuzon
    listar_mensajes: buzones.ListarMensajes
    revisar_buzon: buzones.RevisarBuzon
    revisar_pendientes: buzones.RevisarBuzonesPendientes
    # análisis y casos
    lector: LectorCorreo
    modelos: ProveedorModelos
    analizar_manual: analisis.AnalizarCorreoManual
    listar_casos: casos.ListarCasos
    ver_caso: casos.VerCaso
    liberar_correo: casos.LiberarCorreo
    clasificar_caso: casos.ClasificarCaso
    nota_caso: casos.AgregarNotaCaso
    enviar_avisos: casos.EnviarAvisosPendientes


def clave_avisos(llave_cifrado: str) -> bytes:
    """Llave HMAC para firmar los avisos de Centinela, derivada de la llave de cifrado."""
    return hashlib.sha256(b"centinela-avisos:" + llave_cifrado.encode()).digest()


def construir(config: Configuracion | None = None, autorizacion: AutorizacionCorreo | None = None,
              proveedor: ProveedorCorreo | None = None) -> Contenedor:
    """`autorizacion` y `proveedor` se pueden inyectar (pruebas); si no, se usan los de Google si están configurados."""
    config = config or obtener_configuracion()
    motor = crear_motor(config.bd_url)
    uow = FabricaUnidadDeTrabajoSql(motor)
    reloj = RelojSistema()
    hasher = HasherArgon2()
    llave = config.llave_cifrado.get_secret_value()
    cifrador = CifradorFernet(llave)
    totp = ServicioTotpPyotp()
    if config.gmail_configurado and (autorizacion is None or proveedor is None):
        http = httpx.Client(timeout=httpx.Timeout(20.0, connect=10.0))
        secreto = config.gmail_client_secret.get_secret_value()
        autorizacion = autorizacion or AutorizacionGoogle(config.gmail_client_id, secreto, config.gmail_redirect_uri, http)
        proveedor = proveedor or ProveedorGmail(config.gmail_client_id, secreto, http, reloj)
    lector = LectorCorreoMime(clave_avisos(llave))
    modelos = ProveedorModelosRegistrados(uow, config.dir_modelos)
    motor_analisis = analisis.MotorAnalisis(modelos)
    revisar = buzones.RevisarBuzon(uow, reloj, proveedor, lector, cifrador, motor_analisis)
    return Contenedor(
        config=config, motor=motor, uow=uow, reloj=reloj, cifrador=cifrador,
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
        iniciar_conexion_gmail=buzones.IniciarConexionGmail(uow, reloj, autorizacion),
        completar_conexion_gmail=buzones.CompletarConexionGmail(uow, reloj, autorizacion, proveedor, cifrador),
        desconectar_buzon=buzones.DesconectarBuzon(uow, reloj, autorizacion, cifrador),
        listar_buzones=buzones.ListarBuzones(uow, reloj),
        listar_todos_los_buzones=buzones.ListarTodosLosBuzones(uow, reloj),
        actualizar_buzon=buzones.ActualizarBuzon(uow, reloj),
        listar_mensajes=buzones.ListarMensajes(uow, reloj),
        revisar_buzon=revisar,
        revisar_pendientes=buzones.RevisarBuzonesPendientes(uow, reloj, revisar),
        lector=lector, modelos=modelos,
        analizar_manual=analisis.AnalizarCorreoManual(uow, reloj, lector, motor_analisis),
        listar_casos=casos.ListarCasos(uow, reloj),
        ver_caso=casos.VerCaso(uow, reloj),
        liberar_correo=casos.LiberarCorreo(uow, reloj, proveedor, cifrador),
        clasificar_caso=casos.ClasificarCaso(uow, reloj),
        nota_caso=casos.AgregarNotaCaso(uow, reloj),
        enviar_avisos=casos.EnviarAvisosPendientes(uow, reloj, proveedor, cifrador,
                                                   RedactorAvisosMime(clave_avisos(llave), config.url_panel)),
    )
