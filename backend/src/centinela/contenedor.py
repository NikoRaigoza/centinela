"""Raíz de composición: el único lugar donde se conectan los puertos con sus adaptadores concretos."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

import httpx
from sqlalchemy import Engine

from centinela.adaptadores.entrada.api.tokens import EmisorTokens
from centinela.adaptadores.salida.avisos import RedactorAvisosMime
from centinela.adaptadores.salida.gemini import AsistenteGemini
from centinela.adaptadores.salida.gmail import AutorizacionGoogle, ProveedorGmail
from centinela.adaptadores.salida.inspector_adjuntos import InspectorAdjuntos
from centinela.adaptadores.salida.lector_correo import LectorCorreoMime
from centinela.adaptadores.salida.ml.registro import ProveedorModelosRegistrados
from centinela.adaptadores.salida.postgres.uow import FabricaUnidadDeTrabajoSql, crear_motor
from centinela.adaptadores.salida.pubsub import VerificadorOidcGoogle
from centinela.adaptadores.salida.push import EnviadorWebPush, carga_de_aviso
from centinela.adaptadores.salida.reportes import GeneradorReportes
from centinela.adaptadores.salida.seguridad import CifradorFernet, HasherArgon2, RelojSistema, ServicioTotpPyotp
from centinela.aplicacion.casos_uso import (
    acceso,
    analisis,
    asistente,
    buzones,
    casos,
    notificaciones,
    panel,
    reportes,
    tiempo_real,
)
from centinela.aplicacion.puertos import (
    AutorizacionCorreo,
    Cifrador,
    EnviadorPush,
    FabricaUnidadDeTrabajo,
    LectorCorreo,
    ModeloLenguaje,
    ProveedorCorreo,
    ProveedorModelos,
    Reloj,
    VerificadorAvisosGmail,
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
    # avisos de Gmail en tiempo real
    renovar_vigilancias: tiempo_real.RenovarVigilancias
    recibir_aviso_gmail: tiempo_real.RecibirAvisoGmail
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
    # panel
    resumen_panel: panel.ObtenerResumenPanel
    listar_modelos: panel.ListarModelos
    generar_reporte: reportes.GenerarReporte
    # notificaciones push
    activar_push: notificaciones.ActivarPush
    listar_dispositivos_push: notificaciones.ListarDispositivosPush
    quitar_push: notificaciones.QuitarPush
    probar_push: notificaciones.ProbarPush
    # asistente de IA
    preguntar_asistente: asistente.PreguntarAsistente
    consultar_asistente: asistente.ConsultarAsistente


def clave_avisos(llave_cifrado: str) -> bytes:
    """Llave HMAC para firmar los avisos de Centinela, derivada de la llave de cifrado."""
    return hashlib.sha256(b"centinela-avisos:" + llave_cifrado.encode()).digest()


def construir(config: Configuracion | None = None, autorizacion: AutorizacionCorreo | None = None,
              proveedor: ProveedorCorreo | None = None, enviador_push: EnviadorPush | None = None,
              modelo_ia: ModeloLenguaje | None = None,
              verificador_gmail: VerificadorAvisosGmail | None = None) -> Contenedor:
    """Los servicios externos (Gmail, push, IA) se pueden inyectar en las pruebas; si no, se usan los reales cuando
    están configurados."""
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
    if config.push_configurado and enviador_push is None:
        enviador_push = EnviadorWebPush(config.vapid_clave_privada.get_secret_value(), config.vapid_contacto,
                                        httpx.Client(timeout=httpx.Timeout(15.0, connect=10.0)), reloj)
    if config.ia_configurada and modelo_ia is None:
        modelo_ia = AsistenteGemini(config.gemini_clave.get_secret_value(), config.gemini_modelo,
                                    httpx.Client(timeout=httpx.Timeout(30.0, connect=10.0)))
    if config.tiempo_real_configurado and verificador_gmail is None:
        verificador_gmail = VerificadorOidcGoogle(config.pubsub_audiencia, config.pubsub_cuenta_servicio,
                                                  httpx.Client(timeout=httpx.Timeout(10.0, connect=5.0)))
    lector = LectorCorreoMime(clave_avisos(llave), InspectorAdjuntos())
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
        revisar_pendientes=buzones.RevisarBuzonesPendientes(uow, reloj, revisar,
                                                            tiempo_real=verificador_gmail is not None),
        renovar_vigilancias=tiempo_real.RenovarVigilancias(
            uow, reloj, proveedor, cifrador, config.pubsub_tema if verificador_gmail is not None else None),
        recibir_aviso_gmail=tiempo_real.RecibirAvisoGmail(uow, reloj, verificador_gmail),
        lector=lector, modelos=modelos,
        analizar_manual=analisis.AnalizarCorreoManual(uow, reloj, lector, motor_analisis),
        listar_casos=casos.ListarCasos(uow, reloj),
        ver_caso=casos.VerCaso(uow, reloj),
        liberar_correo=casos.LiberarCorreo(uow, reloj, proveedor, cifrador),
        clasificar_caso=casos.ClasificarCaso(uow, reloj),
        nota_caso=casos.AgregarNotaCaso(uow, reloj),
        enviar_avisos=casos.EnviarAvisosPendientes(uow, reloj, proveedor, cifrador,
                                                   RedactorAvisosMime(clave_avisos(llave), config.url_panel),
                                                   enviador_push, carga_de_aviso),
        resumen_panel=panel.ObtenerResumenPanel(uow, reloj),
        listar_modelos=panel.ListarModelos(uow, reloj),
        generar_reporte=reportes.GenerarReporte(uow, reloj, GeneradorReportes()),
        activar_push=notificaciones.ActivarPush(uow, reloj, enviador_push),
        listar_dispositivos_push=notificaciones.ListarDispositivosPush(uow, reloj),
        quitar_push=notificaciones.QuitarPush(uow, reloj),
        probar_push=notificaciones.ProbarPush(uow, reloj, enviador_push),
        preguntar_asistente=asistente.PreguntarAsistente(uow, reloj, modelo_ia),
        consultar_asistente=asistente.ConsultarAsistente(uow, reloj, modelo_ia),
    )
