"""Casos de uso de identidad y acceso: registro, inicio de sesión con doble factor, sesiones y cuentas.

Reglas de seguridad aplicadas aquí:
  * Mensajes genéricos ante credenciales malas (no revelan si el correo existe).
  * Bloqueo temporal tras varios intentos fallidos (contraseña o código 2FA).
  * Doble factor obligatorio para el administrador.
  * Tokens de renovación rotativos; si se reutiliza uno ya rotado, se cierran todas las sesiones del usuario.
"""
from __future__ import annotations

import hashlib
import math
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from centinela.aplicacion.puertos import (
    Cifrador,
    EventoAuditoria,
    FabricaUnidadDeTrabajo,
    HasherClaves,
    Reloj,
    ServicioTotp,
    UnidadDeTrabajo,
)
from centinela.dominio.errores import (
    AccesoDenegado,
    Conflicto,
    CredencialesInvalidas,
    CuentaBloqueada,
    DatoInvalido,
    NoEncontrado,
)
from centinela.dominio.sesion import Sesion
from centinela.dominio.usuario import EstadoCuenta, Usuario, normalizar_correo, validar_clave

DURACION_SESION = timedelta(days=7)
GRACIA_ROTACION = timedelta(seconds=10)   # dos pestañas renovando a la vez no es un robo
N_CODIGOS_RECUPERACION = 10
MSG_CREDENCIALES = "Correo o contraseña incorrectos."
MSG_SESION = "Tu sesión expiró. Inicia sesión de nuevo."


def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


def _normalizar_codigo_recuperacion(codigo: str) -> str:
    return codigo.strip().lower().replace("-", "").replace(" ", "")


def hash_codigo_recuperacion(codigo: str) -> str:
    return hashlib.sha256(_normalizar_codigo_recuperacion(codigo).encode()).hexdigest()


def _nuevo_codigo_recuperacion() -> str:
    h = secrets.token_hex(5)
    return f"{h[:5]}-{h[5:]}"


@dataclass(frozen=True)
class Contexto:
    """Datos de la petición que sirven para auditar."""
    ip: str | None = None
    agente: str | None = None


SIN_CONTEXTO = Contexto()


@dataclass(frozen=True)
class SesionCreada:
    usuario: Usuario
    token_renovacion: str      # en claro: solo viaja una vez hacia el navegador
    expira_en: datetime


class Paso(StrEnum):
    COMPLETO = "completo"
    VERIFICAR_2FA = "verificar_2fa"
    CONFIGURAR_2FA = "configurar_2fa"


@dataclass(frozen=True)
class ResultadoInicio:
    paso: Paso
    usuario: Usuario
    sesion: SesionCreada | None = None


@dataclass(frozen=True)
class DatosConfiguracion2FA:
    secreto: str
    uri: str


@dataclass(frozen=True)
class Resultado2FAActivado:
    codigos_recuperacion: list[str]
    sesion: SesionCreada | None


class AccionCuenta(StrEnum):
    APROBAR = "aprobar"
    RECHAZAR = "rechazar"
    DESACTIVAR = "desactivar"
    REACTIVAR = "reactivar"


# ---------------------------------------------------------------------- utilidades compartidas
class _CasoDeUso:
    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj):
        self._uow = uow
        self._reloj = reloj


def _auditar(uow: UnidadDeTrabajo, accion: str, ctx: Contexto, usuario_id: int | None = None,
             exito: bool = True, **detalle) -> None:
    uow.auditoria.registrar(EventoAuditoria(accion=accion, usuario_id=usuario_id, objeto_tipo="usuario",
                                            objeto_id=str(usuario_id) if usuario_id else None,
                                            exito=exito, ip=ctx.ip, detalle=detalle))


def _msg_bloqueo(usuario: Usuario, ahora: datetime) -> str:
    minutos = max(1, math.ceil((usuario.bloqueado_hasta - ahora).total_seconds() / 60))
    return f"Demasiados intentos fallidos. Intenta de nuevo en {minutos} minuto(s)."


def _registrar_fallo(uow: UnidadDeTrabajo, usuario: Usuario, ahora: datetime, ctx: Contexto, accion: str) -> None:
    """Cuenta el intento fallido, lo audita y CONFIRMA (el fallo debe quedar guardado aunque luego se lance error)."""
    max_intentos = int(uow.configuracion.obtener("seguridad.max_intentos", 5))
    minutos = int(uow.configuracion.obtener("seguridad.minutos_bloqueo", 15))
    bloqueada = usuario.registrar_fallo(ahora, max_intentos, minutos)
    uow.usuarios.guardar(usuario)
    _auditar(uow, accion, ctx, usuario.id, exito=False, bloqueada=bloqueada)
    uow.confirmar()
    if bloqueada:
        raise CuentaBloqueada(_msg_bloqueo(usuario, ahora))


def _crear_sesion(uow: UnidadDeTrabajo, usuario: Usuario, ahora: datetime, ctx: Contexto) -> SesionCreada:
    token = secrets.token_urlsafe(32)
    uow.sesiones.agregar(Sesion(usuario_id=usuario.id, token_hash=hash_token(token), creada_en=ahora,
                                expira_en=ahora + DURACION_SESION, ip=ctx.ip,
                                agente=(ctx.agente or "")[:300] or None))
    usuario.registrar_acceso(ahora)
    uow.usuarios.guardar(usuario)
    return SesionCreada(usuario=usuario, token_renovacion=token, expira_en=ahora + DURACION_SESION)


def _usuario_activo(uow: UnidadDeTrabajo, usuario_id: int) -> Usuario:
    usuario = uow.usuarios.por_id(usuario_id)
    if usuario is None:
        raise CredencialesInvalidas(MSG_SESION)
    usuario.verificar_puede_ingresar()
    return usuario


def _admin_activo(uow: UnidadDeTrabajo, admin_id: int) -> Usuario:
    admin = _usuario_activo(uow, admin_id)
    if not admin.es_admin:
        raise AccesoDenegado("Esta acción es solo para administradores.")
    return admin


# ---------------------------------------------------------------------- registro
class SolicitarRegistro(_CasoDeUso):
    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, hasher: HasherClaves):
        super().__init__(uow, reloj)
        self._hasher = hasher

    def ejecutar(self, correo: str, nombre: str, clave: str, ctx: Contexto = SIN_CONTEXTO) -> None:
        """Siempre responde igual, exista o no el correo, para no revelar qué cuentas existen."""
        candidato = Usuario.solicitar(correo, nombre, clave_hash="")
        validar_clave(clave, candidato.correo)
        candidato.clave_hash = self._hasher.hashear(clave)      # se calcula siempre: mismo tiempo de respuesta
        with self._uow() as uow:
            if uow.usuarios.por_correo(candidato.correo) is not None:
                _auditar(uow, "usuario.registro_duplicado", ctx, exito=False, correo=candidato.correo)
            else:
                nuevo = uow.usuarios.agregar(candidato)
                _auditar(uow, "usuario.registro", ctx, nuevo.id)
            uow.confirmar()


class CrearAdministrador(_CasoDeUso):
    """Crea un administrador desde la consola del servidor (instalación inicial)."""

    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, hasher: HasherClaves):
        super().__init__(uow, reloj)
        self._hasher = hasher

    def ejecutar(self, correo: str, nombre: str, clave: str) -> Usuario:
        admin = Usuario.administrador_inicial(correo, nombre, clave_hash="", ahora=self._reloj.ahora())
        validar_clave(clave, admin.correo)
        admin.clave_hash = self._hasher.hashear(clave)
        with self._uow() as uow:
            if uow.usuarios.por_correo(admin.correo) is not None:
                raise Conflicto("Ya existe una cuenta con ese correo.")
            admin = uow.usuarios.agregar(admin)
            _auditar(uow, "usuario.crear_admin", Contexto(), admin.id, origen="consola")
            uow.confirmar()
        return admin


# ---------------------------------------------------------------------- inicio de sesión
class IniciarSesion(_CasoDeUso):
    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, hasher: HasherClaves):
        super().__init__(uow, reloj)
        self._hasher = hasher
        self._hash_ficticio = hasher.hashear(secrets.token_hex(16))

    def ejecutar(self, correo: str, clave: str, ctx: Contexto = SIN_CONTEXTO) -> ResultadoInicio:
        try:
            correo = normalizar_correo(correo)
        except DatoInvalido:
            raise CredencialesInvalidas(MSG_CREDENCIALES) from None
        ahora = self._reloj.ahora()
        with self._uow() as uow:
            usuario = uow.usuarios.por_correo(correo)
            if usuario is None:
                self._hasher.verificar(clave, self._hash_ficticio)     # iguala el tiempo de respuesta
                _auditar(uow, "sesion.inicio", ctx, exito=False, motivo="correo_desconocido")
                uow.confirmar()
                raise CredencialesInvalidas(MSG_CREDENCIALES)
            if usuario.esta_bloqueado(ahora):
                _auditar(uow, "sesion.inicio", ctx, usuario.id, exito=False, motivo="cuenta_bloqueada")
                uow.confirmar()
                raise CuentaBloqueada(_msg_bloqueo(usuario, ahora))
            if not self._hasher.verificar(clave, usuario.clave_hash):
                _registrar_fallo(uow, usuario, ahora, ctx, "sesion.inicio")
                raise CredencialesInvalidas(MSG_CREDENCIALES)
            try:
                usuario.verificar_puede_ingresar()
            except AccesoDenegado:
                _auditar(uow, "sesion.inicio", ctx, usuario.id, exito=False, motivo=usuario.estado.value)
                uow.confirmar()
                raise
            if self._hasher.necesita_rehash(usuario.clave_hash):
                usuario.clave_hash = self._hasher.hashear(clave)
                uow.usuarios.guardar(usuario)

            if usuario.debe_configurar_2fa:
                resultado = ResultadoInicio(Paso.CONFIGURAR_2FA, usuario)
            elif usuario.totp_activo:
                resultado = ResultadoInicio(Paso.VERIFICAR_2FA, usuario)
            else:
                resultado = ResultadoInicio(Paso.COMPLETO, usuario, _crear_sesion(uow, usuario, ahora, ctx))
            _auditar(uow, "sesion.inicio" if resultado.sesion else "sesion.contrasena_valida", ctx, usuario.id)
            uow.confirmar()
            return resultado


class VerificarSegundoFactor(_CasoDeUso):
    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, totp: ServicioTotp, cifrador: Cifrador):
        super().__init__(uow, reloj)
        self._totp = totp
        self._cifrador = cifrador

    def ejecutar(self, usuario_id: int, codigo: str, ctx: Contexto = SIN_CONTEXTO) -> SesionCreada:
        ahora = self._reloj.ahora()
        codigo = (codigo or "").strip().replace(" ", "")
        with self._uow() as uow:
            usuario = _usuario_activo(uow, usuario_id)
            if not usuario.totp_activo:
                raise CredencialesInvalidas(MSG_SESION)
            if usuario.esta_bloqueado(ahora):
                raise CuentaBloqueada(_msg_bloqueo(usuario, ahora))

            uso_recuperacion = False
            mensaje = "El código no es correcto."
            if codigo.isdigit() and len(codigo) == 6:
                paso = self._totp.verificar(self._cifrador.descifrar(usuario.totp_secreto_cifrado), codigo, ahora)
                valido = paso is not None
                if valido:
                    try:
                        usuario.consumir_paso_totp(paso)
                    except CredencialesInvalidas as e:
                        valido, mensaje = False, e.mensaje
            else:
                valido = uso_recuperacion = uow.codigos_recuperacion.consumir(
                    usuario.id, hash_codigo_recuperacion(codigo), ahora)

            if not valido:
                _registrar_fallo(uow, usuario, ahora, ctx, "sesion.segundo_factor")
                raise CredencialesInvalidas(mensaje)
            sesion = _crear_sesion(uow, usuario, ahora, ctx)
            _auditar(uow, "sesion.inicio", ctx, usuario.id, segundo_factor=True, codigo_recuperacion=uso_recuperacion)
            uow.confirmar()
            return sesion


class IniciarConfiguracion2FA(_CasoDeUso):
    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, totp: ServicioTotp, cifrador: Cifrador):
        super().__init__(uow, reloj)
        self._totp = totp
        self._cifrador = cifrador

    def ejecutar(self, usuario_id: int) -> DatosConfiguracion2FA:
        secreto = self._totp.generar_secreto()
        with self._uow() as uow:
            usuario = _usuario_activo(uow, usuario_id)
            usuario.preparar_2fa(self._cifrador.cifrar(secreto))
            uow.usuarios.guardar(usuario)
            uow.confirmar()
        return DatosConfiguracion2FA(secreto=secreto, uri=self._totp.uri_aprovisionamiento(secreto, usuario.correo))


class ConfirmarConfiguracion2FA(_CasoDeUso):
    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, totp: ServicioTotp, cifrador: Cifrador):
        super().__init__(uow, reloj)
        self._totp = totp
        self._cifrador = cifrador

    def ejecutar(self, usuario_id: int, codigo: str, ctx: Contexto = SIN_CONTEXTO,
                 iniciar_sesion: bool = False) -> Resultado2FAActivado:
        ahora = self._reloj.ahora()
        with self._uow() as uow:
            usuario = _usuario_activo(uow, usuario_id)
            if usuario.totp_activo:
                raise Conflicto("El doble factor ya está activo en esta cuenta.")
            if usuario.totp_secreto_cifrado is None:
                raise Conflicto("Primero inicia la configuración del doble factor.")
            if usuario.esta_bloqueado(ahora):
                raise CuentaBloqueada(_msg_bloqueo(usuario, ahora))
            paso = self._totp.verificar(self._cifrador.descifrar(usuario.totp_secreto_cifrado),
                                        (codigo or "").strip().replace(" ", ""), ahora)
            if paso is None:
                _registrar_fallo(uow, usuario, ahora, ctx, "2fa.activar")
                raise CredencialesInvalidas("El código no es correcto. Revisa que la hora de tu celular esté bien.")
            usuario.activar_2fa(paso)
            uow.usuarios.guardar(usuario)
            codigos = [_nuevo_codigo_recuperacion() for _ in range(N_CODIGOS_RECUPERACION)]
            uow.codigos_recuperacion.reemplazar(usuario.id, [hash_codigo_recuperacion(c) for c in codigos])
            sesion = _crear_sesion(uow, usuario, ahora, ctx) if iniciar_sesion else None
            _auditar(uow, "2fa.activar", ctx, usuario.id)
            uow.confirmar()
        return Resultado2FAActivado(codigos_recuperacion=codigos, sesion=sesion)


# ---------------------------------------------------------------------- sesiones
class RenovarSesion(_CasoDeUso):
    def ejecutar(self, token: str, ctx: Contexto = SIN_CONTEXTO) -> SesionCreada:
        ahora = self._reloj.ahora()
        with self._uow() as uow:
            sesion = uow.sesiones.por_hash(hash_token(token or ""))
            if sesion is None:
                raise CredencialesInvalidas(MSG_SESION)
            if sesion.revocada_en is not None:
                if ahora - sesion.revocada_en > GRACIA_ROTACION:
                    # Alguien usó un token que ya había sido reemplazado: posible robo. Se cierra todo.
                    n = uow.sesiones.revocar_de_usuario(sesion.usuario_id, ahora)
                    _auditar(uow, "sesion.reuso_detectado", ctx, sesion.usuario_id, exito=False, revocadas=n)
                    uow.confirmar()
                raise CredencialesInvalidas(MSG_SESION)
            if not sesion.vigente(ahora):
                raise CredencialesInvalidas(MSG_SESION)
            usuario = _usuario_activo(uow, sesion.usuario_id)
            sesion.revocar(ahora)
            uow.sesiones.guardar(sesion)
            nueva = _crear_sesion(uow, usuario, ahora, ctx)
            uow.confirmar()
            return nueva


class CerrarSesion(_CasoDeUso):
    def ejecutar(self, token: str, ctx: Contexto = SIN_CONTEXTO) -> None:
        with self._uow() as uow:
            sesion = uow.sesiones.por_hash(hash_token(token or ""))
            if sesion is None or sesion.revocada_en is not None:
                return
            sesion.revocar(self._reloj.ahora())
            uow.sesiones.guardar(sesion)
            _auditar(uow, "sesion.cierre", ctx, sesion.usuario_id)
            uow.confirmar()


# ---------------------------------------------------------------------- cuenta propia
class ObtenerUsuario(_CasoDeUso):
    def ejecutar(self, usuario_id: int) -> Usuario:
        with self._uow() as uow:
            return _usuario_activo(uow, usuario_id)


class CambiarClave(_CasoDeUso):
    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, hasher: HasherClaves):
        super().__init__(uow, reloj)
        self._hasher = hasher

    def ejecutar(self, usuario_id: int, actual: str, nueva: str, ctx: Contexto = SIN_CONTEXTO) -> SesionCreada:
        """Cambia la contraseña, cierra todas las sesiones y abre una nueva para quien hizo el cambio."""
        ahora = self._reloj.ahora()
        with self._uow() as uow:
            usuario = _usuario_activo(uow, usuario_id)
            if usuario.esta_bloqueado(ahora):
                raise CuentaBloqueada(_msg_bloqueo(usuario, ahora))
            if not self._hasher.verificar(actual, usuario.clave_hash):
                _registrar_fallo(uow, usuario, ahora, ctx, "usuario.cambiar_clave")
                raise CredencialesInvalidas("La contraseña actual no es correcta.")
            validar_clave(nueva, usuario.correo)
            if self._hasher.verificar(nueva, usuario.clave_hash):
                raise DatoInvalido("La nueva contraseña debe ser distinta de la actual.")
            usuario.clave_hash = self._hasher.hashear(nueva)
            uow.sesiones.revocar_de_usuario(usuario.id, ahora)
            sesion = _crear_sesion(uow, usuario, ahora, ctx)
            _auditar(uow, "usuario.cambiar_clave", ctx, usuario.id)
            uow.confirmar()
            return sesion


# ---------------------------------------------------------------------- administración
class ListarUsuarios(_CasoDeUso):
    def ejecutar(self, admin_id: int, estado: EstadoCuenta | None = None) -> list[Usuario]:
        with self._uow() as uow:
            _admin_activo(uow, admin_id)
            return uow.usuarios.listar(estado)


class CambiarEstadoCuenta(_CasoDeUso):
    def ejecutar(self, admin_id: int, usuario_id: int, accion: AccionCuenta, ctx: Contexto = SIN_CONTEXTO) -> Usuario:
        ahora = self._reloj.ahora()
        with self._uow() as uow:
            admin = _admin_activo(uow, admin_id)
            usuario = uow.usuarios.por_id(usuario_id)
            if usuario is None:
                raise NoEncontrado("El usuario no existe.")
            if accion is AccionCuenta.APROBAR:
                usuario.aprobar(admin, ahora)
            elif accion is AccionCuenta.RECHAZAR:
                usuario.rechazar(admin)
            elif accion is AccionCuenta.DESACTIVAR:
                usuario.desactivar(admin)
                uow.sesiones.revocar_de_usuario(usuario.id, ahora)
            else:
                usuario.reactivar(admin)
            uow.usuarios.guardar(usuario)
            uow.auditoria.registrar(EventoAuditoria(accion=f"usuario.{accion.value}", usuario_id=admin.id,
                                                    objeto_tipo="usuario", objeto_id=str(usuario.id), ip=ctx.ip))
            uow.confirmar()
            return usuario
