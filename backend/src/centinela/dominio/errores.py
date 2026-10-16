"""Errores del negocio. Cada uno trae un mensaje en español listo para mostrarle a la persona."""


class ErrorCentinela(Exception):
    codigo = "error"

    def __init__(self, mensaje: str):
        super().__init__(mensaje)
        self.mensaje = mensaje


class DatoInvalido(ErrorCentinela):
    codigo = "dato_invalido"


class CredencialesInvalidas(ErrorCentinela):
    codigo = "credenciales_invalidas"


class CuentaBloqueada(ErrorCentinela):
    codigo = "cuenta_bloqueada"


class AccesoDenegado(ErrorCentinela):
    codigo = "acceso_denegado"


class NoEncontrado(ErrorCentinela):
    codigo = "no_encontrado"


class Conflicto(ErrorCentinela):
    codigo = "conflicto"


class TransicionInvalida(ErrorCentinela):
    codigo = "transicion_invalida"


class ServicioNoDisponible(ErrorCentinela):
    codigo = "servicio_no_disponible"
