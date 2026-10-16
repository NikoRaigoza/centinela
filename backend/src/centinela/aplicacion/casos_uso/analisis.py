"""Motor de análisis: une reglas expertas, modelo de contenido y modelo de enlaces en un veredicto explicable."""
from __future__ import annotations

import time
from statistics import mean

from centinela.aplicacion.casos_uso.comun import SIN_CONTEXTO, CasoDeUso, Contexto, usuario_activo
from centinela.aplicacion.puertos import (
    EvaluacionEnlace,
    EventoAuditoria,
    FabricaUnidadDeTrabajo,
    LectorCorreo,
    ProveedorModelos,
    Reloj,
    ResultadoAnalisis,
)
from centinela.dominio.correo import CorreoParseado
from centinela.dominio.dominios import host_de_url
from centinela.dominio.entidades import CatalogoEntidades
from centinela.dominio.idioma import detectar_idioma
from centinela.dominio.reglas import evaluar_reglas
from centinela.dominio.riesgo import (
    PESO_ENLACES,
    UMBRAL_ALTO,
    UMBRAL_MEDIO,
    Area,
    Gravedad,
    NivelRiesgo,
    Razon,
    Veredicto,
    combinar_riesgo,
    redactar_resumen,
    seleccionar_razones,
)

MAX_ENLACES_MODELO = 15
LARGO_MINIMO_TEXTO = 20


def _gravedad_por_probabilidad(p: float) -> Gravedad:
    return Gravedad.ALTA if p >= UMBRAL_ALTO else (Gravedad.MEDIA if p >= 0.5 else Gravedad.BAJA)


def _razones_de_enlaces(evaluaciones: list[EvaluacionEnlace], razones_reglas: list[Razon]) -> list[Razon]:
    """Si el modelo ve riesgo en un enlace que ninguna regla explicó, se agrega una razón genérica para él."""
    if any(r.area is Area.ENLACE for r in razones_reglas):
        return []
    riesgosos = sorted((e for e in evaluaciones if e.probabilidad is not None and e.probabilidad >= 0.5),
                       key=lambda e: e.probabilidad, reverse=True)
    if not riesgosos:
        return []
    e = riesgosos[0]
    return [Razon(Area.ENLACE, _gravedad_por_probabilidad(e.probabilidad),
                  f"Un enlace lleva a {e.dominio}, que tiene características típicas de sitios fraudulentos.",
                  aporte=round(PESO_ENLACES * e.probabilidad, 4))]


class MotorAnalisis:
    def __init__(self, modelos: ProveedorModelos):
        self._modelos = modelos

    def analizar(self, correo: CorreoParseado, catalogo: CatalogoEntidades) -> ResultadoAnalisis:
        inicio = time.perf_counter()
        reglas = evaluar_reglas(correo, catalogo)

        clasificador_texto = self._modelos.contenido()
        contenido = None
        if clasificador_texto is not None and len(correo.cuerpo.strip()) >= LARGO_MINIMO_TEXTO:
            contenido = clasificador_texto.evaluar(correo.asunto, correo.cuerpo)

        clasificador_enlaces = self._modelos.enlaces()
        urls = [e.url for e in correo.enlaces if host_de_url(e.url) and not e.url.lower().startswith("javascript:")]
        enlaces = clasificador_enlaces.evaluar(urls[:MAX_ENLACES_MODELO]) if clasificador_enlaces and urls else []
        probabilidades = [e.probabilidad for e in enlaces if e.probabilidad is not None]
        p_enlaces = mean(probabilidades) if probabilidades else None       # el promedio fue lo más estable

        razones = reglas.razones + (contenido.razones if contenido else []) + _razones_de_enlaces(enlaces, reglas.razones)
        combinado = combinar_riesgo(contenido.probabilidad if contenido else None, p_enlaces, reglas.razones,
                                    remitente_verificado=reglas.remitente_verificado)
        nivel = NivelRiesgo.desde_probabilidad(combinado.p_final, UMBRAL_MEDIO, UMBRAL_ALTO)
        if nivel is not NivelRiesgo.BAJO and not razones:
            razones.append(Razon(Area.CONTENIDO, Gravedad.MEDIA, "El correo se parece a mensajes de phishing conocidos.",
                                 aporte=combinado.p_final))
        visibles = seleccionar_razones(razones)
        entidad = next((e for r in visibles if r.entidad_id for e in catalogo.entidades if e.id == r.entidad_id), None)
        veredicto = Veredicto(
            p_final=combinado.p_final, nivel=nivel,
            resumen=redactar_resumen(nivel, visibles, entidad.nombre if entidad else None),
            razones=razones, p_contenido=round(contenido.probabilidad, 4) if contenido else None,
            p_enlaces=round(p_enlaces, 4) if p_enlaces is not None else None, p_tecnico=combinado.p_tecnico,
            tiempo_ms=int((time.perf_counter() - inicio) * 1000))
        return ResultadoAnalisis(
            veredicto=veredicto, enlaces=enlaces, positivas=reglas.positivas,
            idioma=contenido.idioma if contenido else detectar_idioma(f"{correo.asunto} {correo.cuerpo}"),
            modelo_contenido_id=clasificador_texto.modelo_id if contenido else None,
            modelo_enlaces_id=clasificador_enlaces.modelo_id if enlaces else None)


class AnalizarCorreoManual(CasoDeUso):
    """Analiza un .eml subido al panel. No guarda el correo: sirve para probar y para la evaluación de la tesis."""

    def __init__(self, uow: FabricaUnidadDeTrabajo, reloj: Reloj, lector: LectorCorreo, motor: MotorAnalisis):
        super().__init__(uow, reloj)
        self._lector = lector
        self._motor = motor

    def ejecutar(self, usuario_id: int, crudo: bytes, ctx: Contexto = SIN_CONTEXTO) -> tuple[CorreoParseado, ResultadoAnalisis]:
        with self._uow() as uow:
            usuario_activo(uow, usuario_id)
            catalogo = uow.entidades.catalogo()
        correo = self._lector.leer(crudo)
        resultado = self._motor.analizar(correo, catalogo)
        with self._uow() as uow:
            uow.auditoria.registrar(EventoAuditoria(accion="analisis.manual", usuario_id=usuario_id, ip=ctx.ip,
                                                    detalle={"nivel": resultado.veredicto.nivel.value}))
            uow.confirmar()
        return correo, resultado
