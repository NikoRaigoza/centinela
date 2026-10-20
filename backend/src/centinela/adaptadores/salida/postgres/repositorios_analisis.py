"""Repositorios del análisis: modelos, catálogo de entidades, veredictos, casos, avisos, retroalimentación y
estadísticas del panel."""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from decimal import Decimal

from sqlalchemy import func, select, true, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from centinela.adaptadores.salida.postgres.tablas import (
    AdjuntoAnalizadoFila,
    AvisoFila,
    BuzonFila,
    CasoFila,
    DominioOficialFila,
    EnlaceAnalizadoFila,
    EntidadSuplantadaFila,
    EventoCasoFila,
    MensajeAnalizadoFila,
    ModeloMlFila,
    RazonFila,
    RetroalimentacionFila,
    UsuarioFila,
    VeredictoFila,
)
from centinela.aplicacion.puertos import (
    AdjuntoGuardado,
    AvisoPendiente,
    ContextoCaso,
    DatosAviso,
    DetalleCaso,
    DiaPanel,
    EnlaceGuardado,
    EstadisticasPanel,
    EventoGuardado,
    FilaBuzonReporte,
    ModeloRegistrado,
    ResultadoAnalisis,
    ResumenCaso,
)
from centinela.dominio.caso import Caso, EstadoCaso
from centinela.dominio.dominios import ACORTADORES
from centinela.dominio.entidades import CatalogoEntidades, Entidad
from centinela.dominio.politica import Acciones
from centinela.dominio.riesgo import UMBRAL_ALTO, UMBRAL_MEDIO, Area, Gravedad, NivelRiesgo, Razon

ARRIENDO_AVISO = timedelta(minutes=10)     # mientras un worker envía un aviso, nadie más lo toma


def _dec(x: float | None, digitos: int = 4) -> Decimal | None:
    return None if x is None else Decimal(str(round(x, digitos)))


def _f(x: Decimal | None) -> float | None:
    return None if x is None else float(x)


# ---------------------------------------------------------------------- modelos y catálogo
def _a_modelo(f: ModeloMlFila) -> ModeloRegistrado:
    return ModeloRegistrado(id=f.id, tipo=f.tipo, nombre=f.nombre, version=f.version, ruta=f.ruta_artefacto,
                            sha256=f.sha256, dataset=f.dataset, umbral_medio=float(f.umbral_medio),
                            umbral_alto=float(f.umbral_alto), activo=f.activo, metricas=dict(f.metricas or {}),
                            creado_en=f.creado_en)


class RepoModelosSql:
    def __init__(self, s: Session):
        self._s = s

    def activo(self, tipo: str) -> ModeloRegistrado | None:
        f = self._s.scalar(select(ModeloMlFila).where(ModeloMlFila.tipo == tipo, ModeloMlFila.activo.is_(True)))
        return _a_modelo(f) if f else None

    def listar(self) -> list[ModeloRegistrado]:
        return [_a_modelo(f) for f in self._s.scalars(select(ModeloMlFila).order_by(ModeloMlFila.id))]

    def registrar(self, m: ModeloRegistrado, activar: bool) -> ModeloRegistrado:
        if activar:
            self._s.execute(update(ModeloMlFila).where(ModeloMlFila.tipo == m.tipo).values(activo=False))
        f = ModeloMlFila(tipo=m.tipo, nombre=m.nombre, version=m.version, ruta_artefacto=m.ruta, sha256=m.sha256,
                         dataset=m.dataset, metricas=m.metricas, umbral_medio=_dec(m.umbral_medio, 3),
                         umbral_alto=_dec(m.umbral_alto, 3), activo=activar)
        self._s.add(f)
        self._s.flush()
        return _a_modelo(f)


class RepoEntidadesSql:
    def __init__(self, s: Session):
        self._s = s

    def catalogo(self) -> CatalogoEntidades:
        dominios: dict[int, list[str]] = {}
        for entidad_id, dominio in self._s.execute(select(DominioOficialFila.entidad_id, DominioOficialFila.dominio)):
            dominios.setdefault(entidad_id, []).append(dominio)
        filas = self._s.scalars(select(EntidadSuplantadaFila).where(EntidadSuplantadaFila.activa.is_(True))
                                .order_by(EntidadSuplantadaFila.id))
        return CatalogoEntidades([Entidad(id=f.id, nombre=f.nombre, categoria=f.categoria, alias=tuple(f.alias or ()),
                                          dominios=tuple(dominios.get(f.id, ()))) for f in filas])


# ---------------------------------------------------------------------- veredictos
def _nivel_de(p: float | None) -> str | None:
    return None if p is None else NivelRiesgo.desde_probabilidad(p, UMBRAL_MEDIO, UMBRAL_ALTO).value


class RepoAnalisisSql:
    def __init__(self, s: Session):
        self._s = s

    def guardar(self, mensaje_id: int, r: ResultadoAnalisis) -> int:
        v = r.veredicto
        self._s.execute(update(VeredictoFila).where(VeredictoFila.mensaje_id == mensaje_id, VeredictoFila.vigente.is_(True))
                        .values(vigente=False))
        fila = VeredictoFila(mensaje_id=mensaje_id, modelo_contenido_id=r.modelo_contenido_id,
                             modelo_enlaces_id=r.modelo_enlaces_id, p_contenido=_dec(v.p_contenido),
                             p_enlaces=_dec(v.p_enlaces), p_tecnico=_dec(v.p_tecnico), p_final=_dec(v.p_final),
                             nivel=v.nivel.value, resumen=v.resumen, tiempo_ms=v.tiempo_ms)
        self._s.add(fila)
        self._s.flush()
        visibles = v.razones_visibles
        ordenadas = visibles + [x for x in v.razones if x not in visibles]
        self._s.add_all(RazonFila(veredicto_id=fila.id, orden=i, area=x.area.value, gravedad=x.gravedad.value,
                                  aporte=_dec(x.aporte), texto=x.texto, mostrada=x in visibles, entidad_id=x.entidad_id)
                        for i, x in enumerate(ordenadas, start=1))
        self._s.add_all(EnlaceAnalizadoFila(veredicto_id=fila.id, dominio=e.dominio[:255],
                                            url_sha256=hashlib.sha256(e.url.encode()).hexdigest(),
                                            probabilidad=_dec(e.probabilidad), nivel=_nivel_de(e.probabilidad),
                                            es_acortador=e.dominio in ACORTADORES, enganoso=e.enganoso,
                                            dominio_texto_visible=e.dominio_visible, origen=e.origen)
                        for e in r.enlaces)
        self._s.flush()
        return fila.id


# ---------------------------------------------------------------------- casos
class RepoCasosSql:
    def __init__(self, s: Session):
        self._s = s

    def _guardar_eventos(self, caso: Caso) -> None:
        self._s.add_all(EventoCasoFila(caso_id=caso.id, tipo=e.tipo.value, autor_id=e.autor_id, detalle=e.detalle,
                                       estado_anterior=e.estado_anterior.value if e.estado_anterior else None,
                                       estado_nuevo=e.estado_nuevo.value if e.estado_nuevo else None, creado_en=e.creado_en)
                        for e in caso.eventos_nuevos)
        caso.eventos_nuevos.clear()
        self._s.flush()

    def agregar(self, caso: Caso) -> Caso:
        f = CasoFila(mensaje_id=caso.mensaje_id, estado=caso.estado.value, creado_en=caso.creado_en,
                     cerrado_en=caso.cerrado_en)
        self._s.add(f)
        self._s.flush()
        caso.id = f.id
        self._guardar_eventos(caso)
        return caso

    def por_id(self, caso_id: int) -> Caso | None:
        f = self._s.get(CasoFila, caso_id)
        return Caso(id=f.id, mensaje_id=f.mensaje_id, creado_en=f.creado_en, estado=EstadoCaso(f.estado),
                    cerrado_en=f.cerrado_en) if f else None

    def guardar(self, caso: Caso) -> None:
        f = self._s.get(CasoFila, caso.id)
        f.estado, f.cerrado_en = caso.estado.value, caso.cerrado_en
        self._guardar_eventos(caso)

    def contexto(self, caso_id: int) -> ContextoCaso | None:
        fila = self._s.execute(
            select(CasoFila.id, BuzonFila.usuario_id, BuzonFila.id, MensajeAnalizadoFila.gmail_id, MensajeAnalizadoFila.id)
            .join(MensajeAnalizadoFila, MensajeAnalizadoFila.id == CasoFila.mensaje_id)
            .join(BuzonFila, BuzonFila.id == MensajeAnalizadoFila.buzon_id)
            .where(CasoFila.id == caso_id)).first()
        return ContextoCaso(*fila) if fila else None

    def _consulta_resumen(self):
        return (select(CasoFila, MensajeAnalizadoFila, BuzonFila.correo_gmail, VeredictoFila)
                .join(MensajeAnalizadoFila, MensajeAnalizadoFila.id == CasoFila.mensaje_id)
                .join(BuzonFila, BuzonFila.id == MensajeAnalizadoFila.buzon_id)
                .join(VeredictoFila, (VeredictoFila.mensaje_id == MensajeAnalizadoFila.id) & VeredictoFila.vigente.is_(True)))

    def _razones(self, veredicto_ids: list[int], solo_visibles: bool) -> dict[int, list[RazonFila]]:
        if not veredicto_ids:
            return {}
        q = select(RazonFila).where(RazonFila.veredicto_id.in_(veredicto_ids)).order_by(RazonFila.veredicto_id, RazonFila.orden)
        if solo_visibles:
            q = q.where(RazonFila.mostrada.is_(True))
        por_veredicto: dict[int, list[RazonFila]] = {}
        for r in self._s.scalars(q):
            por_veredicto.setdefault(r.veredicto_id, []).append(r)
        return por_veredicto

    @staticmethod
    def _resumen(caso, mensaje, correo_gmail, veredicto, razones) -> ResumenCaso:
        return ResumenCaso(id=caso.id, estado=caso.estado, creado_en=caso.creado_en, buzon_correo=correo_gmail,
                           remitente_nombre=mensaje.remitente_nombre, remitente_correo=mensaje.remitente_correo,
                           asunto=mensaje.asunto, recibido_en=mensaje.recibido_en, nivel=veredicto.nivel,
                           p_final=float(veredicto.p_final), resumen=veredicto.resumen,
                           razones=[r.texto for r in razones if r.mostrada])

    def listar(self, usuario_id: int, estados: list[str] | None, limite: int, desde: int) -> list[ResumenCaso]:
        q = self._consulta_resumen().where(BuzonFila.usuario_id == usuario_id)
        if estados:
            q = q.where(CasoFila.estado.in_(estados))
        filas = self._s.execute(q.order_by(MensajeAnalizadoFila.recibido_en.desc()).limit(limite).offset(desde)).all()
        razones = self._razones([v.id for *_, v in filas], solo_visibles=True)
        return [self._resumen(c, m, g, v, razones.get(v.id, [])) for c, m, g, v in filas]

    def del_periodo(self, usuario_id: int, desde: datetime, hasta: datetime, limite: int) -> list[ResumenCaso]:
        q = (self._consulta_resumen().where(BuzonFila.usuario_id == usuario_id, MensajeAnalizadoFila.recibido_en >= desde,
                                            MensajeAnalizadoFila.recibido_en < hasta)
             .order_by(MensajeAnalizadoFila.recibido_en.desc()).limit(limite))
        filas = self._s.execute(q).all()
        razones = self._razones([v.id for *_, v in filas], solo_visibles=True)
        return [self._resumen(c, m, g, v, razones.get(v.id, [])) for c, m, g, v in filas]

    def detalle(self, caso_id: int) -> DetalleCaso | None:
        fila = self._s.execute(self._consulta_resumen().where(CasoFila.id == caso_id)).first()
        if fila is None:
            return None
        caso, mensaje, correo_gmail, veredicto = fila
        razones = self._razones([veredicto.id], solo_visibles=False).get(veredicto.id, [])
        enlaces = self._s.scalars(select(EnlaceAnalizadoFila).where(EnlaceAnalizadoFila.veredicto_id == veredicto.id)
                                  .order_by(EnlaceAnalizadoFila.id))
        adjuntos = self._s.scalars(select(AdjuntoAnalizadoFila).where(AdjuntoAnalizadoFila.mensaje_id == mensaje.id)
                                   .order_by(AdjuntoAnalizadoFila.id))
        eventos = self._s.execute(select(EventoCasoFila, UsuarioFila.nombre)
                                  .outerjoin(UsuarioFila, UsuarioFila.id == EventoCasoFila.autor_id)
                                  .where(EventoCasoFila.caso_id == caso_id).order_by(EventoCasoFila.creado_en, EventoCasoFila.id))
        return DetalleCaso(
            resumen=self._resumen(caso, mensaje, correo_gmail, veredicto, razones),
            spf=mensaje.spf, dkim=mensaje.dkim, dmarc=mensaje.dmarc,
            todas_las_razones=[Razon(Area(r.area), Gravedad(r.gravedad), r.texto, _f(r.aporte), r.entidad_id) for r in razones],
            enlaces=[EnlaceGuardado(e.dominio, _f(e.probabilidad), e.enganoso, e.origen) for e in enlaces],
            adjuntos=[AdjuntoGuardado(a.nombre, a.tipo_mime, a.tamano_bytes, a.peligroso, a.motivo) for a in adjuntos],
            eventos=[EventoGuardado(e.tipo, e.creado_en, nombre or ("Centinela" if e.autor_id is None else None), e.detalle)
                     for e, nombre in eventos])


# ---------------------------------------------------------------------- avisos (outbox)
class RepoAvisosSql:
    def __init__(self, s: Session):
        self._s = s

    def agregar(self, caso_id: int, canal: str, destino: str) -> None:
        self._s.execute(pg_insert(AvisoFila).values(caso_id=caso_id, canal=canal, destino=destino)
                        .on_conflict_do_nothing(constraint="aviso_unico_por_canal"))

    def reclamar_pendientes(self, ahora: datetime, limite: int, canales: list[str]) -> list[AvisoPendiente]:
        pendientes = (select(AvisoFila.id).where(AvisoFila.estado == "pendiente", AvisoFila.proximo_intento_en <= ahora,
                                                 AvisoFila.canal.in_(canales))
                      .order_by(AvisoFila.proximo_intento_en).limit(limite).with_for_update(skip_locked=True))
        reclamados = self._s.execute(
            update(AvisoFila).where(AvisoFila.id.in_(pendientes.scalar_subquery()))
            .values(proximo_intento_en=ahora + ARRIENDO_AVISO, intentos=AvisoFila.intentos + 1)
            .returning(AvisoFila.id, AvisoFila.caso_id, AvisoFila.canal, AvisoFila.destino,
                       AvisoFila.intentos)).all()
        if not reclamados:
            return []
        casos = {c.id: (c, m, b, v) for c, m, b, v in self._s.execute(
            select(CasoFila, MensajeAnalizadoFila, BuzonFila, VeredictoFila)
            .join(MensajeAnalizadoFila, MensajeAnalizadoFila.id == CasoFila.mensaje_id)
            .join(BuzonFila, BuzonFila.id == MensajeAnalizadoFila.buzon_id)
            .join(VeredictoFila, (VeredictoFila.mensaje_id == MensajeAnalizadoFila.id) & VeredictoFila.vigente.is_(True))
            .where(CasoFila.id.in_([r.caso_id for r in reclamados])))}
        razones = RepoCasosSql(self._s)._razones([v.id for *_, v in casos.values()], solo_visibles=True)
        salida = []
        for r in reclamados:
            caso, mensaje, buzon, veredicto = casos[r.caso_id]
            remitente = f"{mensaje.remitente_nombre} <{mensaje.remitente_correo}>" if mensaje.remitente_nombre \
                else (mensaje.remitente_correo or "remitente desconocido")
            en_cuarentena = caso.estado == EstadoCaso.EN_CUARENTENA.value
            accion = Acciones(cuarentena=en_cuarentena, etiquetar_sospechoso=not en_cuarentena).descripcion
            salida.append(AvisoPendiente(
                id=r.id, caso_id=r.caso_id, buzon_id=buzon.id, intentos=r.intentos,
                datos=DatosAviso(destinatario=r.destino, nivel=veredicto.nivel, remitente=remitente,
                                 asunto=mensaje.asunto or "(sin asunto)", resumen=veredicto.resumen,
                                 razones=[x.texto for x in razones.get(veredicto.id, [])], accion=accion,
                                 caso_id=r.caso_id, en_cuarentena=en_cuarentena),
                canal=r.canal, usuario_id=buzon.usuario_id))
        return salida

    def marcar_enviado(self, aviso_id: int, ahora: datetime, referencia: str) -> None:
        self._s.execute(update(AvisoFila).where(AvisoFila.id == aviso_id)
                        .values(estado="enviado", enviado_en=ahora, referencia_externa=referencia, ultimo_error=None))

    def registrar_fallo(self, aviso_id: int, error: str, proximo_intento: datetime | None) -> None:
        valores = {"ultimo_error": error}
        if proximo_intento is None:
            valores["estado"] = "fallido"
        else:
            valores["proximo_intento_en"] = proximo_intento
        self._s.execute(update(AvisoFila).where(AvisoFila.id == aviso_id).values(**valores))


class RepoRetroalimentacionSql:
    def __init__(self, s: Session):
        self._s = s

    def registrar(self, mensaje_id: int, usuario_id: int, etiqueta: str, comentario: str | None = None) -> None:
        q = pg_insert(RetroalimentacionFila).values(mensaje_id=mensaje_id, usuario_id=usuario_id, etiqueta=etiqueta,
                                                     comentario=comentario)
        self._s.execute(q.on_conflict_do_update(constraint="retro_una_por_usuario", set_={
            "etiqueta": etiqueta, "comentario": comentario, "validada_por": None, "validada_en": None}))



# ---------------------------------------------------------------------- estadísticas del panel
class RepoEstadisticasSql:
    def __init__(self, s: Session):
        self._s = s

    @staticmethod
    def _propios(usuario_id: int | None):
        if usuario_id is None:
            return true()
        return MensajeAnalizadoFila.buzon_id.in_(select(BuzonFila.id).where(BuzonFila.usuario_id == usuario_id)
                                                 .scalar_subquery())

    def panel(self, usuario_id: int | None, desde: datetime, zona: str) -> EstadisticasPanel:
        propios = self._propios(usuario_id)
        vigente = (VeredictoFila.mensaje_id == MensajeAnalizadoFila.id) & VeredictoFila.vigente.is_(True)
        dia = func.date(func.timezone(zona, MensajeAnalizadoFila.recibido_en))

        por_dia: dict = {}
        por_nivel = {n.value: 0 for n in NivelRiesgo}
        for fecha, nivel, n in self._s.execute(
                select(dia, VeredictoFila.nivel, func.count()).select_from(MensajeAnalizadoFila)
                .outerjoin(VeredictoFila, vigente).where(propios, MensajeAnalizadoFila.recibido_en >= desde)
                .group_by(dia, VeredictoFila.nivel)):
            conteo = por_dia.setdefault(fecha, {"revisados": 0, "medio": 0, "alto": 0})
            conteo["revisados"] += n
            if nivel:
                por_nivel[nivel] += n
                if nivel in conteo:
                    conteo[nivel] += n

        casos = dict(self._s.execute(
            select(CasoFila.estado, func.count()).join(MensajeAnalizadoFila, MensajeAnalizadoFila.id == CasoFila.mensaje_id)
            .where(propios).group_by(CasoFila.estado)).all())

        n_correos = func.count(func.distinct(VeredictoFila.mensaje_id))
        entidades = self._s.execute(
            select(EntidadSuplantadaFila.nombre, n_correos).select_from(RazonFila)
            .join(EntidadSuplantadaFila, EntidadSuplantadaFila.id == RazonFila.entidad_id)
            .join(VeredictoFila, (VeredictoFila.id == RazonFila.veredicto_id) & VeredictoFila.vigente.is_(True))
            .join(MensajeAnalizadoFila, MensajeAnalizadoFila.id == VeredictoFila.mensaje_id)
            .where(propios, MensajeAnalizadoFila.recibido_en >= desde,
                   VeredictoFila.nivel.in_([NivelRiesgo.MEDIO.value, NivelRiesgo.ALTO.value]))
            .group_by(EntidadSuplantadaFila.nombre).order_by(n_correos.desc(), EntidadSuplantadaFila.nombre).limit(5)).all()

        return EstadisticasPanel(
            revisados=sum(c["revisados"] for c in por_dia.values()), por_nivel=por_nivel,
            casos_por_estado={e.value: casos.get(e.value, 0) for e in EstadoCaso},
            entidades_suplantadas=[(nombre, n) for nombre, n in entidades],
            serie=[DiaPanel(f, c["revisados"], c["medio"], c["alto"]) for f, c in sorted(por_dia.items())])

    def indicadores(self, usuario_id: int | None, desde: datetime) -> dict[str, int]:
        propios = self._propios(usuario_id)
        de_riesgo = (VeredictoFila.vigente.is_(True)
                     & VeredictoFila.nivel.in_([NivelRiesgo.MEDIO.value, NivelRiesgo.ALTO.value]))
        salida = {a.value: 0 for a in Area}
        salida.update(dict(self._s.execute(
            select(RazonFila.area, func.count(func.distinct(VeredictoFila.mensaje_id))).select_from(RazonFila)
            .join(VeredictoFila, VeredictoFila.id == RazonFila.veredicto_id)
            .join(MensajeAnalizadoFila, MensajeAnalizadoFila.id == VeredictoFila.mensaje_id)
            .where(propios, de_riesgo, RazonFila.mostrada.is_(True), MensajeAnalizadoFila.recibido_en >= desde)
            .group_by(RazonFila.area)).all()))
        salida["enlaces_qr"] = self._s.scalar(
            select(func.count()).select_from(EnlaceAnalizadoFila)
            .join(VeredictoFila, VeredictoFila.id == EnlaceAnalizadoFila.veredicto_id)
            .join(MensajeAnalizadoFila, MensajeAnalizadoFila.id == VeredictoFila.mensaje_id)
            .where(propios, VeredictoFila.vigente.is_(True), EnlaceAnalizadoFila.origen == "qr",
                   MensajeAnalizadoFila.recibido_en >= desde)) or 0
        salida["adjuntos_peligrosos"] = self._s.scalar(
            select(func.count()).select_from(AdjuntoAnalizadoFila)
            .join(MensajeAnalizadoFila, MensajeAnalizadoFila.id == AdjuntoAnalizadoFila.mensaje_id)
            .where(propios, AdjuntoAnalizadoFila.peligroso.is_(True), MensajeAnalizadoFila.recibido_en >= desde)) or 0
        return salida

    def por_buzon(self, desde: datetime) -> list[FilaBuzonReporte]:
        nivel = VeredictoFila.nivel
        filas = self._s.execute(
            select(BuzonFila.correo_gmail, BuzonFila.estado, func.count(MensajeAnalizadoFila.id),
                   func.count(MensajeAnalizadoFila.id).filter(nivel == NivelRiesgo.MEDIO.value),
                   func.count(MensajeAnalizadoFila.id).filter(nivel == NivelRiesgo.ALTO.value))
            .select_from(BuzonFila)
            .outerjoin(MensajeAnalizadoFila, (MensajeAnalizadoFila.buzon_id == BuzonFila.id)
                       & (MensajeAnalizadoFila.recibido_en >= desde))
            .outerjoin(VeredictoFila, (VeredictoFila.mensaje_id == MensajeAnalizadoFila.id) & VeredictoFila.vigente.is_(True))
            .group_by(BuzonFila.id).order_by(BuzonFila.correo_gmail)).all()
        return [FilaBuzonReporte(c, e, r, m, a) for c, e, r, m, a in filas]
