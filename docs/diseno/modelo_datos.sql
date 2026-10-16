-- =====================================================================
-- CENTINELA · Modelo de datos (PostgreSQL 16)
-- Detección de phishing en correos de Gmail para usuarios en Colombia.
--
-- Principios:
--   * La BD garantiza la INTEGRIDAD (tipos, llaves, unicidad, rangos).
--     El dominio de la aplicación garantiza las REGLAS DE NEGOCIO.
--   * Privacidad: NUNCA se guarda el cuerpo de un correo ni URLs completas.
--   * Secretos (token OAuth, semilla TOTP) cifrados en la aplicación;
--     la llave vive fuera de la BD. Contraseñas y tokens de sesión: solo hash.
--   * Fechas en timestamptz (UTC). Llaves: identity (estándar SQL).
-- Este script es el diseño de referencia; en desarrollo se aplica con Alembic.
-- =====================================================================
BEGIN;

CREATE SCHEMA IF NOT EXISTS centinela;
SET search_path TO centinela;

-- ---------------------------------------------------------------------
-- Tipos enumerados
-- ---------------------------------------------------------------------
CREATE TYPE rol_usuario       AS ENUM ('administrador', 'usuario');
CREATE TYPE estado_cuenta     AS ENUM ('pendiente', 'activo', 'rechazado', 'desactivado');
CREATE TYPE estado_buzon      AS ENUM ('activo', 'pausado', 'revocado', 'error');
CREATE TYPE modo_cuarentena   AS ENUM ('solo_avisar', 'cuarentena_automatica');
CREATE TYPE resultado_auth    AS ENUM ('pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror');
CREATE TYPE nivel_riesgo      AS ENUM ('bajo', 'medio', 'alto');
CREATE TYPE area_razon        AS ENUM ('remitente', 'autenticacion', 'suplantacion', 'contenido', 'enlace', 'adjunto');
CREATE TYPE gravedad          AS ENUM ('baja', 'media', 'alta');
CREATE TYPE tipo_modelo       AS ENUM ('contenido', 'enlaces');
CREATE TYPE categoria_entidad AS ENUM ('banco', 'billetera_digital', 'gobierno', 'logistica', 'comercio',
                                       'telecomunicaciones', 'servicios_publicos', 'educacion', 'otro');
CREATE TYPE estado_caso       AS ENUM ('nuevo', 'en_cuarentena', 'liberado', 'confirmado', 'falso_positivo');
CREATE TYPE tipo_evento_caso  AS ENUM ('creado', 'cuarentena', 'aviso', 'liberado', 'confirmado',
                                       'falso_positivo', 'reabierto', 'nota');
CREATE TYPE etiqueta_usuario  AS ENUM ('phishing', 'legitimo');
CREATE TYPE canal_aviso       AS ENUM ('correo', 'push');
CREATE TYPE estado_aviso      AS ENUM ('pendiente', 'enviado', 'fallido');
CREATE TYPE rol_chat          AS ENUM ('usuario', 'asistente');
CREATE TYPE proveedor_ia      AS ENUM ('gemini', 'local');

-- Mantiene actualizado_en en cada UPDATE
CREATE FUNCTION fijar_actualizado_en() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.actualizado_en := now();
    RETURN NEW;
END $$;

-- =====================================================================
-- 1. IDENTIDAD Y ACCESO
-- =====================================================================
CREATE TABLE usuario (
    id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    correo                text          NOT NULL UNIQUE,
    nombre                text          NOT NULL,
    clave_hash            text          NOT NULL,                 -- argon2id
    rol                   rol_usuario   NOT NULL DEFAULT 'usuario',
    estado                estado_cuenta NOT NULL DEFAULT 'pendiente',
    totp_secreto_cifrado  bytea,                                  -- cifrado en la app (Fernet)
    totp_activo           boolean       NOT NULL DEFAULT false,
    totp_ultimo_paso      bigint,                                 -- impide reutilizar un código TOTP
    intentos_fallidos     smallint      NOT NULL DEFAULT 0,
    bloqueado_hasta       timestamptz,
    aprobado_por          bigint        REFERENCES usuario (id) ON DELETE SET NULL,
    aprobado_en           timestamptz,
    ultimo_acceso         timestamptz,
    creado_en             timestamptz   NOT NULL DEFAULT now(),
    actualizado_en        timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT usuario_correo_valido   CHECK (correo = lower(correo) AND correo ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
    CONSTRAINT usuario_nombre_valido   CHECK (length(btrim(nombre)) BETWEEN 2 AND 120),
    CONSTRAINT usuario_totp_coherente  CHECK (NOT totp_activo OR totp_secreto_cifrado IS NOT NULL),
    CONSTRAINT usuario_intentos_validos CHECK (intentos_fallidos >= 0)
);
CREATE TRIGGER usuario_actualizado BEFORE UPDATE ON usuario
    FOR EACH ROW EXECUTE FUNCTION fijar_actualizado_en();

-- Códigos de un solo uso para recuperar el acceso si se pierde el 2FA
CREATE TABLE codigo_recuperacion (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    usuario_id   bigint      NOT NULL REFERENCES usuario (id) ON DELETE CASCADE,
    codigo_hash  text        NOT NULL,
    usado_en     timestamptz,
    creado_en    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX codigo_recuperacion_usuario_idx ON codigo_recuperacion (usuario_id) WHERE usado_en IS NULL;

-- Sesiones (token de renovación). Solo se guarda el SHA-256 del token.
CREATE TABLE sesion (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    usuario_id    bigint      NOT NULL REFERENCES usuario (id) ON DELETE CASCADE,
    token_hash    bytea       NOT NULL UNIQUE,
    ip            inet,
    agente        text,
    creada_en     timestamptz NOT NULL DEFAULT now(),
    expira_en     timestamptz NOT NULL,
    revocada_en   timestamptz,
    CONSTRAINT sesion_hash_sha256 CHECK (octet_length(token_hash) = 32),
    CONSTRAINT sesion_vigencia    CHECK (expira_en > creada_en)
);
CREATE INDEX sesion_usuario_activa_idx ON sesion (usuario_id) WHERE revocada_en IS NULL;

-- =====================================================================
-- 2. BUZONES DE GMAIL CONECTADOS (OAuth2)
-- =====================================================================
CREATE TABLE buzon (
    id                      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    usuario_id              bigint          NOT NULL REFERENCES usuario (id) ON DELETE RESTRICT,
    correo_gmail            text            NOT NULL UNIQUE,
    refresh_token_cifrado   bytea,                                 -- NULL cuando se revoca
    alcances                text[]          NOT NULL DEFAULT '{}',
    estado                  estado_buzon    NOT NULL DEFAULT 'activo',
    modo                    modo_cuarentena NOT NULL DEFAULT 'cuarentena_automatica',
    avisar_por_correo       boolean         NOT NULL DEFAULT true,
    ultimo_history_id       numeric(20, 0),                        -- historyId de Gmail es uint64
    etiqueta_cuarentena_id  text,
    etiqueta_sospechoso_id  text,
    ultima_revision_en      timestamptz,
    errores_consecutivos    smallint        NOT NULL DEFAULT 0,
    ultimo_error            text,
    conectado_en            timestamptz     NOT NULL DEFAULT now(),
    desconectado_en         timestamptz,
    creado_en               timestamptz     NOT NULL DEFAULT now(),
    actualizado_en          timestamptz     NOT NULL DEFAULT now(),
    CONSTRAINT buzon_correo_valido   CHECK (correo_gmail = lower(correo_gmail)),
    CONSTRAINT buzon_activo_con_token CHECK (estado <> 'activo' OR refresh_token_cifrado IS NOT NULL),
    CONSTRAINT buzon_history_valido  CHECK (ultimo_history_id IS NULL OR ultimo_history_id >= 0),
    CONSTRAINT buzon_errores_validos CHECK (errores_consecutivos >= 0)
);
CREATE INDEX buzon_usuario_idx ON buzon (usuario_id);
CREATE INDEX buzon_activos_idx ON buzon (ultima_revision_en NULLS FIRST) WHERE estado = 'activo';
CREATE TRIGGER buzon_actualizado BEFORE UPDATE ON buzon
    FOR EACH ROW EXECUTE FUNCTION fijar_actualizado_en();

-- =====================================================================
-- 3. CONOCIMIENTO: MODELOS DE ML Y ENTIDADES COLOMBIANAS
-- =====================================================================
-- Registro de modelos: cada veredicto queda ligado a la versión que lo produjo
CREATE TABLE modelo_ml (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tipo            tipo_modelo   NOT NULL,
    nombre          text          NOT NULL,
    version         text          NOT NULL,
    ruta_artefacto  text          NOT NULL,
    sha256          char(64)      NOT NULL,
    dataset         text          NOT NULL,
    metricas        jsonb         NOT NULL DEFAULT '{}',
    umbral_medio    numeric(4, 3) NOT NULL,
    umbral_alto     numeric(4, 3) NOT NULL,
    activo          boolean       NOT NULL DEFAULT false,
    creado_en       timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT modelo_version_unica UNIQUE (tipo, version),
    CONSTRAINT modelo_sha256_hex    CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT modelo_umbrales      CHECK (0 < umbral_medio AND umbral_medio < umbral_alto AND umbral_alto < 1)
);
-- Solo un modelo activo por tipo
CREATE UNIQUE INDEX modelo_un_activo_por_tipo ON modelo_ml (tipo) WHERE activo;

-- Catálogo de entidades que más se suplantan en Colombia (editable por el administrador)
CREATE TABLE entidad_suplantada (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    nombre          text              NOT NULL UNIQUE,
    categoria       categoria_entidad NOT NULL,
    alias           text[]            NOT NULL DEFAULT '{}',     -- formas en que aparece en el texto
    activa          boolean           NOT NULL DEFAULT true,
    creado_en       timestamptz       NOT NULL DEFAULT now(),
    actualizado_en  timestamptz       NOT NULL DEFAULT now()
);
CREATE TRIGGER entidad_actualizada BEFORE UPDATE ON entidad_suplantada
    FOR EACH ROW EXECUTE FUNCTION fijar_actualizado_en();

CREATE TABLE dominio_oficial (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    entidad_id  bigint NOT NULL REFERENCES entidad_suplantada (id) ON DELETE CASCADE,
    dominio     text   NOT NULL UNIQUE,
    CONSTRAINT dominio_valido CHECK (dominio = lower(dominio) AND dominio ~ '^[a-z0-9.-]+\.[a-z]{2,}$')
);
CREATE INDEX dominio_oficial_entidad_idx ON dominio_oficial (entidad_id);

-- =====================================================================
-- 4. ANÁLISIS DE CORREOS (sin cuerpo del mensaje)
-- =====================================================================
CREATE TABLE mensaje_analizado (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    buzon_id             bigint         NOT NULL REFERENCES buzon (id) ON DELETE CASCADE,
    gmail_id             text           NOT NULL,
    gmail_hilo_id        text,
    message_id_rfc       text,
    remitente_correo     text,
    remitente_nombre     text,
    remitente_dominio    text,                       -- derivado; se guarda para filtrar y agregar
    responder_a_dominio  text,
    asunto               text,
    recibido_en          timestamptz    NOT NULL,
    analizado_en         timestamptz    NOT NULL DEFAULT now(),
    idioma               text           NOT NULL DEFAULT 'es',
    tamano_bytes         integer,
    n_enlaces            smallint       NOT NULL DEFAULT 0,
    n_adjuntos           smallint       NOT NULL DEFAULT 0,
    spf                  resultado_auth,
    dkim                 resultado_auth,
    dmarc                resultado_auth,
    -- Idempotencia: el mismo correo nunca se analiza dos veces en el mismo buzón
    CONSTRAINT mensaje_unico_por_buzon UNIQUE (buzon_id, gmail_id),
    CONSTRAINT mensaje_idioma_valido   CHECK (idioma IN ('es', 'en', 'otro')),
    CONSTRAINT mensaje_asunto_largo    CHECK (asunto IS NULL OR length(asunto) <= 500),
    CONSTRAINT mensaje_conteos         CHECK (n_enlaces >= 0 AND n_adjuntos >= 0 AND (tamano_bytes IS NULL OR tamano_bytes >= 0))
);
CREATE INDEX mensaje_buzon_fecha_idx ON mensaje_analizado (buzon_id, recibido_en DESC);
CREATE INDEX mensaje_remitente_dominio_idx ON mensaje_analizado (remitente_dominio);

CREATE TABLE adjunto_analizado (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mensaje_id    bigint   NOT NULL REFERENCES mensaje_analizado (id) ON DELETE CASCADE,
    nombre        text     NOT NULL,
    extension     text,
    tipo_mime     text,
    tamano_bytes  integer  CHECK (tamano_bytes IS NULL OR tamano_bytes >= 0),
    sha256        char(64) CHECK (sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'),
    peligroso     boolean  NOT NULL DEFAULT false,
    motivo        text
);
CREATE INDEX adjunto_mensaje_idx ON adjunto_analizado (mensaje_id);

-- Un mensaje puede re-analizarse con una versión nueva del modelo; solo un veredicto es el vigente
CREATE TABLE veredicto (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mensaje_id           bigint        NOT NULL REFERENCES mensaje_analizado (id) ON DELETE CASCADE,
    modelo_contenido_id  bigint        REFERENCES modelo_ml (id) ON DELETE RESTRICT,
    modelo_enlaces_id    bigint        REFERENCES modelo_ml (id) ON DELETE RESTRICT,
    p_contenido          numeric(5, 4),
    p_enlaces            numeric(5, 4),
    p_tecnico            numeric(5, 4),
    p_final              numeric(5, 4) NOT NULL,
    nivel                nivel_riesgo  NOT NULL,
    resumen              text          NOT NULL,
    tiempo_ms            integer,
    vigente              boolean       NOT NULL DEFAULT true,
    creado_en            timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT veredicto_probabilidades CHECK (
        p_final BETWEEN 0 AND 1
        AND (p_contenido IS NULL OR p_contenido BETWEEN 0 AND 1)
        AND (p_enlaces   IS NULL OR p_enlaces   BETWEEN 0 AND 1)
        AND (p_tecnico   IS NULL OR p_tecnico   BETWEEN 0 AND 1)),
    CONSTRAINT veredicto_tiempo CHECK (tiempo_ms IS NULL OR tiempo_ms >= 0)
);
CREATE UNIQUE INDEX veredicto_un_vigente ON veredicto (mensaje_id) WHERE vigente;
CREATE INDEX veredicto_nivel_idx ON veredicto (nivel) WHERE vigente;
CREATE INDEX veredicto_modelo_contenido_idx ON veredicto (modelo_contenido_id);
CREATE INDEX veredicto_modelo_enlaces_idx ON veredicto (modelo_enlaces_id);

-- Todas las razones calculadas; "mostrada" marca las (máx. 3) que ve el usuario
CREATE TABLE razon (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    veredicto_id  bigint        NOT NULL REFERENCES veredicto (id) ON DELETE CASCADE,
    orden         smallint      NOT NULL,
    area          area_razon    NOT NULL,
    gravedad      gravedad      NOT NULL,
    aporte        numeric(6, 4),                     -- contribución al riesgo (puede ser negativa)
    texto         text          NOT NULL,
    mostrada      boolean       NOT NULL DEFAULT false,
    entidad_id    bigint        REFERENCES entidad_suplantada (id) ON DELETE SET NULL,
    CONSTRAINT razon_orden_unico UNIQUE (veredicto_id, orden),
    CONSTRAINT razon_orden_valido CHECK (orden >= 1)
);
CREATE INDEX razon_entidad_idx ON razon (entidad_id) WHERE entidad_id IS NOT NULL;

-- Promesa del producto: como máximo 3 razones visibles por veredicto
CREATE FUNCTION validar_max_razones() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.mostrada AND (SELECT count(*) FROM razon
                         WHERE veredicto_id = NEW.veredicto_id AND mostrada AND id <> NEW.id) >= 3 THEN
        RAISE EXCEPTION 'Un veredicto no puede mostrar más de 3 razones (veredicto %)', NEW.veredicto_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER razon_max_mostradas BEFORE INSERT OR UPDATE OF mostrada ON razon
    FOR EACH ROW EXECUTE FUNCTION validar_max_razones();

-- Enlaces: solo dominio + hash de la URL (la URL completa puede contener datos personales)
CREATE TABLE enlace_analizado (
    id                     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    veredicto_id           bigint        NOT NULL REFERENCES veredicto (id) ON DELETE CASCADE,
    dominio                text          NOT NULL,
    url_sha256             char(64)      NOT NULL CHECK (url_sha256 ~ '^[0-9a-f]{64}$'),
    dominio_texto_visible  text,                       -- el que muestra el texto del enlace
    probabilidad           numeric(5, 4) CHECK (probabilidad IS NULL OR probabilidad BETWEEN 0 AND 1),
    nivel                  nivel_riesgo,
    es_acortador           boolean       NOT NULL DEFAULT false,
    enganoso               boolean       NOT NULL DEFAULT false
);
CREATE INDEX enlace_veredicto_idx ON enlace_analizado (veredicto_id);
CREATE INDEX enlace_dominio_idx ON enlace_analizado (dominio);

-- =====================================================================
-- 5. GESTIÓN: CASOS, CUARENTENA, AVISOS Y RETROALIMENTACIÓN
-- =====================================================================
-- Se abre un caso para cada mensaje con riesgo medio o alto
CREATE TABLE caso (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mensaje_id      bigint      NOT NULL UNIQUE REFERENCES mensaje_analizado (id) ON DELETE CASCADE,
    estado          estado_caso NOT NULL DEFAULT 'nuevo',
    creado_en       timestamptz NOT NULL DEFAULT now(),
    actualizado_en  timestamptz NOT NULL DEFAULT now(),
    cerrado_en      timestamptz,
    CONSTRAINT caso_cierre_coherente CHECK ((cerrado_en IS NULL) = (estado IN ('nuevo', 'en_cuarentena')))
);
CREATE INDEX caso_abiertos_idx ON caso (estado, creado_en DESC) WHERE estado IN ('nuevo', 'en_cuarentena');
CREATE TRIGGER caso_actualizado BEFORE UPDATE ON caso
    FOR EACH ROW EXECUTE FUNCTION fijar_actualizado_en();

-- Historial del caso: solo se agregan filas (bitácora)
CREATE TABLE evento_caso (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    caso_id          bigint           NOT NULL REFERENCES caso (id) ON DELETE CASCADE,
    tipo             tipo_evento_caso NOT NULL,
    estado_anterior  estado_caso,
    estado_nuevo     estado_caso,
    autor_id         bigint           REFERENCES usuario (id) ON DELETE SET NULL,   -- NULL = el sistema
    detalle          text,
    creado_en        timestamptz      NOT NULL DEFAULT now()
);
CREATE INDEX evento_caso_idx ON evento_caso (caso_id, creado_en);
CREATE INDEX evento_autor_idx ON evento_caso (autor_id) WHERE autor_id IS NOT NULL;

-- Bandeja de salida de avisos: el worker los envía y reintenta (patrón outbox)
CREATE TABLE aviso (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    caso_id             bigint       NOT NULL REFERENCES caso (id) ON DELETE CASCADE,
    canal               canal_aviso  NOT NULL,
    destino             text         NOT NULL,
    estado              estado_aviso NOT NULL DEFAULT 'pendiente',
    intentos            smallint     NOT NULL DEFAULT 0 CHECK (intentos >= 0),
    proximo_intento_en  timestamptz  NOT NULL DEFAULT now(),
    enviado_en          timestamptz,
    referencia_externa  text,                      -- id del mensaje de aviso en Gmail
    ultimo_error        text,
    creado_en           timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT aviso_envio_coherente CHECK ((estado = 'enviado') = (enviado_en IS NOT NULL)),
    CONSTRAINT aviso_unico_por_canal UNIQUE (caso_id, canal)
);
CREATE INDEX aviso_pendientes_idx ON aviso (proximo_intento_en) WHERE estado = 'pendiente';

-- Etiqueta que da el usuario. Solo las validadas por un administrador alimentan el reentrenamiento.
CREATE TABLE retroalimentacion (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mensaje_id     bigint           NOT NULL REFERENCES mensaje_analizado (id) ON DELETE CASCADE,
    usuario_id     bigint           NOT NULL REFERENCES usuario (id) ON DELETE CASCADE,
    etiqueta       etiqueta_usuario NOT NULL,
    comentario     text,
    validada_por   bigint           REFERENCES usuario (id) ON DELETE RESTRICT,  -- usuarios se desactivan, no se borran
    validada_en    timestamptz,
    creado_en      timestamptz      NOT NULL DEFAULT now(),
    CONSTRAINT retro_una_por_usuario UNIQUE (mensaje_id, usuario_id),
    CONSTRAINT retro_validacion_coherente CHECK ((validada_en IS NULL) = (validada_por IS NULL))
);
CREATE INDEX retro_usuario_idx ON retroalimentacion (usuario_id);
CREATE INDEX retro_por_validar_idx ON retroalimentacion (creado_en) WHERE validada_en IS NULL;

-- =====================================================================
-- 6. ASISTENTE DE IA
-- =====================================================================
CREATE TABLE conversacion (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    usuario_id      bigint      NOT NULL REFERENCES usuario (id) ON DELETE CASCADE,
    mensaje_id      bigint      REFERENCES mensaje_analizado (id) ON DELETE SET NULL,  -- si se abrió desde un correo
    titulo          text,
    creado_en       timestamptz NOT NULL DEFAULT now(),
    actualizado_en  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX conversacion_usuario_idx ON conversacion (usuario_id, actualizado_en DESC);
CREATE INDEX conversacion_mensaje_idx ON conversacion (mensaje_id) WHERE mensaje_id IS NOT NULL;
CREATE TRIGGER conversacion_actualizada BEFORE UPDATE ON conversacion
    FOR EACH ROW EXECUTE FUNCTION fijar_actualizado_en();

CREATE TABLE turno_chat (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    conversacion_id  bigint       NOT NULL REFERENCES conversacion (id) ON DELETE CASCADE,
    rol              rol_chat     NOT NULL,
    contenido        text         NOT NULL CHECK (length(contenido) BETWEEN 1 AND 8000),
    proveedor        proveedor_ia,
    creado_en        timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT turno_proveedor_coherente CHECK ((rol = 'asistente') = (proveedor IS NOT NULL))
);
CREATE INDEX turno_conversacion_idx ON turno_chat (conversacion_id, creado_en);

-- =====================================================================
-- 7. CONFIGURACIÓN Y AUDITORÍA
-- =====================================================================
CREATE TABLE configuracion (
    clave           text        PRIMARY KEY CHECK (clave ~ '^[a-z_]+(\.[a-z_]+)*$'),
    valor           jsonb       NOT NULL,
    descripcion     text        NOT NULL,
    actualizado_por bigint      REFERENCES usuario (id) ON DELETE SET NULL,
    actualizado_en  timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER configuracion_actualizada BEFORE UPDATE ON configuracion
    FOR EACH ROW EXECUTE FUNCTION fijar_actualizado_en();

-- Bitácora inmutable (Ley 1581 de 2012). Sin llaves foráneas a propósito:
-- debe conservarse aunque se borren usuarios o mensajes por retención.
CREATE TABLE auditoria (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ocurrido_en  timestamptz NOT NULL DEFAULT now(),
    usuario_id   bigint,
    accion       text        NOT NULL,   -- ej.: 'sesion.inicio', 'caso.liberar', 'buzon.conectar'
    objeto_tipo  text,
    objeto_id    text,
    exito        boolean     NOT NULL DEFAULT true,
    ip           inet,
    detalle      jsonb       NOT NULL DEFAULT '{}'
);
CREATE INDEX auditoria_fecha_idx ON auditoria (ocurrido_en DESC);
CREATE INDEX auditoria_usuario_idx ON auditoria (usuario_id, ocurrido_en DESC);

CREATE FUNCTION auditoria_inmutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'La auditoría no se puede modificar ni borrar' USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER auditoria_sin_cambios BEFORE UPDATE OR DELETE ON auditoria
    FOR EACH ROW EXECUTE FUNCTION auditoria_inmutable();

-- =====================================================================
-- 8. VISTAS PARA EL PANEL Y LA TESIS
-- =====================================================================
-- Resumen por usuario de los últimos 30 días
CREATE VIEW v_resumen_usuario AS
SELECT b.usuario_id,
       count(*)                                                 AS analizados,
       count(*) FILTER (WHERE v.nivel = 'alto')                 AS riesgo_alto,
       count(*) FILTER (WHERE v.nivel = 'medio')                AS riesgo_medio,
       count(c.id) FILTER (WHERE c.estado = 'en_cuarentena')    AS en_cuarentena,
       round(avg(v.tiempo_ms))                                  AS tiempo_medio_ms
FROM mensaje_analizado m
JOIN buzon b      ON b.id = m.buzon_id
JOIN veredicto v  ON v.mensaje_id = m.id AND v.vigente
LEFT JOIN caso c  ON c.mensaje_id = m.id
WHERE m.recibido_en >= now() - interval '30 days'
GROUP BY b.usuario_id;

-- Entidades colombianas más suplantadas
CREATE VIEW v_entidades_suplantadas AS
SELECT e.nombre, e.categoria, count(DISTINCT v.mensaje_id) AS correos
FROM razon r
JOIN veredicto v           ON v.id = r.veredicto_id AND v.vigente
JOIN entidad_suplantada e  ON e.id = r.entidad_id
WHERE r.area = 'suplantacion'
GROUP BY e.nombre, e.categoria
ORDER BY correos DESC;

-- Precisión observada en producción, según lo que deciden los usuarios
CREATE VIEW v_precision_produccion AS
SELECT count(*) FILTER (WHERE estado = 'confirmado')                       AS verdaderos_positivos,
       count(*) FILTER (WHERE estado IN ('falso_positivo', 'liberado'))    AS falsos_positivos,
       round(count(*) FILTER (WHERE estado = 'confirmado')::numeric
             / NULLIF(count(*) FILTER (WHERE estado IN ('confirmado', 'falso_positivo', 'liberado')), 0), 4)
                                                                          AS precision
FROM caso;

-- =====================================================================
-- 9. DATOS INICIALES
-- =====================================================================
INSERT INTO configuracion (clave, valor, descripcion) VALUES
    ('analisis.intervalo_sondeo_s',  '30',   'Segundos entre revisiones de cada buzón'),
    ('politica.nivel_cuarentena',    '"alto"', 'Nivel de riesgo a partir del cual se pone en cuarentena'),
    ('retencion.dias_bajo_riesgo',   '30',   'Días que se guardan los análisis de riesgo bajo'),
    ('retencion.dias_casos',         '365',  'Días que se guardan los casos cerrados'),
    ('asistente.max_preguntas_dia',  '30',   'Preguntas al asistente por usuario y día'),
    ('seguridad.max_intentos',       '5',    'Intentos fallidos antes de bloquear la cuenta'),
    ('seguridad.minutos_bloqueo',    '15',   'Minutos de bloqueo tras superar los intentos');

WITH e AS (
    INSERT INTO entidad_suplantada (nombre, categoria, alias) VALUES
        ('DIAN',                       'gobierno',           '{dian,"impuestos y aduanas"}'),
        ('Registraduría',              'gobierno',           '{registraduria,"registraduría nacional"}'),
        ('Policía Nacional',           'gobierno',           '{"policia nacional","policía nacional"}'),
        ('Fiscalía',                   'gobierno',           '{fiscalia,fiscalía}'),
        ('Colpensiones',               'gobierno',           '{colpensiones}'),
        ('SENA',                       'educacion',          '{sena}'),
        ('MinTIC',                     'gobierno',           '{mintic}'),
        ('Superintendencia de Industria y Comercio', 'gobierno', '{sic,"superintendencia de industria"}'),
        ('Superintendencia Financiera', 'gobierno',          '{superfinanciera,"superintendencia financiera"}'),
        ('Servientrega',               'logistica',          '{servientrega}'),
        ('Interrapidísimo',            'logistica',          '{interrapidisimo,interrapidísimo}'),
        ('Coordinadora',               'logistica',          '{coordinadora}'),
        ('EPM',                        'servicios_publicos', '{epm,"empresas publicas de medellin"}'),
        ('Mercado Libre',              'comercio',           '{"mercado libre",mercadolibre}'),
        ('Rappi',                      'comercio',           '{rappi}'),
        ('Davivienda',                 'banco',              '{davivienda}'),
        ('Bancolombia',                'banco',              '{bancolombia}'),
        ('Nequi',                      'billetera_digital',  '{nequi}')
    RETURNING id, nombre
)
INSERT INTO dominio_oficial (entidad_id, dominio)
SELECT e.id, d.dominio
FROM e
JOIN (VALUES
    ('DIAN', 'dian.gov.co'), ('Registraduría', 'registraduria.gov.co'), ('Policía Nacional', 'policia.gov.co'),
    ('Fiscalía', 'fiscalia.gov.co'), ('Colpensiones', 'colpensiones.gov.co'), ('SENA', 'sena.edu.co'),
    ('MinTIC', 'mintic.gov.co'), ('Superintendencia de Industria y Comercio', 'sic.gov.co'),
    ('Superintendencia Financiera', 'superfinanciera.gov.co'), ('Servientrega', 'servientrega.com'),
    ('Interrapidísimo', 'interrapidisimo.com'), ('Coordinadora', 'coordinadora.com'), ('EPM', 'epm.com.co'),
    ('Mercado Libre', 'mercadolibre.com'), ('Mercado Libre', 'mercadolibre.com.co'),
    ('Rappi', 'rappi.com'), ('Rappi', 'rappi.com.co'), ('Davivienda', 'davivienda.com'),
    ('Bancolombia', 'bancolombia.com'), ('Bancolombia', 'grupobancolombia.com'),
    ('Nequi', 'nequi.com.co'), ('Nequi', 'nequi.com')
) AS d (entidad, dominio) ON d.entidad = e.nombre;

COMMIT;

-- ---------------------------------------------------------------------
-- Permisos recomendados en despliegue (se ejecutan como superusuario):
--   CREATE ROLE centinela_app LOGIN PASSWORD '...';
--   GRANT USAGE ON SCHEMA centinela TO centinela_app;
--   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA centinela TO centinela_app;
--   GRANT USAGE ON ALL SEQUENCES IN SCHEMA centinela TO centinela_app;
--   REVOKE UPDATE, DELETE ON centinela.auditoria FROM centinela_app;
-- La aplicación nunca se conecta como dueña del esquema.
-- ---------------------------------------------------------------------
