// Política de tratamiento de datos personales (Ley 1581 de 2012) y Términos de uso. Son públicas: se enlazan desde
// el registro y Google las exige en la pantalla de permisos de Gmail. Los datos del responsable, los plazos de
// retención y la versión vigente vienen de la API, así que el texto siempre coincide con lo que hace el servidor.

import { useQuery } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router";
import { publico } from "../api/servicios";
import type { InfoLegal } from "../api/tipos";
import { Escudo } from "../componentes/Escudo";
import { ErrorCarga, Esqueleto } from "../componentes/ui";
import { useSesion } from "../sesion/Sesion";

function MarcoLegal({ titulo, children }: { titulo: string; children: (info: InfoLegal) => ReactNode }) {
  const info = useQuery({ queryKey: ["publico", "legal"], queryFn: publico.legal, staleTime: Infinity });
  const { estado } = useSesion();
  const volver = estado.tipo === "autenticado" ? "/cuenta" : "/ingreso";
  return (
    <div className="pagina-legal">
      <header className="fila" style={{ gap: 10 }}>
        <Escudo tamano={28} /><strong>Centinela</strong>
      </header>
      <article className="tarjeta texto-legal">
        <Link to={volver} className="boton fantasma pequeno"><ArrowLeft size={14} aria-hidden /> Volver</Link>
        <h1>{titulo}</h1>
        {info.isPending && <Esqueleto filas={6} />}
        {info.isError && <ErrorCarga error={info.error} reintentar={() => void info.refetch()} />}
        {info.data && children(info.data)}
      </article>
    </div>
  );
}

function contacto(i: InfoLegal) {
  return i.correo_contacto ? <a href={`mailto:${i.correo_contacto}`}>{i.correo_contacto}</a> : "el administrador de Centinela";
}

export function PaginaPrivacidad() {
  return (
    <MarcoLegal titulo="Política de tratamiento de datos personales">
      {(i) => (
        <>
          <p className="muy-tenue">Versión {i.version_politica}. Ley 1581 de 2012 y Decreto 1074 de 2015 (Capítulo 25).</p>

          <h2>1. Responsable</h2>
          <p><strong>{i.responsable}</strong>, contacto: {contacto(i)}. Centinela es un proyecto académico (proyecto de grado)
            que detecta correos de phishing en buzones de Gmail.</p>

          <h2>2. Qué datos tratamos</h2>
          <ul>
            <li><strong>Tu cuenta:</strong> nombre, correo, contraseña (guardada solo como huella cifrada con Argon2) y, si lo
              activas, el secreto del doble factor (cifrado).</li>
            <li><strong>Tus buzones de Gmail:</strong> la dirección y el permiso que Google le da a Centinela (cifrado).</li>
            <li><strong>De cada correo que llega:</strong> remitente, asunto, fecha, resultados de autenticación (SPF, DKIM,
              DMARC), los dominios de sus enlaces, los nombres de sus adjuntos y el resultado del análisis. <strong>Nunca
              guardamos el cuerpo del correo ni los archivos adjuntos</strong>: se leen en memoria y se descartan.</li>
            <li><strong>Lo que haces en el panel:</strong> tus decisiones sobre los casos, notas, conversaciones con el
              asistente y los dispositivos donde activas notificaciones.</li>
            <li><strong>Seguridad:</strong> fecha, dirección IP y navegador de los ingresos y de las acciones importantes.</li>
          </ul>
          <p>No pedimos datos sensibles. Si un correo los contiene, Centinela no los guarda.</p>

          <h2>3. Para qué los usamos</h2>
          <ul>
            <li>Detectar correos de phishing, ponerlos en cuarentena (nunca se borran) y avisarte.</li>
            <li>Explicarte por qué un correo es riesgoso, responder tus preguntas en el asistente y generar tus reportes.</li>
            <li>Mejorar la detección con las correcciones que tú haces («es phishing» / «es legítimo»).</li>
            <li>Proteger tu cuenta y cumplir obligaciones legales.</li>
          </ul>

          <h2>4. Con quién se comparten</h2>
          <ul>
            <li><strong>Google:</strong> Gmail (lectura y etiquetas de tu buzón, con tu permiso) y, si está activo, Gemini para
              el asistente, al que solo se envían datos mínimos y anonimizados (sin direcciones de correo, enlaces completos
              ni números largos).</li>
            <li><strong>Servicios de notificaciones de tu navegador</strong> (Google, Apple, Mozilla o Microsoft): reciben el
              aviso cifrado de punta a punta, sin asunto ni remitente.</li>
            <li><strong>Microsoft Azure:</strong> aloja el servidor y la base de datos.</li>
          </ul>
          <p>Algunos de estos servidores están fuera de Colombia; al aceptar esta política autorizas esa transferencia.
            No vendemos ni cedemos tus datos a nadie más.</p>
          <p>El uso que hace Centinela de la información recibida de las API de Google cumple la <a
            href="https://developers.google.com/terms/api-services-user-data-policy" target="_blank" rel="noreferrer">Política
            de datos de usuario de los servicios de API de Google</a>, incluidos los requisitos de uso limitado.</p>

          <h2>5. Cuánto tiempo los guardamos</h2>
          <ul>
            <li>Correos sin riesgo: <strong>{i.dias_sin_riesgo} días</strong>.</li>
            <li>Casos ya cerrados: <strong>{i.dias_casos} días</strong>. Los abiertos se conservan hasta que los cierres.</li>
            <li>Sesiones vencidas: 30 días.</li>
            <li>El registro de seguridad (auditoría) se conserva para poder investigar incidentes; solo guarda tu número de
              usuario, no tus datos.</li>
          </ul>

          <h2>6. Tus derechos</h2>
          <p>Puedes conocer, actualizar, rectificar y suprimir tus datos, pedir prueba de tu autorización, saber cómo se
            usan, revocar la autorización y presentar quejas ante la Superintendencia de Industria y Comercio. Desde el
            panel puedes desconectar tus buzones (<em>Mis buzones</em>) y <strong>eliminar tu cuenta con todos tus datos</strong>{" "}
            (<em>Mi cuenta</em>). Para lo demás, escribe a {contacto(i)}: respondemos las consultas en máximo 10 días hábiles y
            los reclamos en máximo 15 días hábiles.</p>

          <h2>7. Seguridad</h2>
          <p>Conexión cifrada (HTTPS), contraseñas con Argon2, doble factor, permisos de Gmail cifrados, base de datos con
            permisos mínimos y registro de auditoría que no se puede modificar.</p>
        </>
      )}
    </MarcoLegal>
  );
}

export function PaginaTerminos() {
  return (
    <MarcoLegal titulo="Términos de uso">
      {(i) => (
        <>
          <p className="muy-tenue">Versión {i.version_politica}.</p>
          <h2>1. Qué es Centinela</h2>
          <p>Un proyecto académico que analiza los correos nuevos de los buzones de Gmail que conectes, aparta los peligrosos
            en una etiqueta de cuarentena (sin borrarlos) y te explica por qué.</p>
          <h2>2. Es una ayuda, no una garantía</h2>
          <p>Ningún sistema detecta el 100 % de los engaños ni acierta siempre. Centinela puede dejar pasar un correo
            peligroso o marcar uno legítimo. La decisión final es tuya: ante la duda, verifica por un canal oficial.</p>
          <h2>3. Tu cuenta</h2>
          <ul>
            <li>Un administrador aprueba cada cuenta. Usa una contraseña propia y, si puedes, el doble factor.</li>
            <li>Solo conecta buzones que sean tuyos o que estés autorizado a proteger.</li>
            <li>Puedes desconectar tus buzones o eliminar tu cuenta cuando quieras.</li>
          </ul>
          <h2>4. Uso aceptable</h2>
          <p>No intentes acceder a cuentas ajenas, saturar el servicio ni usar Centinela para fines distintos a protegerte
            del phishing. El administrador puede desactivar las cuentas que incumplan estos términos.</p>
          <h2>5. Datos personales</h2>
          <p>Se tratan según la <Link to="/privacidad">Política de tratamiento de datos personales</Link>.</p>
          <h2>6. Cambios y contacto</h2>
          <p>Si estos términos cambian, se publicará una nueva versión aquí. Contacto: {contacto(i)}.</p>
        </>
      )}
    </MarcoLegal>
  );
}
