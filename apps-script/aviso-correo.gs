/**
 * Aviso por correo de los PDFs que suben los árbitros (Evaluación Árbitros FVBCV).
 *
 * El Worker llama a este script cada vez que se sube un PDF y el script envía el
 * correo desde la cuenta de Gmail en la que está creado.
 *
 * Puesta en marcha (una sola vez):
 *   1. https://script.google.com → Nuevo proyecto → pega este archivo entero.
 *   2. Configuración del proyecto (⚙) → Propiedades del script → añade DESTINATARIOS con el
 *      correo o correos que quieras, separados por comas.
 *   3. Ejecuta la función generarClave() (menú de arriba → Ejecutar) y acepta los permisos.
 *      En «Registro de ejecución» sale la clave: cópiala.
 *   4. Implementar → Nueva implementación → tipo «Aplicación web»:
 *        Ejecutar como: Yo · Quién tiene acceso: Cualquier usuario → Implementar.
 *      Copia la URL que acaba en /exec.
 *   5. En la carpeta worker del repo:
 *        npx wrangler secret put NOTIFY_WEBHOOK_URL -c wrangler.toml      (pega la URL /exec)
 *        npx wrangler secret put NOTIFY_WEBHOOK_SECRET -c wrangler.toml   (pega la clave)
 *   6. Opcional: ejecuta probarEnvio() para comprobar que te llega un correo.
 *
 * Para cambiar a quién llega: Configuración del proyecto (⚙) → Propiedades del script →
 * edita DESTINATARIOS y guarda. Se aplica al momento: no hace falta volver a implementar
 * ni tocar Cloudflare. (Si cambias el CÓDIGO, sí: Implementar → Gestionar implementaciones →
 * editar → Versión: nueva.)
 */

// Solo se usa si no existe la propiedad del script DESTINATARIOS
const DESTINATARIOS_POR_DEFECTO = 'gabrielarnedo725@gmail.com';
const NOMBRE_REMITENTE = 'Evaluaciones FVBCV';

function doPost(e) {
  try {
    const body = JSON.parse((e && e.postData && e.postData.contents) || '{}');
    const clave = PropertiesService.getScriptProperties().getProperty('CLAVE');
    if (!clave || body.secret !== clave) return respuesta_({ ok: false, error: 'no autorizado' });
    if (!body.subject || !body.html) return respuesta_({ ok: false, error: 'faltan datos' });
    enviar_(String(body.subject).slice(0, 180), String(body.html));
    return respuesta_({ ok: true });
  } catch (err) {
    return respuesta_({ ok: false, error: String(err) });
  }
}

function enviar_(asunto, html) {
  MailApp.sendEmail({
    to: PropertiesService.getScriptProperties().getProperty('DESTINATARIOS') || DESTINATARIOS_POR_DEFECTO,
    subject: asunto,
    htmlBody: html,
    name: NOMBRE_REMITENTE,
  });
}

function respuesta_(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}

/** Crea (o recupera) la clave compartida con el Worker y la muestra en el registro. */
function generarClave() {
  const props = PropertiesService.getScriptProperties();
  let clave = props.getProperty('CLAVE');
  if (!clave) {
    clave = Utilities.getUuid().replace(/-/g, '') + Utilities.getUuid().replace(/-/g, '');
    props.setProperty('CLAVE', clave);
  }
  Logger.log('Clave para NOTIFY_WEBHOOK_SECRET: ' + clave);
}

/** Envía un correo de prueba a los destinatarios configurados. */
function probarEnvio() {
  enviar_('Prueba: aviso de PDFs FVBCV', '<p>Si lees esto, el aviso por correo funciona.</p>');
}
