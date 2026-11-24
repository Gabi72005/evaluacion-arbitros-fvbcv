# Evaluación Árbitros FVBCV

App web móvil para evaluar a árbitros aspirantes de voleibol (1º árbitro, 2º árbitro y anotador) con la plantilla de examinador de la Federación de Voleibol de la Comunitat Valenciana (FVBCV) y generar el informe en PDF.

## Estructura

- `index.html` — la app completa en un solo archivo (HTML + CSS + JS). Lleva incrustados `pdf-lib` y los recursos de la plantilla/membrete de la FVBCV, por eso pesa ~850 KB.
- El comentario `<!--PWA_HEAD-->` del `<head>` es el punto donde se inyectan el `manifest.json` y el registro del service worker en la versión PWA instalable.

## Funcionalidad

- **Inicio:** nombre del examinador (se guarda en `localStorage`) e historial de evaluaciones (borradores, regenerar PDF, borrar).
- **Datos:** rol evaluado, aspirante (con autocompletado y detección de evaluaciones previas del mismo aspirante), nº de evaluación (1ª, 2ª…), partido, categoría + género (desplegable), nivel Alto/Medio/Bajo (desplegable) y fecha.
- **Antes / Durante / Después:** cada ítem con APTO / NO APTO y observación; botón para marcar lo pendiente como APTO; contador por bloque; autoguardado.
- **Final:** resumen por bloque frente al mínimo de aptos de la plantilla, resultado global (supera solo si llega al mínimo en los tres bloques) y comentarios generales amplios.
- **PDF:** se genera sobre la hoja con membrete de la FVBCV; las observaciones van debajo de cada ítem y la fila crece si hace falta; sección final grande con tabla resumen. Sin bloque de firma. El botón primero descarga el PDF y luego ofrece "Compartir".

## Uso local

Abre `index.html` en el navegador, o sírvela con cualquier servidor estático:

```bash
python3 -m http.server 8000
```

Los datos se guardan solo en el navegador/dispositivo donde se usa.

## Origen

Versión publicada en Claude: https://claude.ai/artifact/3MRLptUfkEszo8PoibhbLy (última actualización: 9 nov 2026).

## Envío de PDFs a la federación (rama preparada, sin activar)

> Esta funcionalidad vive solo en la rama `claude/busy-ramanujan-iv7aw8`. No está en `main` ni desplegada.

**Qué hace**

- **Árbitro:** en la pestaña *Final*, una vez descargado el PDF, aparece **«📤 Enviar PDF a la FVBCV»**. El PDF se sube al Worker y queda archivado. Si reenvía la misma evaluación, se sustituye la anterior y se le indica «hay cambios» si la ha modificado tras enviarla.
- **Admin:** nueva pestaña **PDFs** en el panel, con un banner «🔔 N PDFs nuevos», un contador en la pestaña y otro en el título del navegador. Se comprueba cada 5 min mientras el panel está abierto. Puede buscar, filtrar *Nuevos*, seleccionar los PDFs que quiera (o todos) y **descargarlos en un ZIP**, uno a uno, marcarlos como vistos o eliminarlos. En *Actividad* aparecen como «Enviado».
- **Aviso por correo:** cada subida manda un email a la admin a través de [Resend](https://resend.com) (gratis, 3.000 correos/mes). Es opcional: sin configurarlo, todo lo demás funciona igual.

**Cómo funciona (todo gratis)**

- Los PDFs se guardan en el mismo **Cloudflare KV** (`EVAL_KV`) que ya usa la app: `up:<id>` (bytes + datos) y `upn:<id>` (marca de "nuevo"). Se conservan 1 año. Límite de 5 MB por PDF y 10 envíos cada 15 min por árbitro.
- El ZIP se genera en el navegador de la admin con **JSZip 3.10.1**, alojado en `vendor/jszip.min.js` (no depende de ninguna CDN).
- Endpoints nuevos del Worker: `POST /upload/pdf` (sesión del árbitro) y `GET /admin/uploads`, `GET /admin/uploads/file?id=`, `POST /admin/uploads/seen`, `POST /admin/uploads/delete` (token de admin).

**Para activarlo cuando se quiera**

1. Fusionar esta rama en `main` y desplegar el Worker (`cd worker && npx wrangler deploy`) y la web.
2. (Opcional, aviso por correo) Crear una cuenta gratuita en Resend **con el correo de la admin**, generar una API key y ejecutar:
   ```bash
   cd worker
   npx wrangler secret put RESEND_API_KEY
   npx wrangler secret put NOTIFY_EMAIL      # el mismo correo de la cuenta de Resend
   npx wrangler secret put ADMIN_URL         # p. ej. https://evaluacion-arbitros-fvbcv.pages.dev/admin
   ```
   Sin dominio propio, Resend envía desde `onboarding@resend.dev` y **solo al correo con el que se creó la cuenta**, que es justo el de la admin. Con un dominio verificado se puede fijar `NOTIFY_FROM`.
3. Actualizar las guías PDF (árbitros y administración) con el nuevo botón y la pestaña PDFs.
