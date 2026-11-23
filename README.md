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
