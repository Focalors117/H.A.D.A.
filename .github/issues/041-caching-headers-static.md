# 41. Add caching headers for static assets

Descripción

- Configurar cabeceras de caching (`Cache-Control`, `ETag`) para los activos estáticos y el build del frontend, mejorando rendimiento y reducción de ancho de banda.

Criterios de aceptación

- Cabeceras aplicadas correctamente a `public/` y a los assets generados por el build.
- Documentación sobre validación/invalidation y control de versiones para evitar servir contenido obsoleto.

Pasos sugeridos

1. Configurar el servidor para incluir `Cache-Control`/`ETag` con políticas razonables (long cache para assets versionados, no-cache para HTML).
2. Implementar versionado de assets en el proceso de build (hashes en nombres de archivo) y documentar la estrategia de invalidación.
