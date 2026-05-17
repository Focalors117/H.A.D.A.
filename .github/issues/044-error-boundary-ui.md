# 44. Add better error boundary UI

Descripción

- Implementar un Error Boundary que capture fallos en React y muestre una pantalla amigable con opciones para reintentar, copiar detalles o reportar el error.

Criterios de aceptación

- Componente `ErrorBoundary` reutilizable que muestre información útil para el usuario y opciones de recuperación.
- Logs de error enviados a telemetría o almacenados para diagnóstico.

Pasos sugeridos

1. Crear el componente `ErrorBoundary` y envolver la aplicación o los componentes críticos.
2. Añadir UI para reintentar, copiar el error y reportarlo (opcional: enlace a docs o soporte).
3. Añadir tests y documentar el comportamiento esperado.
