# 35. Add asset activity timeline in modal

Descripción

- Añadir una sección de actividad dentro de `AssetModal` que muestre un historial (scans, cambios de estado, anotaciones) ordenado cronológicamente.

Criterios de aceptación

- Timeline clara y navegable desde el modal, con paginación o lazy-loading.
- Eventos servidos por un endpoint backend que acepte filtros por asset y rango de fechas.

Pasos sugeridos

1. Diseñar el modelo de eventos y añadir un endpoint `/api/assets/:id/events`.
2. Extender `AssetModal` con la UI de timeline (eventos compactos con fecha, tipo y enlace a detalles).
3. Añadir tests de interfaz y documentación breve de la API.
