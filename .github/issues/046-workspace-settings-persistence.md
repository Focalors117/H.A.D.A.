# 46. Add per-workspace settings persistence

Descripción

- Guardar preferencias por workspace (toggles, opciones de visualización) para que cada entorno conserve su configuración.

Criterios de aceptación

- Lectura/escritura de settings por workspace desde frontend y backend (opcionalmente localStorage para uso sin backend).

Pasos sugeridos

1. Diseñar el modelo de settings y la clave de persistencia por workspace.
2. Añadir endpoints para leer y guardar settings y un pequeño wrapper frontend para consumirlos.
3. Documentar el comportamiento y las opciones disponibles.
