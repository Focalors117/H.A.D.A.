# 37. Add dark-mode toggle persistence

Descripción

- Guardar la preferencia de tema (claro/oscuro) para que se mantenga entre sesiones y dispositivos si se desea.

Criterios de aceptación

- El toggle mantiene la elección al recargar la página (localStorage) y opcionalmente puede sincronizarse por workspace en backend.

Pasos sugeridos

1. Implementar persistencia simple con `localStorage` y aplicar la clase/variable CSS correspondiente al cargarse la app.
2. (Opcional) Añadir endpoints para guardar la preferencia por workspace y sincronizarla al iniciar sesión.
