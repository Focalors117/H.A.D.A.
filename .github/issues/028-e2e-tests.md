# 28. Add E2E tests for main flows

Descripción

- Añadir pruebas de extremo a extremo que verifiquen los flujos críticos: crear un asset, lanzar un scan y comprobar la presentación de resultados.

Criterios de aceptación

- Suite E2E reproducible localmente y en CI (Playwright o Cypress).
- Tests que cubran al menos: creación de asset, llamada a `/api/scan`, y visualización de recomendaciones en la UI.

Pasos sugeridos

1. Añadir Playwright o Cypress con una configuración mínima y comandos npm (`test:e2e`).
2. Escribir tests que ejecuten los flujos principales y usen fixtures/seed de datos.
3. Integrar la suite en el workflow de CI y documentar cómo ejecutarla localmente.
