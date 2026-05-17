# 49. Audit third-party deps for vulnerabilities

Descripción

- Auditar las dependencias del frontend y backend para identificar vulnerabilidades y proponer actualizaciones o sustituciones.

Criterios de aceptación

- Informe con las dependencias vulnerables y PRs o acciones para mitigarlas.

Pasos sugeridos

1. Ejecutar `npm audit` y herramientas adicionales (Snyk, Dependabot) en frontend y backend.
2. Priorizar actualizaciones por severidad, probar cambios y generar PRs con las correcciones.
