# 43. Add prettier/format CI enforcement

Descripción

- Forzar un estilo de código consistente mediante Prettier en CI; evitar merges con formato incorrecto.

Criterios de aceptación

- Workflow de CI que ejecute `npm run format:check` y falle si el código no cumple con el formato.

Pasos sugeridos

1. Añadir scripts `format` y `format:check` en los `package.json` relevantes (raíz, frontend, backend).
2. Añadir un job en GitHub Actions que ejecute la comprobación y, si se desea, otro job que aplique el formato automáticamente en PRs.
