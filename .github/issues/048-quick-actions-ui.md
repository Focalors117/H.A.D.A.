# 48. Add quick actions (isolate, block IP) UI

Descripción

- Añadir acciones rápidas en la UI para operar sobre nodos o direcciones IP (aislar, bloquear, marcar para investigación) con confirmaciones y feedback claro.

Criterios de aceptación

- Acciones accesibles desde `TopologyPanel` y `AssetModal`, con confirmación y estado de ejecución.

Pasos sugeridos

1. Definir endpoints o hooks que representen las acciones y sus efectos (simulados si no hay integración real).
2. Añadir botones/menús en la UI y manejar estados (pendiente, éxito, error).
