# 36. Implement optimistic UI for deletes

Descripción

- Implementar borrados optimistas en la interfaz: eliminar el elemento inmediatamente en la UI y deshacer el cambio si el servidor falla.

Criterios de aceptación

- UX fluida: el asset desaparece instantáneamente; en caso de error se muestra un aviso y se restaura el estado.
- Manejo correcto de estados de carga y errores en el frontend.

Pasos sugeridos

1. Añadir la lógica optimista en `InventoryPanel` y `AssetModal` (guardar snapshot para rollback).
2. Manejar cases de error (toasts, reintento manual) y añadir tests unitarios para asegurar el rollback.
