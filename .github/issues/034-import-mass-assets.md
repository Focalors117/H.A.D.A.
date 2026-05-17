# 34. Add import for mass asset registration

Descripción

- Permitir al usuario subir archivos CSV o JSON para registrar varios assets a la vez, con previsualización y validación previa.

Criterios de aceptación

- UI para subir y previsualizar registros antes de confirmar la importación.
- Endpoint backend que valide, cree los assets en lote y devuelva un informe de errores/éxitos.

Pasos sugeridos

1. Definir el formato de importación (columnas requeridas, validaciones) y crear ejemplos de CSV/JSON.
2. Implementar la UI de importación y el endpoint `/api/assets/import` que procese los lotes de forma segura.
3. Añadir tests de integración y documentación de uso.
