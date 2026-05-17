# 16. Add DB migration script for assets

Descripción

- Crear un script de migración que cree o actualice la estructura necesaria para los `assets` en la base de datos, con instrucciones claras para desarrollo y despliegue.

Criterios de aceptación

- Migración idempotente con pasos `up` y `down`.
- Documentación breve (cómo ejecutar, rollback, requisitos) incluida en `README.md` o `docs/migrations.md`.
- Pruebas locales que demuestren la migración en una base de datos de desarrollo.

Pasos sugeridos

1. Elegir la herramienta de migraciones (Prisma, TypeORM, Flyway, raw SQL, etc.).
2. Implementar los scripts `up`/`down` que añaden los campos/índices necesarios.
3. Añadir un script npm para ejecutar migraciones y documentar el procedimiento.
4. Probar la migración en una base de datos local y en CI si procede.
