# 40. Implement content security policy headers

Descripción

- Añadir cabeceras Content Security Policy (CSP) en el servidor para reducir el riesgo de XSS y carga de recursos no autorizados.

Criterios de aceptación

- CSP aplicada desde `server.ts` (o middleware) y documentada.
- Política que cubra recursos estáticos y scripts sin romper la carga legítima de la app.

Pasos sugeridos

1. Definir una política inicial conservadora (solo fuentes y dominios necesarios).
2. Implementar middleware que añada la cabecera `Content-Security-Policy` y un `report-to` para staging.
3. Probar en staging y ajustar excepciones (scripts inline, eval) antes de pasar a producción.
