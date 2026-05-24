# H.A.D.A — Resumen de funcionalidades

Este documento resume las funciones principales de la aplicación web H.A.D.A (Hazard Analysis & Detection Assistant).

- Radar / Auto-descubrimiento
  - Realiza barridos ICMP (ping sweep) y consulta la tabla ARP local para detectar dispositivos en la red local.
  - Usa mDNS para resolver nombres de host cuando están disponibles.
  - Mantiene una caché en memoria y sincroniza con MongoDB cuando está disponible.

- Gestión de Activos
  - CRUD de activos vía API (`/api/assets`).
  - Import masivo de activos vía `/api/assets/import` (acepta array JSON).
  - Organización por `networkId` (workspaces) para segmentar activos.

- Escaneo de puertos y enriquecimiento
  - Escanea puertos comunes (21,22,23,80,443,445,3306,3389,8080).
  - Recolecta banners y fingerprint HTTP para puertos 80/443.
  - Calcula una métrica `cvssLikeScore` y mapea recomendaciones simples por puerto.
  - Guarda resultados en DB o en caché en memoria cuando Mongo no está disponible.

- Eventos y alertas
  - Genera eventos de seguridad (p. ej. `NEW_UNKNOWN_DEVICE`, `DOUBLE_AGENT`) en detecciones relevantes.
  - Mantiene un timeline en memoria y se puede consultar vía `/api/events`.

- Acciones rápidas (simuladas)
  - `POST /api/assets/:id/isolate` — simula el envío de un comando remoto de aislamiento.
  - `POST /api/firewall/block` — encola una solicitud de bloqueo de IP (simulado).
  - Interfaz con botones en `AssetModal` para ejecutar estas acciones desde la UI.

- Feedback y Telemetría
  - Endpoint `/api/feedback` para enviar mensajes/feedback que se almacenan en memoria (recibos).
  - Ajustes por workspace (persistidos en frontend) para opciones como modo radar, TTL, tema.

- Seguridad y rendimiento
  - Content-Security-Policy y cabeceras de cache para assets estáticos.
  - Rate-limiter para la API de escaneo para evitar abuso.

- Testing y E2E
  - Playwright configurado para levantar el servidor frontend automáticamente durante E2E (`playwright.config.ts`).
  - Tests de ejemplo en `frontend/tests/e2e`.

Notas y limitaciones

- Las acciones de aislamiento/bloqueo son simuladas — requieren integración con infra real para producción.
- El scanner puede necesitar privilegios o binarios del sistema (`ping`) para funcionar correctamente en algunos entornos; el servidor ahora captura errores de `ping` y continúa.

Si quieres, puedo expandir este README con ejemplos de uso por endpoint, capturas de pantalla o diagramas de flujo.
