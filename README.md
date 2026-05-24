# H.A.D.A

H.A.D.A es una plataforma de monitoreo y escaneo controlado para entornos de red locales. El proyecto combina un backend en Node.js/Express con persistencia en MongoDB y un frontend en React + Vite para visualizar activos, escaneos, eventos de seguridad y el contexto de red activo.

## Estructura

- `backend/`: API, descubrimiento de red, escaneo, persistencia y pruebas de integración.
- `frontend/`: interfaz web, paneles de inventario, métricas, topología y modales de gestión.
- `TODO.md`: tareas pendientes y mejoras previstas.
- `WEBSITE_FUNCTIONS.md`: resumen funcional del sitio.

## Requisitos

- Node.js 18 o superior.
- npm 9 o superior.
- MongoDB accesible desde el backend si quieres persistencia real.
- Windows o una red compatible si vas a usar la detección de Wi-Fi del backend.

## Instalación

Instala dependencias por separado en ambos proyectos:

```bash
cd backend
npm install

cd ../frontend
npm install
```

## Configuración

El backend usa estas variables de entorno:

- `PORT`: puerto HTTP del API, por defecto `3001`.
- `MONGO_URI`: cadena de conexión de MongoDB.

Puedes crear un archivo `.env` dentro de `backend/` con algo como esto:

```env
PORT=3001
MONGO_URI=mongodb://localhost:27017/hada
```

## Ejecución local

1. Arranca el backend:

```bash
cd backend
npm run dev
```

2. Arranca el frontend en otra terminal:

```bash
cd frontend
npm run dev
```

3. Abre la URL que indique Vite, normalmente `http://localhost:5173`.

## Scripts útiles

### Backend

- `npm run dev`: servidor en modo desarrollo.
- `npm run build`: compila TypeScript.
- `npm run start`: ejecuta el build compilado.
- `npm run test:health`: prueba de salud del API.
- `npm run test:scan`: prueba de escaneo.
- `npm run test:integration`: ejecuta las pruebas de integración principales.

### Frontend

- `npm run dev`: servidor de desarrollo de Vite.
- `npm run build`: build de producción.
- `npm run lint`: revisión de código.
- `npm run test`: suite de Vitest.
- `npm run test:e2e`: pruebas end-to-end con Playwright.

## Funcionalidad principal

- Contexto de red activo y detección de interfaz local.
- Registro, edición y eliminación de activos.
- Escaneo controlado de IPs privadas con rate limiting.
- Inventario visual con métricas, topología, eventos y alertas.
- Persistencia en MongoDB con fallback en memoria si la base no está disponible.

## API principal

Base URL: `http://localhost:3001/api`

- `GET /health`: estado del backend.
- `GET /network/context`: contexto de red activo.
- `GET /assets?networkId=...`: inventario de activos.
- `POST /assets`: crea un activo.
- `POST /assets/import`: importación masiva.
- `PUT /assets/:id`: actualiza un activo.
- `DELETE /assets/:id`: elimina un activo.
- `GET /events?networkId=...`: eventos recientes.
- `POST /radar/control`: activa o pausa el radar.
- `POST /scan`: ejecuta un escaneo controlado.

## Notas

- El escaneo solo acepta IPs privadas.
- El backend mantiene cachés en memoria para seguir funcionando si MongoDB cae.
- Los artefactos de build, logs y resultados de pruebas están excluidos por `.gitignore`.
