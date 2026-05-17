# H.A.D.A Dashboard

Interfaz de monitoreo y escaneo para la red H.A.D.A. El frontend vive en esta carpeta y consume el backend en `http://localhost:3001`.

## Requisitos

- Node.js 18 o superior
- Backend levantado en el puerto 3001

## Instalación

```bash
cd frontend
npm install
```

## Scripts

```bash
npm run dev
npm run build
npm run lint
npm run test
npm run preview
```

## Arranque local

1. Levanta el backend:

```bash
cd backend
npm install
npm run dev
```

2. Levanta el frontend:

```bash
cd frontend
npm run dev
```

3. Abre `http://localhost:5173`.

## API principal

Base URL: `http://localhost:3001/api`

| Método | Ruta                    | Descripción                      |
| ------ | ----------------------- | -------------------------------- |
| GET    | `/health`               | Estado general del backend       |
| GET    | `/network/context`      | Contexto de red activo detectado |
| GET    | `/assets?networkId=...` | Lista los activos del workspace  |
| POST   | `/assets`               | Crea un activo                   |
| PUT    | `/assets/:id`           | Actualiza estado o criticidad    |
| DELETE | `/assets/:id`           | Elimina un activo                |
| DELETE | `/workspaces/:id`       | Borra un workspace y sus activos |
| GET    | `/events?networkId=...` | Eventos de seguridad recientes   |
| POST   | `/radar/control`        | Activa o pausa el radar          |
| POST   | `/scan`                 | Ejecuta un escaneo controlado    |

## Ejemplos cURL

### Salud

```bash
curl http://localhost:3001/api/health
```

### Contexto de red

```bash
curl http://localhost:3001/api/network/context
```

### Listar activos

```bash
curl "http://localhost:3001/api/assets?networkId=default"
```

### Crear activo

```bash
curl -X POST http://localhost:3001/api/assets ^
  -H "Content-Type: application/json" ^
  -d "{\"hostname\":\"LAB-PC\",\"ip\":\"192.168.1.50\",\"mac\":\"AA:BB:CC:DD:EE:FF\",\"os\":\"Windows\",\"criticality\":5,\"status\":\"Active\",\"networkId\":\"default\"}"
```

### Ejecutar scan

```bash
curl -X POST http://localhost:3001/api/scan ^
  -H "Content-Type: application/json" ^
  -d "{\"ip\":\"192.168.1.50\",\"mode\":\"normal\"}"
```

### Pausar radar

```bash
curl -X POST http://localhost:3001/api/radar/control ^
  -H "Content-Type: application/json" ^
  -d "{\"active\":false}"
```

## Notas

- El escaneo solo acepta IPs privadas.
- El endpoint `/scan` aplica rate limiting in-memory para evitar abuso.
- Si Mongo no está disponible, el backend sigue funcionando con caché en memoria.
