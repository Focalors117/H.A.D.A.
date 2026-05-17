import { Schema, model } from 'mongoose'; // Importa las funciones necesarias de Mongoose para definir el esquema y el modelo

// Definición del esquema para el modelo de Asset
const AssetSchema = new Schema(
  {
    hostname: { type: String, required: true }, // Nombre del host del activo
    ip: { type: String, required: true }, // Dirección IP del activo
    mac: { type: String, required: false, default: '00:00:00:00:00:00' }, // Dirección MAC del activo
    os: { type: String, required: true, default: 'Desconocido' }, // Sistema operativo del activo
    vendor: { type: String, required: false, default: 'Generico' }, // Fabricante del activo
    detectionSource: {
      type: String,
      enum: ['ARP', 'TTL', 'MANUAL'],
      default: 'ARP',
    }, // Fuente de detección del activo
    criticality: { type: Number, min: 1, max: 10, default: 5 }, // Nivel de criticidad del activo (1-10)
    status: {
      type: String,
      enum: ['Active', 'Down', 'Compromised'],
      default: 'Active',
    }, // Estado del activo
    networkId: {
      type: String,
      required: true,
      default: 'default',
      index: true,
    }, // Segmento/red de trabajo para aislar inventarios
    services: [
      {
        port: { type: Number, required: true }, // Puerto detectado como abierto
        banner: { type: String, default: '' }, // Banner simple capturado por socket
        fingerprint: { type: String, default: '' }, // Fingerprint HTTP/HTTPS (title + server)
      },
    ],
    lastScanAt: { type: Date, required: false }, // Momento del último escaneo de puertos
    lastScanMode: {
      type: String,
      enum: ['normal', 'stealth'],
      required: false,
    }, // Modo del último escaneo ejecutado
  },
  { timestamps: true }
); // Esto crea "createdAt" y "updatedAt" automáticamente

export const Asset = model('Asset', AssetSchema); // Exporta el modelo de Asset para su uso en otras partes de la aplicación
