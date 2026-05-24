import { Schema, model } from 'mongoose'; // Importa las funciones necesarias de Mongoose para definir el esquema y el modelo

// Definición del esquema para el modelo de Asset
const AssetSchema = new Schema(
  {
    hostname: { type: String, required: true }, // Nombre del host del activo
    mac: { type: String, required: false, default: '00:00:00:00:00:00' }, // Dirección MAC del activo
    os: { type: String, required: true, default: 'Desconocido' }, // Sistema operativo del activo
    vendor: { type: String, required: false, default: 'Generico' }, // Fabricante del activo
    criticality: { type: Number, min: 1, max: 10, default: 5 }, // Nivel de criticidad del activo (1-10)
    networkId: {
      type: String,
      required: true,
      default: 'default',
      index: true,
    }, // Segmento/red de trabajo para aislar inventarios
  },
  { timestamps: true }
); // Esto crea "createdAt" y "updatedAt" automáticamente

export const Asset = model('Asset', AssetSchema); // Exporta el modelo de Asset para su uso en otras partes de la aplicación
