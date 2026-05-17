import mongoose from 'mongoose';
import { Asset } from '../models/Asset.js';

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/hada-dev';

async function run() {
  try {
    await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 });
    console.log('Conectado a Mongo para migración');

    // Asegurar índices importantes
    await Asset.createIndexes();
    console.log('Índices creados para Asset');

    // Comprobar existencia de colección
    const exists = await mongoose.connection.db
      .listCollections({ name: Asset.collection.name })
      .hasNext();
    if (!exists) {
      await mongoose.connection.createCollection(Asset.collection.name);
      console.log(`Colección ${Asset.collection.name} creada`);
    } else {
      console.log(`Colección ${Asset.collection.name} ya existente`);
    }

    console.log('Migración completada');
    process.exit(0);
  } catch (err) {
    console.error('Error en migración:', err);
    process.exit(1);
  }
}

void run();
