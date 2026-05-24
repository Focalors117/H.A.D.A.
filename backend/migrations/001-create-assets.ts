import mongoose from 'mongoose';
import { Asset } from '../models/Asset.js';
import { Scan } from '../models/Scan.js';
import { Service } from '../models/Service.js';

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/hada-dev';

async function run() {
  try {
    await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 });
    console.log('Conectado a Mongo para migración');

    // Asegurar índices importantes
    await Asset.createIndexes();
    await Scan.createIndexes();
    await Service.createIndexes();
    console.log('Índices creados para Asset, Scan y Service');

    const db = mongoose.connection.db;
    if (!db) throw new Error('No se pudo acceder a mongoose.connection.db');

    // Comprobar existencia de colecciones
    const collections = [Asset.collection.name, Scan.collection.name, Service.collection.name];
    for (const collectionName of collections) {
      const exists = await db.listCollections({ name: collectionName }).hasNext();
      if (!exists) {
        await db.createCollection(collectionName);
        console.log(`Colección ${collectionName} creada`);
      } else {
        console.log(`Colección ${collectionName} ya existente`);
      }
    }

    console.log('Migración completada');
    process.exit(0);
  } catch (err) {
    console.error('Error en migración:', err);
    process.exit(1);
  }
}

void run();
