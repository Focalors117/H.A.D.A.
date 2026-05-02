// --- IMPORTACIONES ---
import express from "express"; // Framework web para crear el servidor y manejar rutas
import mongoose from "mongoose"; // Para interactuar con MongoDB Atlas usando Mongoose
import cors from "cors"; // Para habilitar CORS
import dotenv from "dotenv"; // Para cargar variables de entorno desde un archivo .env
import { Asset } from "./models/Asset.js"; // Importamos el modelo de Asset para interactuar con la base de datos
import ping from "ping"; // Para pingear activos y analizar TTL
import { exec } from "child_process"; // Para ejecutar comandos del sistema (como arp y ping con hostname)
import ouiData from 'oui-data' with { type: "json" }; // Importamos la base de datos OUI para identificar fabricantes por MAC
import net from 'net'; // Módulo nativo de Node para conexiones TCP

// --- CONFIGURACIÓN ---
dotenv.config();

// --- INICIALIZACIÓN ---
const app = express();
app.use(express.json());
app.use(cors());

// --- CONFIGURACIÓN DE PUERTO Y BASE DE DATOS ---
const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI || "";

// Conexión a MongoDB
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ Conectado a MongoDB Atlas"))
  .catch((err) => console.error("❌ Error de conexión:", err));

import os from 'os'; // Añade esta importación arriba

// Función para registrar la PC local (Sentinel Host)
const registerLocalHost = async () => {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]!) {
      if (iface.family === 'IPv4' && !iface.internal) {
        const exists = await Asset.findOne({ ip: iface.address });
        
        if (!exists) {
          // Detectamos si es una interfaz virtual (común en VirtualBox)
          const isVirtual = name.toLowerCase().includes('virtual') || iface.address.startsWith('192.168.56');
          
          const localDevice = new Asset({
            hostname: `${os.hostname().toUpperCase()} (${isVirtual ? 'VIRTUAL' : 'HOST'})`,
            ip: iface.address,
            mac: iface.mac.toUpperCase().replace(/-/g, ':'),
            os: isVirtual ? "Virtual Network Adapter" : "Windows (Local Host)",
            status: "Active"
          });
          await localDevice.save();
        }
      }
    }
  }
};

// Llama a esta función una sola vez al arrancar el servidor
registerLocalHost();

// --- SENSORES DE RED (LOGICA ACTIVA) ---

// Función Sensor: Escanea la red para ver quién está vivo y detectar SO
const scanNetwork = async () => {
  console.log("🔍 Escaneando red y analizando TTL...");
  try {
    const assets = await Asset.find();
    for (const asset of assets) {
      const res = await ping.promise.probe(asset.ip, { timeout: 2 });
      let nuevoEstado: "Active" | "Down" | "Compromised" = asset.status;
      let detectedOS = asset.os;

      if (res.alive) {
        nuevoEstado = asset.status === "Down" ? "Active" : asset.status;
        const ttlMatch = res.output.match(/TTL=(\d+)/i);
        if (ttlMatch && ttlMatch[1]) {
          const ttlValue = parseInt(ttlMatch[1]);
          if (ttlValue <= 64) detectedOS = "Linux / Android / iOS";
          else if (ttlValue <= 128) detectedOS = "Windows";
          else detectedOS = "Network Device (Router/Switch)";
        }
      } else {
        nuevoEstado = "Down";
      }

      if (nuevoEstado !== asset.status || (detectedOS !== asset.os && detectedOS !== "Unknown")) {
        await Asset.findByIdAndUpdate(asset._id, { status: nuevoEstado, os: detectedOS });
        console.log(`📡 Asset actualizado: ${asset.hostname} -> OS: ${detectedOS}`);
      }
    }
  } catch (error) {
    console.error("❌ Error en el sensor de TTL:", error);
  }
};

// Función de Auto-Descubrimiento: Inyecta dispositivos nuevos detectados por ARP
const autoDiscoverDevices = () => {
  console.log("📡 Radar de descubrimiento activo...");
  exec("arp -a", async (error, stdout) => {
    if (error) return;
    const lines = stdout.split("\n");

    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 2) {
        const ip = parts[0];
        const mac = parts[1] ? parts[1].replace(/-/g, ":").toUpperCase() : "";

        if (ip.startsWith("192.168.") || ip.startsWith("10.")) {
          try {
            const exists = await Asset.findOne({ ip: ip });
            // Solo inyectamos si no existe y tiene una MAC válida
            if (!exists && mac && mac !== "---" && !mac.includes("FF-FF-FF")) {
              
              const hostnameReal = await new Promise((resolve) => {
                exec(`ping -a -n 1 ${ip}`, (err, out) => {
                  const m = out.match(/Pinging\s+(.*?)\s+\[/);
                  resolve(m && m[1] ? m[1].toUpperCase() : `DEVICE-${ip.split(".")[3]}`);
                });
              });

              const ouiPrefix = mac.split(":").slice(0, 3).join("").toUpperCase();
              const vendorInfo = (ouiData as any)[ouiPrefix];
              const fabricante = vendorInfo ? vendorInfo.split("\n")[0] : "Generic Vendor";

              const newDevice = new Asset({
                hostname: hostnameReal,
                ip: ip,
                mac: mac,
                os: fabricante, 
                status: "Active",
              });

              await newDevice.save();
              console.log(`🚨 AUTO-DETECTADO: ${fabricante} (${hostnameReal})`);
            }
          } catch (e) { console.error("❌ Error en Auto-Discover:", e); }
        }
      }
    }
  });
};

// Intervalos de ejecución
setInterval(scanNetwork, 30000);
setInterval(autoDiscoverDevices, 45000);

// --- RUTAS DE LA API (CRUD) ---

// 1. OBTENER todos los activos (GET) -> ¡AQUÍ ESTABA EL ERROR 404!
app.get("/api/assets", async (req, res) => {
  try {
    const assets = await Asset.find();
    res.json(assets);
  } catch (error) {
    res.status(500).json({ message: "Error al obtener activos" });
  }
});

// 2. CREAR un nuevo activo (POST)
app.post("/api/assets", async (req, res) => {
  try {
    const newAsset = new Asset(req.body);
    await newAsset.save();
    res.status(201).json(newAsset);
  } catch (error) {
    res.status(400).json({ message: "Error al crear activo", error });
  }
});

// 3. ELIMINAR un activo (DELETE)
app.delete("/api/assets/:id", async (req, res) => {
  try {
    await Asset.findByIdAndDelete(req.params.id);
    res.json({ message: "Activo eliminado" });
  } catch (error) {
    res.status(500).json({ message: "Error al eliminar", error });
  }
});

// 4. ACTUALIZAR un activo (PUT)
app.put("/api/assets/:id", async (req, res) => {
  try {
    const updatedAsset = await Asset.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(updatedAsset);
  } catch (error) {
    res.status(500).json({ message: "Error al actualizar", error });
  }
});

// 5. ESCÁNER DE PUERTOS (Mini-Nmap)
app.post("/api/scan", async (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ message: "IP requerida para el escaneo" });

  // Lista de puertos críticos a revisar (FTP, SSH, Web, SMB, RDP)
  const portsToScan = [21, 22, 80, 443, 445, 3389, 8080];
  const openPorts: number[] = [];

  const scanPort = (port: number) => {
    return new Promise<void>((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(1500); // Si no responde en 1.5 segundos, lo damos por cerrado

      socket.on("connect", () => {
        openPorts.push(port); // ¡Bingo! Puerto abierto
        socket.destroy();
        resolve();
      });

      socket.on("timeout", () => {
        socket.destroy();
        resolve();
      });

      socket.on("error", () => {
        resolve(); // Error de conexión = puerto cerrado o filtrado
      });

      socket.connect(port, ip);
    });
  };

  try {
    // Escaneamos todos los puertos al mismo tiempo (en paralelo) para que sea súper rápido
    await Promise.all(portsToScan.map(scanPort));
    res.json({ ip, openPorts });
  } catch (error) {
    res.status(500).json({ message: "Fallo crítico en el escáner" });
  }
});

// --- INICIO DEL SERVIDOR ---
app.listen(PORT, () => {
  console.log(`🚀 Sentinel-DB operativo en http://localhost:${PORT}`);
});