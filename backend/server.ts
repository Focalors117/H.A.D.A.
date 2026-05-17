// --- IMPORTACIONES ---
import cors from 'cors';
import dotenv from 'dotenv';
import express, { type NextFunction, type Request, type Response } from 'express';
import { exec, execSync } from 'child_process';
import http from 'http';
import https from 'https';
import mdns from 'multicast-dns';
import mongoose from 'mongoose';
import net from 'net';
import os from 'os';
import ping from 'ping';
import ouiData from 'oui-data' assert { type: 'json' };
import { pathToFileURL } from 'url';
import { Asset } from './models/Asset.js';
import { createScanRateLimiter } from './utils/scanRateLimit.js';

// --- CONFIGURACIÓN ---
dotenv.config();
const app = express();
export { app };
app.use(express.json());
app.use(cors());

// Security: Content-Security-Policy middleware (conservadora)
app.use((req: Request, res: Response, next: NextFunction) => {
  const policy = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "connect-src 'self' http://localhost:3001 ws://localhost:3001",
    "font-src 'self' data:",
    "object-src 'none'",
  ].join('; ');
  res.setHeader('Content-Security-Policy', policy);
  next();
});

// Caching headers para activos estáticos cuando el backend sirve la carpeta public/
app.use((req: Request, res: Response, next: NextFunction) => {
  if (req.path.startsWith('/assets/') || req.path.match(/\.(js|css|png|jpg|jpeg|svg|webp)$/)) {
    // assets fingerprinted by build should be cached long
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    return next();
  }
  if (req.path === '/' || req.path.endsWith('.html')) {
    res.setHeader('Cache-Control', 'no-cache');
    return next();
  }
  return next();
});

const PORT = Number(process.env.PORT || 3001);
const MONGO_URI = process.env.MONGO_URI || '';
const PORTS_TO_SCAN = [21, 22, 23, 80, 443, 445, 3306, 3389, 8080];
const scanRateLimiter = createScanRateLimiter({ windowMs: 60_000, max: 3 });

// --- ESTADO DE RUNTIME ---
let isRadarEnabled = true;
let cachedAssets: any[] = [];
const localDeviceNames: Record<string, string> = {};
const knownMacPerNetwork = new Map<string, Set<string>>();
const securityEvents: Array<{
  id: string;
  type: 'NEW_UNKNOWN_DEVICE' | 'DOUBLE_AGENT';
  networkId: string;
  ip: string;
  mac: string;
  message: string;
  timestamp: string;
}> = [];

type ScanRisk = {
  port: number;
  severity: 'low' | 'medium' | 'high';
  message: string;
};

type ServiceScan = {
  port: number;
  banner: string;
  fingerprint: string;
};

const PORT_RISK_RULES: Record<number, Omit<ScanRisk, 'port'>> = {
  21: {
    severity: 'high',
    message: 'Transferencia de archivos sin cifrar (riesgo de intercepción).',
  },
  23: {
    severity: 'high',
    message: 'Servicio Telnet expuesto sin cifrado robusto.',
  },
  445: {
    severity: 'high',
    message: 'Superficie SMB vulnerable (ej. EternalBlue en sistemas no parchados).',
  },
  3389: {
    severity: 'medium',
    message: 'RDP expuesto, objetivo común de fuerza bruta y ransomware.',
  },
  3306: {
    severity: 'medium',
    message: 'Base de datos expuesta, requiere control estricto de acceso.',
  },
  80: {
    severity: 'low',
    message: 'HTTP sin cifrar, contenido y credenciales pueden ser interceptados.',
  },
};

// Mapeo simplificado de vulnerabilidades / recomendaciones por puerto.
const PORT_CVE_MAP: Record<number, { cve: string; title: string; recommendation: string }> = {
  21: {
    cve: 'CVE-1999-0001',
    title: 'FTP sin cifrado',
    recommendation: 'Deshabilitar FTP o migrar a SFTP/FTPS y restringir acceso por IP.',
  },
  23: {
    cve: 'CVE-1999-0002',
    title: 'Telnet expuesto',
    recommendation: 'Deshabilitar Telnet y usar SSH con claves. Filtrar accesos en firewall.',
  },
  80: {
    cve: 'CVE-1999-0003',
    title: 'HTTP sin TLS',
    recommendation: 'Configurar HTTPS/TLS y redirigir tráfico HTTP a HTTPS.',
  },
  445: {
    cve: 'CVE-2017-0144',
    title: 'SMBv1 / EternalBlue (familia)',
    recommendation: 'Actualizar sistemas, deshabilitar SMBv1 y limitar accesos SMB en la red.',
  },
  3389: {
    cve: 'CVE-2019-0708',
    title: 'RDP expuesto',
    recommendation: 'Usar gateway RDP, MFA, y restringir acceso desde Internet. Revisar parches.',
  },
};

// --- UTILIDADES DE RED ---
const normalizeNetworkId = (input: string) =>
  input
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-_/.:]/g, '');

const isPrivateIP = (ip: string) => {
  return (
    ip.startsWith('10.') || ip.startsWith('192.168.') || /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)
  );
};

const isBroadcastOrInvalidTarget = (ip: string) => {
  const parts = ip.split('.');
  if (parts.length !== 4) return true;
  const octets = parts.map((part) => Number(part));
  if (octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return true;
  if (octets[3] === 0 || octets[3] === 255) return true;
  if (octets[0] >= 224) return true;
  return false;
};

const getWifiSsid = () => {
  try {
    const output = execSync('netsh wlan show interfaces', {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 3000,
    });
    const match = output.match(/^\s*SSID\s*:\s*(.+)$/m);
    const ssid = match?.[1]?.trim();
    return ssid && ssid !== '' ? ssid : null;
  } catch {
    return null;
  }
};

const getNetworkContext = () => {
  const interfaces = os.networkInterfaces();
  const networks: Array<{
    iface: string;
    ip: string;
    networkId: string;
    label: string;
  }> = [];
  const wifiSsid = getWifiSsid();

  for (const ifaceName of Object.keys(interfaces)) {
    for (const iface of interfaces[ifaceName] ?? []) {
      if (iface.family !== 'IPv4' || iface.internal) continue;
      const lowerName = ifaceName.toLowerCase();
      if (/loopback|virtual|tunnel|docker|vmware|hyper-v|veth|vpn/.test(lowerName)) continue;
      const base = iface.address.split('.').slice(0, 3).join('.');
      const networkId = `${base}.0/24`;
      const label = wifiSsid && /wi-?fi|wireless|wlan/.test(lowerName) ? wifiSsid : ifaceName;
      networks.push({ iface: ifaceName, ip: iface.address, networkId, label });
    }
  }

  const preferred =
    networks.find((network) => /wi-?fi|wireless|wlan/i.test(network.iface)) ??
    networks.find((network) => /ethernet|eth/i.test(network.iface)) ??
    networks[0];

  return {
    activeNetworkId: preferred?.networkId ?? 'default',
    activeNetworkLabel: preferred?.label ?? preferred?.iface ?? 'default',
    activeInterface: preferred?.iface ?? '',
    networks,
  };
};

const inferOSFromTTL = (ttl: number, hostname: string) => {
  const host = hostname.toLowerCase();
  if (ttl >= 127 && ttl <= 128) return 'Windows';
  if (ttl >= 63 && ttl <= 64) {
    if (host.endsWith('-android') || host.includes('android')) return 'Android';
    return 'Linux / Unix';
  }
  if (ttl <= 64) return 'Linux / Android / iOS';
  if (ttl <= 128) return 'Windows';
  return 'Network Device (Router/Switch)';
};

const withDbCache = async <T>(operation: () => Promise<T>, fallback: T): Promise<T> => {
  if (mongoose.connection.readyState !== 1) {
    console.warn('⚠️ [Cache] MongoDB no está conectado. Usando fallback en memoria.');
    return fallback;
  }
  try {
    return await operation();
  } catch (error) {
    console.error('⚠️ Fallback de caché activado por error en MongoDB:', error);
    return fallback;
  }
};

const isMongoReady = () => mongoose.connection.readyState === 1;

const upsertCachedAsset = (asset: any) => {
  const assetId = String(asset._id ?? `${asset.ip}-${asset.networkId}`);
  const nextAsset = { ...asset, _id: assetId };
  const index = cachedAssets.findIndex((item) => String(item._id) === assetId);

  if (index >= 0) {
    cachedAssets[index] = { ...cachedAssets[index], ...nextAsset };
    return cachedAssets[index];
  }

  cachedAssets = [...cachedAssets, nextAsset];
  return nextAsset;
};

const updateCachedAsset = (assetId: string, patch: Record<string, unknown>) => {
  const index = cachedAssets.findIndex((item) => String(item._id) === assetId);
  if (index < 0) return null;

  cachedAssets[index] = { ...cachedAssets[index], ...patch };
  return cachedAssets[index];
};

const deleteCachedAsset = (assetId: string) => {
  const before = cachedAssets.length;
  cachedAssets = cachedAssets.filter((item) => String(item._id) !== assetId);
  return cachedAssets.length !== before;
};

const refreshCache = async () => {
  if (!isMongoReady()) return cachedAssets;
  cachedAssets = await withDbCache(() => Asset.find().lean(), cachedAssets);
  return cachedAssets;
};

const pushSecurityEvent = (event: Omit<(typeof securityEvents)[number], 'id' | 'timestamp'>) => {
  securityEvents.unshift({
    ...event,
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    timestamp: new Date().toISOString(),
  });
  if (securityEvents.length > 100) securityEvents.length = 100;
};

// Feedback receipts (in-memory; lightweight)
const feedbacks: Array<{ id: string; email?: string; message: string; ts: string }> = [];

const pushFeedback = (payload: { email?: string; message: string }) => {
  const entry = { id: `${Date.now()}-${Math.random().toString(16).slice(2)}`, ...payload, ts: new Date().toISOString() };
  feedbacks.unshift(entry);
  if (feedbacks.length > 200) feedbacks.length = 200;
  return entry;
};

const registerKnownMac = (networkId: string, mac: string) => {
  const normalized = mac.toUpperCase();
  if (!knownMacPerNetwork.has(networkId)) knownMacPerNetwork.set(networkId, new Set());
  knownMacPerNetwork.get(networkId)?.add(normalized);
};

const detectDoubleAgent = (networkId: string, mac: string, ip: string) => {
  const sameMacAssets = cachedAssets.filter(
    (asset) => asset.networkId === networkId && asset.mac === mac
  );
  const distinctIps = new Set(sameMacAssets.map((asset) => asset.ip));
  if (distinctIps.size >= 2 && !distinctIps.has(ip)) {
    pushSecurityEvent({
      type: 'DOUBLE_AGENT',
      networkId,
      ip,
      mac,
      message: `MAC ${mac} asociada a múltiples IPs en ${networkId}. Posible spoofing/MITM.`,
    });
  }
};

// --- ENRIQUECIMIENTO DE SERVICIOS ---
const getServiceBanner = (ip: string, port: number): Promise<string> => {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = 'Servicio activo (sin banner)';
    socket.setTimeout(1500);

    socket.connect(port, ip, () => {
      if ([80, 443, 8080].includes(port)) {
        socket.write(`HEAD / HTTP/1.1\r\nHost: ${ip}\r\nConnection: close\r\n\r\n`);
      }
    });

    socket.on('data', (data) => {
      const firstLine = data.toString().split('\n')[0]?.trim();
      if (firstLine) banner = firstLine.slice(0, 90);
      socket.destroy();
    });

    socket.on('error', () => socket.destroy());
    socket.on('timeout', () => socket.destroy());
    socket.on('close', () => resolve(banner));
  });
};

const getHttpFingerprint = (ip: string, port: number): Promise<string> => {
  return new Promise((resolve) => {
    const isSecure = port === 443;
    const transport = isSecure ? https : http;
    const request = transport.request(
      {
        host: ip,
        port,
        path: '/',
        method: 'GET',
        timeout: 2000,
        rejectUnauthorized: false,
        headers: { 'User-Agent': 'HADA-Scanner/1.0' },
      },
      (response) => {
        let body = '';
        response.on('data', (chunk) => {
          if (body.length < 6000) body += chunk.toString();
        });
        response.on('end', () => {
          const titleMatch = body.match(/<title[^>]*>(.*?)<\/title>/i);
          const title = titleMatch?.[1]?.trim() || 'Sin <title>';
          const serverHeader =
            typeof response.headers.server === 'string'
              ? response.headers.server
              : 'Server desconocido';
          resolve(`title=${title.slice(0, 80)} | server=${serverHeader.slice(0, 80)}`);
        });
      }
    );

    request.on('timeout', () => {
      request.destroy();
      resolve('Fingerprint HTTP no disponible (timeout)');
    });
    request.on('error', () => resolve('Fingerprint HTTP no disponible'));
    request.end();
  });
};

const getRiskCards = (ports: number[]): ScanRisk[] => {
  return ports.flatMap((port) => {
    const rule = PORT_RISK_RULES[port];
    if (!rule) return [];
    return [{ port, ...rule }];
  });
};

const computeCvssLikeScore = (ports: number[], risks: ScanRisk[]) => {
  if (ports.length === 0) return 0;

  const severityWeight = risks.reduce((acc, risk) => {
    if (risk.severity === 'high') return acc + 3.3;
    if (risk.severity === 'medium') return acc + 1.8;
    return acc + 0.8;
  }, 0);

  const uniquePorts = new Set(ports).size;
  const exposureBoost = Math.min(2.5, uniquePorts * 0.35);
  const criticalPorts = [23, 445, 3389];
  const criticalBoost = Math.min(
    1.8,
    criticalPorts.filter((port) => ports.includes(port)).length * 0.6
  );

  const raw = 1.2 + severityWeight + exposureBoost + criticalBoost;
  return Math.min(10, Math.round(raw * 10) / 10);
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// --- MIDDLEWARE DE SEGURIDAD PARA SCAN ---
const validateScanTarget = (req: Request, res: Response, next: NextFunction) => {
  const targetIp = String(req.body?.ip || '').trim();
  if (!targetIp) return res.status(400).json({ message: 'IP requerida' });
  if (isBroadcastOrInvalidTarget(targetIp)) {
    return res.status(400).json({
      message: 'IP inválida o de broadcast. Usa un host real de la red.',
    });
  }
  if (!isPrivateIP(targetIp)) {
    return res.status(400).json({
      message: 'Solo se permiten IPs privadas para escaneo controlado.',
    });
  }
  return next();
};

const mdnsSniffer = mdns();
mdnsSniffer.on('response', (response) => {
  response.answers.forEach((answer) => {
    if (answer.type !== 'A' && answer.type !== 'PTR') return;
    const name = answer.name.replace(/\.local\.?$/, '');
    const ip = answer.data as string;
    if (typeof ip === 'string' && ip.includes('.')) {
      localDeviceNames[ip] = name.toUpperCase();
    }
  });
});

const registerLocalHost = async () => {
  const interfaces = os.networkInterfaces();
  for (const ifaceName of Object.keys(interfaces)) {
    for (const iface of interfaces[ifaceName] ?? []) {
      if (iface.family !== 'IPv4' || iface.internal) continue;
      const base = iface.address.split('.').slice(0, 3).join('.');
      const networkId = `${base}.0/24`;
      const exists = await withDbCache(() => Asset.findOne({ ip: iface.address, networkId }), null);
      if (exists) continue;

      const isVirtual =
        ifaceName.toLowerCase().includes('virtual') || iface.address.startsWith('192.168.56');
      const localDevice = new Asset({
        hostname: `${os.hostname().toUpperCase()} (${isVirtual ? 'VIRTUAL' : 'HOST'})`,
        ip: iface.address,
        mac: iface.mac.toUpperCase().replace(/-/g, ':'),
        os: isVirtual ? 'Virtual Network Adapter' : 'Windows (Local Host)',
        status: 'Active',
        networkId,
      });

      await withDbCache(async () => {
        await localDevice.save();
        return true;
      }, false);
      upsertCachedAsset(localDevice.toObject());
      registerKnownMac(networkId, localDevice.mac || '');
    }
  }
  await refreshCache();
};

// --- SENSORES DE RED ---
const scanNetwork = async () => {
  if (!isRadarEnabled) return;
  console.log(
    `[Sensor] scanNetwork -> Iniciando escaneo de activos en base de datos. Cantidad: ${cachedAssets.length}`
  );
  const assets = isMongoReady()
    ? await withDbCache(() => Asset.find(), cachedAssets)
    : cachedAssets;

  let activeCount = 0;
  let downCount = 0;

  for (const asset of assets) {
    const pingResult = await ping.promise.probe(asset.ip, { timeout: 2 });
    let nextStatus: 'Active' | 'Down' | 'Compromised' = asset.status;
    let detectedOS = asset.os;

    if (pingResult.alive) {
      activeCount++;
      nextStatus = asset.status === 'Down' ? 'Active' : asset.status;
      const ttlMatch = pingResult.output.match(/TTL=(\d+)/i);
      const ttlValue = ttlMatch?.[1] ? Number(ttlMatch[1]) : null;
      if (ttlValue !== null) {
        const inferredOS = inferOSFromTTL(ttlValue, asset.hostname || '');
        const generic = !asset.os || asset.os === 'Detecting...' || asset.os === 'Unknown';
        if (generic) detectedOS = inferredOS;
      }
    } else {
      downCount++;
      nextStatus = 'Down';
    }

    if (nextStatus !== asset.status || detectedOS !== asset.os) {
      console.log(
        `[Sensor] Actualizado estado/OS para ${asset.ip} -> Estado: ${nextStatus}, OS: ${detectedOS}`
      );
      await withDbCache(
        () =>
          Asset.findByIdAndUpdate(asset._id, { status: nextStatus, os: detectedOS }, { new: true }),
        null
      );
    }
  }

  console.log(`[Sensor] scanNetwork -> Completado. Activos: ${activeCount}, Caídos: ${downCount}`);
  await refreshCache();
};

const activeNetworkSweep = async () => {
  if (!isRadarEnabled) return;
  const { networks } = getNetworkContext();
  console.log(
    `[Sensor] activeNetworkSweep -> Haciendo sweep de rangos: ${networks
      .map((n) => n.networkId)
      .join(', ')}`
  );
  const probes: Array<Promise<unknown>> = [];

  for (const network of networks) {
    const base = network.ip.split('.').slice(0, 3).join('.');
    for (let host = 1; host <= 254; host += 1) {
      // Incrementar timeout a 1s para redes WiFi o físicas reales
      probes.push(ping.promise.probe(`${base}.${host}`, { timeout: 1 }));
    }
  }

  await Promise.all(probes);
  console.log('🏁 [Radar] Active Sweep finalizado. Se enviaron pings a todos los hosts posibles.');
};

const resolveHostname = async (ip: string) => {
  if (localDeviceNames[ip]) return localDeviceNames[ip];
  return new Promise<string>((resolve) => {
    exec(`ping -a -n 1 ${ip}`, (_err, out) => {
      const match = out.match(/Pinging\s+(.*?)\s+\[/i);
      resolve(match?.[1] ? match[1].toUpperCase() : `DEVICE-${ip.split('.')[3]}`);
    });
  });
};

const autoDiscoverDevices = async () => {
  if (!isRadarEnabled) {
    console.log('⏸️ [Radar] Pausado, saltando auto-descubrimiento...');
    return;
  }
  console.log('🔍 [Radar] Iniciando Active Sweep (ICMP/Ping)...');
  await activeNetworkSweep();

  console.log('📡 [Radar] Inspeccionando tabla ARP local...');
  exec('arp -a', async (error, stdout) => {
    if (error) return;

    const lines = stdout.split('\n');
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 2) continue;

      const ip = parts[0];
      const mac = (parts[1] || '').replace(/-/g, ':').toUpperCase();
      if (!isPrivateIP(ip) || !mac || mac === '---' || mac.includes('FF:FF:FF')) continue;

      const base = ip.split('.').slice(0, 3).join('.');
      const networkId = `${base}.0/24`;
      const exists = await withDbCache(() => Asset.findOne({ ip, networkId }), null);
      if (exists) continue;

      const hostname = await resolveHostname(ip);
      const ouiPrefix = mac.split(':').slice(0, 3).join('').toUpperCase();
      const vendorInfo = (ouiData as Record<string, string>)[ouiPrefix];
      const vendor = vendorInfo ? vendorInfo.split('\n')[0] : 'Generic Vendor';

      const newDevice = new Asset({
        hostname,
        ip,
        mac,
        os: 'Detecting...',
        vendor,
        status: 'Active',
        detectionSource: 'ARP',
        networkId,
      });

      await withDbCache(async () => {
        await newDevice.save();
        return true;
      }, false);
      upsertCachedAsset(newDevice.toObject());

      const knownMacs = knownMacPerNetwork.get(networkId) ?? new Set<string>();
      if (!knownMacs.has(mac)) {
        console.log(
          `🚨 [Alerta] ¡Nuevo dispositivo desconocido! IP: ${ip}, MAC: ${mac}, Fabricante: ${vendor}`
        );
        pushSecurityEvent({
          type: 'NEW_UNKNOWN_DEVICE',
          networkId,
          ip,
          mac,
          message: `Nuevo dispositivo desconocido detectado (${ip} / ${mac}).`,
        });
      }

      registerKnownMac(networkId, mac);
      detectDoubleAgent(networkId, mac, ip);
    }

    console.log('✅ [Radar] Tabla ARP procesada. Activos registrados en BD y caché listos.');
    await refreshCache();
  });
};

// Rutas API registradas...
app.get('/api/network/context', (_req, res) => {
  const context = getNetworkContext();
  res.json(context);
});

app.get('/api/events', (req, res) => {
  const networkId = normalizeNetworkId(String(req.query.networkId || ''));
  const payload = networkId
    ? securityEvents.filter((event) => event.networkId === networkId)
    : securityEvents;
  res.json(payload.slice(0, 40));
});

app.post('/api/radar/control', (req, res) => {
  const { active } = req.body;
  isRadarEnabled = Boolean(active);
  console.log(isRadarEnabled ? '🚀 RADAR: ACTIVADO' : '🛑 RADAR: PAUSADO');
  res.json({ status: 'ok', radarActive: isRadarEnabled });
});

app.get('/api/assets', async (req, res) => {
  const networkId = normalizeNetworkId(String(req.query.networkId || ''));
  const dbAssets = await withDbCache(
    () => (networkId ? Asset.find({ networkId }) : Asset.find()),
    cachedAssets.filter((asset) => (networkId ? asset.networkId === networkId : true))
  );
  res.json(dbAssets);
});

app.post('/api/assets', async (req, res) => {
  try {
    const rawNetworkId = String(req.body.networkId || getNetworkContext().activeNetworkId);
    const networkId = normalizeNetworkId(rawNetworkId) || 'default';
    if (!isMongoReady()) {
      const asset = upsertCachedAsset({
        ...req.body,
        _id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
        networkId,
      });
      registerKnownMac(networkId, asset.mac || '');
      res.status(201).json(asset);
      return;
    }

    const asset = new Asset({ ...req.body, networkId });
    await asset.save();
    registerKnownMac(networkId, asset.mac || '');
    await refreshCache();
    res.status(201).json(asset);
  } catch (error) {
    console.error('❌ Error al crear asset:', error);
    res.status(400).json({ message: 'No fue posible crear el activo' });
  }
});

// Import masivo de activos (acepta JSON array de activos)
app.post('/api/assets/import', async (req, res) => {
  try {
    const items = Array.isArray(req.body) ? req.body : [];
    if (items.length === 0) return res.status(400).json({ message: 'Payload inválido' });

    const rawNetworkId = String(
      req.query.networkId || getNetworkContext().activeNetworkId || 'default'
    );
    const networkId = normalizeNetworkId(rawNetworkId) || 'default';

    const saved: any[] = [];
    if (!isMongoReady()) {
      for (const incoming of items) {
        const asset = upsertCachedAsset({
          ...incoming,
          _id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
          networkId,
        });
        registerKnownMac(networkId, asset.mac || '');
        saved.push(asset);
      }
      await refreshCache();
      return res.status(201).json({ created: saved.length, items: saved });
    }

    // Persistir en DB
    const toInsert = items.map((i) => ({ ...i, networkId }));
    const created = await Asset.insertMany(toInsert, { ordered: false }).catch((e) => {
      // ignorar errores parciales
      console.warn('Import parcial:', e?.message || e);
      return [];
    });
    for (const a of created || []) registerKnownMac(networkId, a.mac || '');
    await refreshCache();
    res.status(201).json({ created: (created || []).length });
  } catch (error) {
    console.error('Error en import:', error);
    res.status(500).json({ message: 'Error interno al importar activos' });
  }
});

app.delete('/api/assets/:id', async (req, res) => {
  try {
    if (!isMongoReady()) {
      const removed = deleteCachedAsset(req.params.id);
      if (!removed) return res.status(404).json({ message: 'Activo no encontrado' });
      res.json({ message: 'Eliminado' });
      return;
    }

    await Asset.findByIdAndDelete(req.params.id);
    await refreshCache();
    res.json({ message: 'Eliminado' });
  } catch (error) {
    console.error('❌ Error al eliminar:', error);
    res.status(500).json({ message: 'No fue posible eliminar el activo' });
  }
});

// Eliminar un workspace y sus activos asociados (DB + caché en memoria)
app.delete('/api/workspaces/:id', async (req, res) => {
  try {
    const raw = String(req.params.id || '').trim();
    const networkId = normalizeNetworkId(raw);
    if (!networkId) return res.status(400).json({ message: 'Workspace inválido' });

    if (!isMongoReady()) {
      // Solo caché en memoria
      const before = cachedAssets.length;
      cachedAssets = cachedAssets.filter((a) => a.networkId !== networkId);
      const removed = before - cachedAssets.length;
      await refreshCache();
      return res.json({ deleted: true, removed });
    }

    // Borrar en la BD y luego limpiar caché
    await withDbCache(async () => {
      await Asset.deleteMany({ networkId });
      return true;
    }, false);

    const before = cachedAssets.length;
    cachedAssets = cachedAssets.filter((a) => a.networkId !== networkId);
    const removed = before - cachedAssets.length;
    knownMacPerNetwork.delete(networkId);
    for (let i = securityEvents.length - 1; i >= 0; i--) {
      if (securityEvents[i]?.networkId === networkId) securityEvents.splice(i, 1);
    }
    await refreshCache();

    pushSecurityEvent({
      type: 'NEW_UNKNOWN_DEVICE',
      networkId,
      ip: '0.0.0.0',
      mac: '00:00:00:00:00:00',
      message: `Workspace ${networkId} eliminado por petición API`,
    });

    return res.json({ deleted: true, removed });
  } catch (error) {
    console.error('❌ Error al eliminar workspace:', error);
    return res.status(500).json({ message: 'Error interno' });
  }
});

// Quick action: isolate an asset (simulated)
app.post('/api/assets/:id/isolate', async (req, res) => {
  try {
    const assetId = String(req.params.id || '');
    const asset = cachedAssets.find((a) => String(a._id) === assetId);
    pushSecurityEvent({
      type: 'NEW_UNKNOWN_DEVICE',
      networkId: asset?.networkId ?? 'unknown',
      ip: asset?.ip ?? '0.0.0.0',
      mac: asset?.mac ?? '00:00:00:00:00:00',
      message: `Aislamiento remoto solicitado para ${assetId}`,
    });
    // Simulate action accepted
    res.status(200).json({ status: 'accepted', action: 'isolate', assetId });
  } catch (e) {
    res.status(500).json({ message: 'Error al procesar aislamiento' });
  }
});

// Quick action: block IP via firewall (simulated)
app.post('/api/firewall/block', async (req, res) => {
  try {
    const ip = String(req.body?.ip || '');
    if (!ip) return res.status(400).json({ message: 'IP requerida' });
    pushSecurityEvent({
      type: 'DOUBLE_AGENT',
      networkId: 'operator',
      ip,
      mac: '00:00:00:00:00:00',
      message: `Solicitud de bloqueo de IP ${ip}`,
    });
    res.status(202).json({ status: 'queued', ip });
  } catch {
    res.status(500).json({ message: 'Error al encolar bloqueo' });
  }
});

// Feedback endpoint (stores in-memory and returns receipt id)
app.post('/api/feedback', async (req, res) => {
  try {
    const { email, message } = req.body ?? {};
    if (!message || String(message).trim().length === 0) return res.status(400).json({ message: 'Mensaje requerido' });
    const entry = pushFeedback({ email: String(email || ''), message: String(message) });
    res.status(201).json({ received: true, id: entry.id });
  } catch (e) {
    res.status(500).json({ message: 'Error interno' });
  }
});

app.put('/api/assets/:id', async (req, res) => {
  try {
    if (!isMongoReady()) {
      const updated = updateCachedAsset(req.params.id, req.body);
      if (!updated) return res.status(404).json({ message: 'Activo no encontrado' });
      res.json(updated);
      return;
    }

    const updated = await Asset.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });
    if (!updated) return res.status(404).json({ message: 'Activo no encontrado' });
    await refreshCache();
    res.json(updated);
  } catch (error) {
    console.error('❌ Error al actualizar:', error);
    res.status(500).json({ message: 'No fue posible actualizar el activo' });
  }
});

app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    mongoReady: isMongoReady(),
    radarEnabled: isRadarEnabled,
    cachedAssets: cachedAssets.length,
    uptimeSeconds: Math.round(process.uptime()),
  });
});

app.post('/api/scan', validateScanTarget, scanRateLimiter.middleware, async (req, res) => {
  const ip = String(req.body.ip).trim();
  const mode = req.body.mode === 'stealth' ? 'stealth' : 'normal';
  const openServices: ServiceScan[] = [];

  console.log(`🎯 [Scanner] Iniciando escaneo de puertos cruzando a -> ${ip} (Modo: ${mode})`);

  const scanPort = (port: number): Promise<void> => {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(1100);

      socket.on('connect', async () => {
        socket.destroy();
        const banner = await getServiceBanner(ip, port);
        const fingerprint = [80, 443].includes(port)
          ? await getHttpFingerprint(ip, port)
          : 'Fingerprint no aplica';
        console.log(`🔓 [Scanner] Puerto ${port} ABIERTO en ${ip}. Fingerprint: ${fingerprint}`);
        openServices.push({ port, banner, fingerprint });
        resolve();
      });

      socket.on('error', () => resolve());
      socket.on('timeout', () => {
        socket.destroy();
        resolve();
      });

      socket.connect(port, ip);
    });
  };

  if (mode === 'stealth') {
    for (const port of PORTS_TO_SCAN) {
      await scanPort(port);
      await sleep(5000);
    }
  } else {
    await Promise.all(PORTS_TO_SCAN.map((port) => scanPort(port)));
  }

  const openPorts = openServices.map((service) => service.port).sort((a, b) => a - b);
  const risks = getRiskCards(openPorts);
  const cvssLikeScore = computeCvssLikeScore(openPorts, risks);

  // Construir recomendaciones simplificadas tipo CVE para los puertos abiertos
  const recommendations = openPorts.flatMap((port) => {
    const info = PORT_CVE_MAP[port];
    if (!info) return [];
    return [{ port, ...info }];
  });

  if (!isMongoReady()) {
    const match = cachedAssets.find((asset) => asset.ip === ip);
    if (match) {
      updateCachedAsset(String(match._id), {
        services: openServices,
        lastScanAt: new Date(),
        lastScanMode: mode,
      });
    }
  } else {
    await withDbCache(async () => {
      await Asset.findOneAndUpdate(
        { ip },
        {
          $set: {
            services: openServices,
            lastScanAt: new Date(),
            lastScanMode: mode,
          },
        },
        { new: true }
      );
      return true;
    }, false);
  }

  await refreshCache();
  res.json({
    ip,
    mode,
    openPorts,
    services: openServices,
    risks,
    cvssLikeScore,
    recommendations,
  });
});

const startRadarRuntime = () => {
  void registerLocalHost();
  void autoDiscoverDevices();
  setInterval(scanNetwork, 3 * 60 * 1000);
  setInterval(autoDiscoverDevices, 20 * 1000);
};

export const startServer = async (port = PORT) => {
  try {
    await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 });
    console.log('✅ Conectado a MongoDB Atlas');
  } catch (err) {
    console.error('❌ Error de conexión a MongoDB:', err);
    console.log(`🚀 Iniciando de todas formas en modo Offline / Fallback en memoria.`);
  }

  await refreshCache();
  for (const asset of cachedAssets) registerKnownMac(asset.networkId || 'default', asset.mac || '');

  console.log(`🚀 Radar H.A.D.A activo localmente. Autodescubrimiento iniciado...`);
  startRadarRuntime();

  return app.listen(port, () => {
    console.log(`🚀 H.A.D.A. escuchando en http://localhost:${port}`);
  });
};

const isMainModule =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMainModule) {
  void startServer();
}
