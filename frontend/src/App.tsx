import { useCallback, useEffect, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { Toaster, toast } from 'react-hot-toast';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import './App.css';

// Modelo básico del inventario de red que consume el frontend.
interface Asset {
  _id: string;
  hostname: string;
  ip: string;
  mac: string;
  os: string;
  criticality: number;
  status: 'Active' | 'Down' | 'Compromised';
}

// Resultado persistido de un escaneo de puertos para un activo.
interface PortScanResult {
  openPorts: number[];
  timestamp: string;
  vulnerable: boolean;
}

type AssetFormState = {
  hostname: string;
  ip: string;
  mac: string;
  os: string;
  criticality: number;
  status: Asset['status'];
};

const API_BASE = 'http://localhost:3001/api';
const SCAN_STORAGE_KEY = 'hada_port_scans';
const RAR_STORAGE_KEY = 'hada_radar_active';
const TTL_STORAGE_KEY = 'hada_ttl_seconds';
const DEFAULT_TTL = 10;

const STATUS_ORDER: Asset['status'][] = ['Active', 'Compromised', 'Down'];

const STATUS_LABELS: Record<Asset['status'], string> = {
  Active: 'Operativo',
  Down: 'Caído',
  Compromised: 'Comprometido',
};

const STATUS_COLORS: Record<Asset['status'], string> = {
  Active: '#22c55e',
  Down: '#94a3b8',
  Compromised: '#f43f5e',
};

const OS_COLORS = ['#2dd4bf', '#60a5fa', '#818cf8', '#f59e0b'];

function readJSON<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function getAssetProfile(asset: Asset) {
  const profile = asset.os.toLowerCase();
  const hostname = asset.hostname.toLowerCase();

  const isRouterLike = /router|switch|gateway|firewall|shenzhen|vendor/i.test(profile) || /router|gateway/i.test(hostname);
  const isWindows = profile.includes('windows');
  const isUnix = profile.includes('linux') || profile.includes('android') || profile.includes('ios');

  if (isRouterLike) return 'Edge / Fabricante de red';
  if (isWindows) return 'Endpoint Windows';
  if (isUnix) return 'Linux / Móvil';
  return 'Perfil genérico';
}

function getCriticalityHint(asset: Asset, latestScan?: PortScanResult) {
  const ports = latestScan?.openPorts.length ?? 0;
  if (asset.criticality >= 8) return 'Alta por diseño: activo sensible o expuesto.';
  if (ports >= 4) return 'Alta exposición: varios puertos críticos abiertos.';
  if (ports >= 1) return 'Exposición moderada: revisar superficie de ataque.';
  return 'Baja exposición visible en el último escaneo.';
}

function getRiskScore(asset: Asset, latestScan?: PortScanResult) {
  const openPorts = latestScan?.openPorts.length ?? 0;
  const base = asset.criticality;
  const scanBonus = Math.min(3, openPorts);
  const statusBonus = asset.status === 'Compromised' ? 3 : asset.status === 'Down' ? 1 : 0;
  return Math.min(10, base + scanBonus + statusBonus);
}

function formatDate(value?: string) {
  if (!value) return 'Sin datos';
  return new Date(value).toLocaleString();
}

function App() {
  // Inventario principal.
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);

  // Escaneos persistidos por activo.
  const [portScans, setPortScans] = useState<Record<string, PortScanResult[]>>(() => readJSON(SCAN_STORAGE_KEY, {}));

  // Panel de detalle.
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [showModal, setShowModal] = useState(false);

  // Radar configurable.
  const [radarActive, setRadarActive] = useState(() => localStorage.getItem(RAR_STORAGE_KEY) !== 'false');
  const [ttlSeconds, setTtlSeconds] = useState(() => {
    const value = Number(localStorage.getItem(TTL_STORAGE_KEY) ?? DEFAULT_TTL);
    return Number.isFinite(value) && value > 0 ? value : DEFAULT_TTL;
  });

  // Formulario de alta de activos.
  const [form, setForm] = useState<AssetFormState>({
    hostname: '',
    ip: '',
    mac: '00:00:00:00:00:00',
    os: '',
    criticality: 5,
    status: 'Active',
  });

  // Cálculos del dashboard.
  const totalAssets = assets.length;
  const activeAssets = assets.filter((asset) => asset.status === 'Active').length;
  const compromisedAssets = assets.filter((asset) => asset.status === 'Compromised').length;
  const downAssets = assets.filter((asset) => asset.status === 'Down').length;

  const latestScanForSelected = selectedAsset ? portScans[selectedAsset._id]?.[0] : undefined;

  const osDistribution = assets
    .reduce<Record<string, number>>((accumulator, asset) => {
      const key = asset.os?.trim() || 'Sin perfil';
      accumulator[key] = (accumulator[key] ?? 0) + 1;
      return accumulator;
    }, {})
    ;

  const osChartData = Object.entries(osDistribution)
    .map(([name, value], index) => ({ name, value, color: OS_COLORS[index % OS_COLORS.length] }))
    .sort((left, right) => right.value - left.value)
    .slice(0, 5);

  const statusChartData = STATUS_ORDER.map((status) => ({
    status,
    count: assets.filter((asset) => asset.status === status).length,
    fill: STATUS_COLORS[status],
  }));

  const fetchAssets = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/assets`);
      if (!response.ok) throw new Error('No fue posible leer el inventario');
      const data = (await response.json()) as Asset[];
      setAssets(data);
      setLoading(false);
    } catch (error) {
      console.error('Error al conectar con el backend:', error);
      toast.error('No se pudo cargar el inventario');
      setLoading(false);
    }
  }, []);

  const persistScanResult = (assetId: string, result: PortScanResult) => {
    setPortScans((previous) => {
      const next = {
        ...previous,
        [assetId]: [result, ...(previous[assetId] ?? [])].slice(0, 20),
      };
      localStorage.setItem(SCAN_STORAGE_KEY, JSON.stringify(next));
      return next;
    });
  };

  const handleCreateAsset = async (event: FormEvent) => {
    event.preventDefault();

    try {
      const response = await fetch(`${API_BASE}/assets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hostname: form.hostname.trim(),
          ip: form.ip.trim(),
          mac: form.mac.trim(),
          os: form.os.trim(),
          criticality: form.criticality,
          status: form.status,
        }),
      });

      if (!response.ok) throw new Error('No fue posible crear el activo');

      setForm({
        hostname: '',
        ip: '',
        mac: '00:00:00:00:00:00',
        os: '',
        criticality: 5,
        status: 'Active',
      });
      toast.success('Activo registrado en el inventario');
      await fetchAssets();
    } catch (error) {
      console.error('Error al guardar:', error);
      toast.error('No se pudo registrar el activo');
    }
  };

  const handleDelete = async (id: string) => {
    try {
      const response = await fetch(`${API_BASE}/assets/${id}`, { method: 'DELETE' });
      if (!response.ok) throw new Error('No fue posible eliminar el activo');
      toast.success('Activo eliminado de la red');
      await fetchAssets();
    } catch (error) {
      console.error('Error al eliminar:', error);
      toast.error('Fallo al intentar eliminar el activo');
    }
  };

  const handleStatusChange = async (id: string, currentStatus: Asset['status']) => {
    const nextStatus: Asset['status'] = currentStatus === 'Active' ? 'Down' : currentStatus === 'Down' ? 'Compromised' : 'Active';

    try {
      const response = await fetch(`${API_BASE}/assets/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: nextStatus }),
      });

      if (!response.ok) throw new Error('No fue posible cambiar el estado');
      await fetchAssets();

      if (nextStatus === 'Compromised') {
        toast.error('Activo comprometido', { icon: '🚨' });
      } else if (nextStatus === 'Active') {
        toast.success('Activo restaurado', { icon: '🛡️' });
      } else {
        toast('Activo marcado como offline', { icon: '⚠️' });
      }
    } catch (error) {
      console.error('Error al cambiar estado:', error);
      toast.error('Error de conexión con el backend');
    }
  };

  const handleScan = async (asset: Asset) => {
    const loadingId = `scan-${asset._id}`;
    toast.loading(`Escaneando ${asset.hostname}...`, { id: loadingId });

    try {
      const response = await fetch(`${API_BASE}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: asset.ip }),
      });

      if (!response.ok) throw new Error('El escaneo falló');
      const data = (await response.json()) as { openPorts?: number[] };
      const openPorts = Array.isArray(data.openPorts) ? data.openPorts : [];

      const result: PortScanResult = {
        openPorts,
        timestamp: new Date().toISOString(),
        vulnerable: openPorts.length > 0,
      };

      persistScanResult(asset._id, result);

      if (openPorts.length > 0) {
        toast.success(`Puertos encontrados: ${openPorts.length}`, { id: loadingId });
      } else {
        toast.success('Sin puertos abiertos detectados', { id: loadingId });
      }
    } catch (error) {
      console.error('Error en escaneo:', error);
      toast.error('Error al ejecutar el escaneo', { id: loadingId });
    }
  };

  const openAssetModal = (asset: Asset) => {
    setSelectedAsset(asset);
    setShowModal(true);
  };

  useEffect(() => {
    const controller = new AbortController();
    void fetchAssets();
    return () => controller.abort();
  }, [fetchAssets]);

  useEffect(() => {
    if (!radarActive) return;
    const timer = window.setInterval(() => {
      void fetchAssets();
    }, Math.max(1000, ttlSeconds * 1000));

    return () => window.clearInterval(timer);
  }, [fetchAssets, radarActive, ttlSeconds]);

  useEffect(() => {
    localStorage.setItem(RAR_STORAGE_KEY, String(radarActive));
  }, [radarActive]);

  useEffect(() => {
    localStorage.setItem(TTL_STORAGE_KEY, String(ttlSeconds));
  }, [ttlSeconds]);

  return (
    <div className="hada-shell min-h-screen text-slate-100">
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: '#0e1428',
            color: '#f8fafc',
            border: '1px solid rgba(125, 211, 252, 0.25)',
          },
        }}
      />

      {/* Capa atmosférica tipo interfaz futurista. */}
      <div className="hada-bg-glow" aria-hidden="true" />
      <div className="hada-bg-grid" aria-hidden="true" />

      <main className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-4 py-6 sm:px-6 lg:px-8">
        <header className="hada-header">
          <div className="space-y-1">
            <p className="hada-kicker">Cyber Operations Interface</p>
            <h1 className="hada-title" data-text="H.A.D.A">
              H.A.D.A
            </h1>
            <p className="text-sm text-slate-300/80 sm:text-base">
              Hub de Analisis y Defensa Avanzada
            </p>
          </div>

          <div className="hada-controls">
            <div className="control-chip">
              <span className="control-label">Radar</span>
              <button
                type="button"
                className={`control-button ${radarActive ? 'is-on' : 'is-off'}`}
                onClick={() => setRadarActive((value) => !value)}
              >
                {radarActive ? 'ACTIVO' : 'PAUSADO'}
              </button>
            </div>
            <label className="control-chip">
              <span className="control-label">TTL</span>
              <input
                type="number"
                min={1}
                max={120}
                value={ttlSeconds}
                onChange={(event) => setTtlSeconds(Number(event.target.value) || DEFAULT_TTL)}
                className="control-input"
              />
            </label>
            <button type="button" className="ghost-button" onClick={() => void fetchAssets()}>
              Refrescar
            </button>
          </div>
        </header>

        {compromisedAssets > 0 && (
          <section className="alert-strip">
            <span className="alert-title">Alerta activa</span>
            <span>{compromisedAssets} activo(s) comprometido(s) requieren atención.</span>
          </section>
        )}

        <section className="stats-grid">
          <MetricCard label="Total en Red" value={totalAssets} tone="blue" />
          <MetricCard label="Operativos" value={activeAssets} tone="green" />
          <MetricCard label="Bajo Ataque" value={compromisedAssets} tone="rose" pulse={compromisedAssets > 0} />
          <MetricCard label="Offline / Down" value={downAssets} tone="amber" />
        </section>

        <section className="info-grid">
          <article className="panel panel-form">
            <div className="panel-header">
              <div>
                <h2>Registrar activo</h2>
                <p>Completa los campos que el backend realmente usa para el inventario.</p>
              </div>
              <div className="panel-note">Base: hostname, IP, MAC, OS/fabricante, criticidad y estado</div>
            </div>

            <form className="space-y-4" onSubmit={handleCreateAsset}>
              <Field label="Hostname" hint="Ej. RTKGW-BWROUTER" required>
                <input
                  type="text"
                  value={form.hostname}
                  onChange={(event) => setForm((previous) => ({ ...previous, hostname: event.target.value }))}
                  className="field-input"
                  placeholder="Nombre del dispositivo"
                  required
                />
              </Field>

              <div className="grid gap-4 md:grid-cols-2">
                <Field label="Dirección IP" hint="Red interna o segmento descubierto" required>
                  <input
                    type="text"
                    value={form.ip}
                    onChange={(event) => setForm((previous) => ({ ...previous, ip: event.target.value }))}
                    className="field-input"
                    placeholder="192.168.1.1"
                    required
                  />
                </Field>

                <Field label="Dirección MAC" hint="Se guarda tal cual en el backend">
                  <input
                    type="text"
                    value={form.mac}
                    onChange={(event) => setForm((previous) => ({ ...previous, mac: event.target.value }))}
                    className="field-input"
                    placeholder="AA:BB:CC:DD:EE:FF"
                  />
                </Field>
              </div>

              <Field label="Perfil / Fabricante / OS" hint="Aquí suele entrar el vendor detectado por auto-discovery">
                <input
                  type="text"
                  value={form.os}
                  onChange={(event) => setForm((previous) => ({ ...previous, os: event.target.value }))}
                  className="field-input"
                  placeholder="Shenzhen, Windows, Linux, Router..."
                  required
                />
              </Field>

              <div className="grid gap-4 md:grid-cols-2">
                <Field label="Criticidad" hint="1 = baja exposición, 10 = sistema altamente sensible">
                  <div className="space-y-2">
                    <input
                      type="range"
                      min={1}
                      max={10}
                      title="Nivel de criticidad"
                      placeholder="5"
                      value={form.criticality}
                      onChange={(event) => setForm((previous) => ({ ...previous, criticality: Number(event.target.value) }))}
                      className="range-input"
                    />
                    <div className="flex items-center justify-between text-xs text-slate-400">
                      <span>Baja</span>
                      <span className="font-semibold text-slate-100">Nivel {form.criticality}</span>
                      <span>Alta</span>
                    </div>
                  </div>
                </Field>

                <Field label="Estado inicial" hint="Puedes dejarlo como Active y cambiarlo luego">
                  <select
                    title="Estado inicial del activo"
                    value={form.status}
                    onChange={(event) => setForm((previous) => ({ ...previous, status: event.target.value as Asset['status'] }))}
                    className="field-input"
                  >
                    <option value="Active">Active</option>
                    <option value="Down">Down</option>
                    <option value="Compromised">Compromised</option>
                  </select>
                </Field>
              </div>

              <div className="flex flex-wrap gap-3 pt-2">
                <button type="submit" className="primary-button">
                  Guardar en Inventario
                </button>
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() =>
                    setForm({
                      hostname: '',
                      ip: '',
                      mac: '00:00:00:00:00:00',
                      os: '',
                      criticality: 5,
                      status: 'Active',
                    })
                  }
                >
                  Limpiar
                </button>
              </div>
            </form>
          </article>

          <article className="panel panel-chart">
            <div className="panel-header">
              <div>
                <h2>Distribución OS / Vendor</h2>
                <p>Uso como mapa rápido de plataformas y fabricantes detectados.</p>
              </div>
            </div>

            <div className="chart-wrap">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={osChartData} dataKey="value" innerRadius={62} outerRadius={88} paddingAngle={4}>
                    {osChartData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} stroke="none" />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      border: '1px solid rgba(125, 211, 252, 0.2)',
                      borderRadius: '12px',
                      color: '#f8fafc',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="panel-divider" />

            <div className="mini-bars">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={statusChartData} barSize={24}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148, 163, 184, 0.2)" vertical={false} />
                  <XAxis dataKey="status" tick={{ fill: '#cbd5e1', fontSize: 12 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#cbd5e1', fontSize: 12 }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      border: '1px solid rgba(125, 211, 252, 0.2)',
                      borderRadius: '12px',
                      color: '#f8fafc',
                    }}
                  />
                  <Legend />
                  <Bar dataKey="count" radius={[12, 12, 0, 0]}>
                    {statusChartData.map((entry) => (
                      <Cell key={entry.status} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </article>
        </section>

        <section className="panel panel-table">
          <div className="panel-header">
            <div>
              <h2>Inventario de red</h2>
              <p>Haz clic en un dispositivo para abrir su panel de detalle y ver datos persistidos.</p>
            </div>
          </div>

          {loading ? (
            <p className="state-text">Escaneando base de datos...</p>
          ) : assets.length === 0 ? (
            <p className="state-text">No hay activos registrados. Empieza con el formulario de arriba.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="hada-table">
                <thead>
                  <tr>
                    <th>Dispositivo</th>
                    <th>Red</th>
                    <th>Perfil</th>
                    <th>Criticidad</th>
                    <th>Estado</th>
                    <th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  {assets.map((asset) => {
                    const latestScan = portScans[asset._id]?.[0];
                    const riskScore = getRiskScore(asset, latestScan);
                    return (
                      <tr key={asset._id} onClick={() => openAssetModal(asset)}>
                        <td>
                          <div className="asset-name">{asset.hostname}</div>
                          <div className="asset-subtext">ID {asset._id.slice(-6)}</div>
                        </td>
                        <td>
                          <div className="mono-strong">{asset.ip}</div>
                          <div className="asset-subtext">{asset.mac || 'Sin MAC'}</div>
                        </td>
                        <td>
                          <div className="asset-profile">{asset.os}</div>
                          <div className="asset-subtext">{getAssetProfile(asset)}</div>
                        </td>
                        <td>
                          <div className="criticality-wrap">
                            <span className={`criticality-dot level-${asset.criticality >= 8 ? 'high' : asset.criticality >= 5 ? 'mid' : 'low'}`} />
                            <span>Nivel {asset.criticality}</span>
                          </div>
                          <div className="asset-subtext">Riesgo sugerido {riskScore}/10</div>
                        </td>
                        <td>
                          <StatusBadge status={asset.status} />
                        </td>
                        <td>
                          <div className="action-row" onClick={(event) => event.stopPropagation()}>
                            <button type="button" className="action-button scan" onClick={() => void handleScan(asset)}>
                              Scan
                            </button>
                            <button type="button" className="action-button status" onClick={() => void handleStatusChange(asset._id, asset.status)}>
                              Mod
                            </button>
                            <button type="button" className="action-button danger" onClick={() => void handleDelete(asset._id)}>
                              Del
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </main>

      {showModal && selectedAsset && (
        <AssetModal
          asset={selectedAsset}
          scans={portScans[selectedAsset._id] ?? []}
          latestScan={latestScanForSelected}
          onClose={() => setShowModal(false)}
          onScan={() => void handleScan(selectedAsset)}
        />
      )}
    </div>
  );
}

function MetricCard({
  label,
  value,
  tone,
  pulse = false,
}: {
  label: string;
  value: number;
  tone: 'blue' | 'green' | 'rose' | 'amber';
  pulse?: boolean;
}) {
  return (
    <article className={`metric-card tone-${tone} ${pulse ? 'is-pulse' : ''}`}>
      <span className="metric-label">{label}</span>
      <span className="metric-value">{value}</span>
    </article>
  );
}

function Field({
  label,
  hint,
  required = false,
  children,
}: {
  label: string;
  hint?: string;
  required?: boolean;
  children: ReactNode;
}) {
  return (
    <label className="field">
      <span className="field-label">
        {label}
        {required ? <span className="field-required">*</span> : null}
      </span>
      {hint ? <span className="field-hint">{hint}</span> : null}
      {children}
    </label>
  );
}

function StatusBadge({ status }: { status: Asset['status'] }) {
  return <span className={`status-badge status-${status.toLowerCase()}`}>{STATUS_LABELS[status]}</span>;
}

function AssetModal({
  asset,
  scans,
  latestScan,
  onClose,
  onScan,
}: {
  asset: Asset;
  scans: PortScanResult[];
  latestScan?: PortScanResult;
  onClose: () => void;
  onScan: () => void;
}) {
  const riskScore = getRiskScore(asset, latestScan);
  const criticalityHint = getCriticalityHint(asset, latestScan);

  return (
    <div className="modal-backdrop">
      <div className="modal-card">
        <div className="modal-header">
          <div>
            <p className="modal-kicker">Detalle de dispositivo</p>
            <h3 className="modal-title">{asset.hostname}</h3>
            <p className="modal-subtitle">{asset.ip} • {asset.mac}</p>
          </div>

          <div className="modal-actions">
            <button type="button" className="primary-button small" onClick={onScan}>
              Re-scan
            </button>
            <button type="button" className="secondary-button small" onClick={onClose}>
              Cerrar
            </button>
          </div>
        </div>

        <div className="modal-grid">
          <section className="detail-card">
            <span className="detail-label">Perfil detectado</span>
            <strong>{asset.os}</strong>
            <p>{getAssetProfile(asset)}</p>
          </section>
          <section className="detail-card">
            <span className="detail-label">Criticidad actual</span>
            <strong>{asset.criticality}/10</strong>
            <p>{criticalityHint}</p>
          </section>
          <section className="detail-card">
            <span className="detail-label">Riesgo sugerido</span>
            <strong>{riskScore}/10</strong>
            <p>Calculado con criticidad, estado y puertos abiertos recientes.</p>
          </section>
          <section className="detail-card">
            <span className="detail-label">Último escaneo</span>
            <strong>{latestScan ? formatDate(latestScan.timestamp) : 'Sin escaneos'}</strong>
            <p>{latestScan ? `${latestScan.openPorts.length} puerto(s) abierto(s)` : 'Ejecuta un scan para guardar evidencia local.'}</p>
          </section>
        </div>

        <div className="modal-columns">
          <section className="modal-panel">
            <h4>Puertos y hallazgos guardados</h4>
            {scans.length === 0 ? (
              <p className="state-text">Aún no hay resultados persistidos para este dispositivo.</p>
            ) : (
              <div className="scan-list">
                {scans.map((scan, index) => (
                  <article key={`${scan.timestamp}-${index}`} className="scan-item">
                    <div className="scan-item-top">
                      <span>{formatDate(scan.timestamp)}</span>
                      <span className={`scan-pill ${scan.vulnerable ? 'is-danger' : 'is-safe'}`}>
                        {scan.vulnerable ? 'Expuesto' : 'Limpio'}
                      </span>
                    </div>
                    <div className="scan-ports">
                      {scan.openPorts.length > 0 ? scan.openPorts.join(', ') : 'Sin puertos abiertos detectados'}
                    </div>
                  </article>
                ))}
              </div>
            )}
          </section>

          <section className="modal-panel">
            <h4>Resumen rápido</h4>
            <div className="summary-grid">
              <div>
                <span className="summary-label">Host</span>
                <strong>{asset.hostname}</strong>
              </div>
              <div>
                <span className="summary-label">IP</span>
                <strong>{asset.ip}</strong>
              </div>
              <div>
                <span className="summary-label">MAC</span>
                <strong>{asset.mac}</strong>
              </div>
              <div>
                <span className="summary-label">Estado</span>
                <StatusBadge status={asset.status} />
              </div>
            </div>
            <div className="insight-box">
              <p>El backend actual registra fabricante/OS detectado dentro de <strong>os</strong>, por eso aquí verás marcas como router, vendor o Windows según el auto-discovery del servidor.</p>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

export default App;
