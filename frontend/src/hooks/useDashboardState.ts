import { useCallback, useEffect, useMemo, useState } from 'react';
import { toast } from 'react-hot-toast';
import useWorkspace from './useWorkspace';
import { resolveVulnerabilities } from '../utils/vulnerabilities';
import type { Asset, NetworkWorkspace } from '../types';

const API_BASE = 'http://localhost:3001/api';
const RAR_STORAGE_KEY = 'hada_radar_active';
const TTL_STORAGE_KEY = 'hada_ttl_seconds';
const WORKSPACES_KEY = 'hada_network_workspaces';
const ACTIVE_WORKSPACE_KEY = 'hada_network_workspace_active';
const WORKSPACE_SETTINGS_KEY = 'hada_workspace_settings';
const DEFAULT_TTL = 10;

const STATUS_ORDER: Asset['status'][] = ['Active', 'Compromised', 'Down'];
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

export default function useDashboardState() {
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [radarActive, setRadarActive] = useState(
    () => localStorage.getItem(RAR_STORAGE_KEY) !== 'false'
  );
  const TELEMETRY_KEY = 'hada_telemetry';
  const [telemetryEnabled, setTelemetryEnabled] = useState(
    () => localStorage.getItem(TELEMETRY_KEY) !== 'false'
  );
  const THEME_KEY = 'hada_theme';
  const [darkMode, setDarkMode] = useState(
    () => (localStorage.getItem(THEME_KEY) || 'dark') !== 'light'
  );
  const ANIMATION_KEY = 'hada_animations';
  const [animationsEnabled, setAnimationsEnabled] = useState(
    () => localStorage.getItem(ANIMATION_KEY) !== 'false'
  );
  const PAN_LOCK_KEY = 'hada_pan_locked';
  const [panLocked, setPanLocked] = useState(() => localStorage.getItem(PAN_LOCK_KEY) === 'true');
  const [ttlSeconds, setTtlSeconds] = useState(() => {
    const value = Number(localStorage.getItem(TTL_STORAGE_KEY) ?? DEFAULT_TTL);
    return Number.isFinite(value) && value > 0 ? value : DEFAULT_TTL;
  });
  const [workspaces, setWorkspaces] = useState<NetworkWorkspace[]>(() => {
    const initial = readJSON<NetworkWorkspace[]>(WORKSPACES_KEY, []);
    return initial.length > 0 ? initial : [{ id: 'default', label: 'Red Default' }];
  });
  const [activeWorkspaceId, setActiveWorkspaceId] = useState(
    () =>
      localStorage.getItem(ACTIVE_WORKSPACE_KEY) ??
      readJSON<NetworkWorkspace[]>(WORKSPACES_KEY, [{ id: 'default', label: 'Red Default' }])[0].id
  );
  // load per-workspace overrides on workspace change
  useEffect(() => {
    const settings = readJSON<Record<string, Record<string, any>>>(WORKSPACE_SETTINGS_KEY, {});
    const workspaceSettings = settings[activeWorkspaceId] ?? {};
    if (typeof workspaceSettings.darkMode === 'boolean') setDarkMode(workspaceSettings.darkMode);
    if (typeof workspaceSettings.telemetryEnabled === 'boolean')
      setTelemetryEnabled(workspaceSettings.telemetryEnabled);
    if (typeof workspaceSettings.animationsEnabled === 'boolean')
      setAnimationsEnabled(workspaceSettings.animationsEnabled);
    if (typeof workspaceSettings.ttlSeconds === 'number') setTtlSeconds(workspaceSettings.ttlSeconds);
    if (typeof workspaceSettings.radarActive === 'boolean') setRadarActive(workspaceSettings.radarActive);
    if (typeof workspaceSettings.panLocked === 'boolean') setPanLocked(workspaceSettings.panLocked);
  }, [activeWorkspaceId]);
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | Asset['status']>('all');
  const [riskFilter, setRiskFilter] = useState<'all' | 'high' | 'medium' | 'low' | 'none'>('all');
  const {
    assets,
    loading,
    portScans,
    events,
    scanningAssetId,
    handleScan,
    cancelScan,
    handleCreateAsset,
    handleDelete,
    handleStatusChange,
    handleCriticalityChange,
    fetchAssets,
    handleImportAssets,
  } = useWorkspace(activeWorkspaceId, radarActive, ttlSeconds);

  const selectedScanKey = selectedAsset ? `${activeWorkspaceId}:${selectedAsset._id}` : '';
  const latestScanForSelected = selectedAsset ? portScans[selectedScanKey]?.[0] : undefined;

  const filteredAssets = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return assets.filter((asset) => {
      const scan = portScans[`${activeWorkspaceId}:${asset._id}`]?.[0];
      const vulnerabilities = resolveVulnerabilities(scan?.openPorts ?? [], scan?.risks);
      const hasHighRisk = vulnerabilities.some((risk) => risk.severity === 'high');
      const hasMediumRisk = vulnerabilities.some((risk) => risk.severity === 'medium');
      const hasLowRisk = vulnerabilities.some((risk) => risk.severity === 'low');

      const matchesText =
        normalizedQuery.length === 0 ||
        asset.hostname.toLowerCase().includes(normalizedQuery) ||
        asset.ip.toLowerCase().includes(normalizedQuery) ||
        asset.mac.toLowerCase().includes(normalizedQuery);

      const matchesStatus = statusFilter === 'all' || asset.status === statusFilter;
      const matchesRisk =
        riskFilter === 'all' ||
        (riskFilter === 'high' && hasHighRisk) ||
        (riskFilter === 'medium' && hasMediumRisk) ||
        (riskFilter === 'low' && hasLowRisk) ||
        (riskFilter === 'none' && vulnerabilities.length === 0);

      return matchesText && matchesStatus && matchesRisk;
    });
  }, [activeWorkspaceId, assets, portScans, query, riskFilter, statusFilter]);

  const totalAssets = filteredAssets.length;
  const activeAssets = filteredAssets.filter((asset) => asset.status === 'Active').length;
  const compromisedAssets = filteredAssets.filter((asset) => asset.status === 'Compromised').length;
  const downAssets = filteredAssets.filter((asset) => asset.status === 'Down').length;

  const currentMetrics = useMemo(
    () => ({
      total: totalAssets,
      active: activeAssets,
      compromised: compromisedAssets,
      down: downAssets,
    }),
    [activeAssets, compromisedAssets, downAssets, totalAssets]
  );

  const previousMetrics = useMemo(() => {
    const snapshot = readJSON<
      Record<string, { total: number; active: number; compromised: number; down: number }>
    >('hada_metric_snapshot', {});
    return snapshot[activeWorkspaceId] ?? currentMetrics;
  }, [activeWorkspaceId, currentMetrics]);

  const metricDeltas = useMemo(
    () => ({
      total: currentMetrics.total - previousMetrics.total,
      active: currentMetrics.active - previousMetrics.active,
      compromised: currentMetrics.compromised - previousMetrics.compromised,
      down: currentMetrics.down - previousMetrics.down,
    }),
    [currentMetrics, previousMetrics]
  );

  const duplicateMacDetected = useMemo(() => {
    const groups = new Map<string, Set<string>>();
    for (const asset of assets) {
      if (!asset.mac) continue;
      if (!groups.has(asset.mac)) groups.set(asset.mac, new Set());
      groups.get(asset.mac)?.add(asset.ip);
    }
    return Array.from(groups.values()).some((ips) => ips.size > 1);
  }, [assets]);

  const osDistribution = filteredAssets.reduce<Record<string, number>>((accumulator, asset) => {
    const key = asset.os?.trim() || 'Sin perfil';
    accumulator[key] = (accumulator[key] ?? 0) + 1;
    return accumulator;
  }, {});

  const osChartData = Object.entries(osDistribution)
    .map(([name, value], index) => ({
      name,
      value,
      color: OS_COLORS[index % OS_COLORS.length],
    }))
    .sort((left, right) => right.value - left.value)
    .slice(0, 5);

  const statusChartData = STATUS_ORDER.map((status) => ({
    status,
    count: filteredAssets.filter((asset) => asset.status === status).length,
    fill: STATUS_COLORS[status],
  }));

  const topologyData = useMemo(() => {
    const centerNodeId = `router-${activeWorkspaceId}`;
    const nodes = [
      { id: centerNodeId, label: activeWorkspaceId, type: 'router' as const },
      ...filteredAssets.map((asset) => ({
        id: asset._id,
        label: asset.hostname,
        type: 'device' as const,
        status: asset.status,
      })),
    ];

    const links = filteredAssets.map((asset) => ({
      source: centerNodeId,
      target: asset._id,
    }));
    return { nodes, links };
  }, [activeWorkspaceId, filteredAssets]);

  const upsertWorkspace = useCallback((workspace: NetworkWorkspace) => {
    setWorkspaces((previous) => {
      const exists = previous.some((item) => item.id === workspace.id);
      const next = exists ? previous : [...previous, workspace];
      localStorage.setItem(WORKSPACES_KEY, JSON.stringify(next));
      return next;
    });
  }, []);

  const openAssetModal = useCallback((asset: Asset) => {
    setSelectedAsset(asset);
    setShowModal(true);
  }, []);

  const handleCreateWorkspace = useCallback(() => {
    const label = window.prompt('Nombre de la red/workspace (ej: LAB-UNIVERSIDAD, CASA, OFICINA):');
    if (!label) return;
    const id = label.trim().toLowerCase().replace(/\s+/g, '-');
    if (!id) return;

    const workspace = { id, label: label.trim() };
    upsertWorkspace(workspace);
    setSelectedAsset(null);
    setShowModal(false);
    setActiveWorkspaceId(workspace.id);
  }, [upsertWorkspace]);

  const handleRemoveWorkspace = useCallback(
    (workspaceId: string) => {
      void (async () => {
        try {
          const response = await fetch(
            `${API_BASE}/workspaces/${encodeURIComponent(workspaceId)}`,
            { method: 'DELETE' }
          );
          if (!response.ok) throw new Error('No fue posible eliminar el workspace');
          const keep = workspaces.filter((w) => w.id !== workspaceId);
          const nextWorkspaces = keep.length > 0 ? keep : [{ id: 'default', label: 'Red Default' }];
          setWorkspaces(nextWorkspaces);
          localStorage.setItem(WORKSPACES_KEY, JSON.stringify(nextWorkspaces));
          if (activeWorkspaceId === workspaceId) {
            setActiveWorkspaceId(nextWorkspaces[0].id ?? 'default');
          }
          toast.success('Workspace eliminado');
        } catch (error) {
          console.error('Error al eliminar workspace:', error);
          toast.error('No se pudo eliminar el workspace');
        }
      })();
    },
    [activeWorkspaceId, workspaces]
  );

  const handleSelectWorkspace = useCallback((workspaceId: string) => {
    setSelectedAsset(null);
    setShowModal(false);
    setActiveWorkspaceId(workspaceId);
  }, []);

  const toggleRadar = useCallback(async () => {
    const nextState = !radarActive;
    setRadarActive(nextState);

    try {
      await fetch(`${API_BASE}/radar/control`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ active: nextState }),
      });
      toast(nextState ? 'Radar activado' : 'Radar pausado', {
        icon: nextState ? '📡' : '🛑',
      });
    } catch (error) {
      console.error('Error al sincronizar el estado del radar', error);
      toast.error('Error al comunicar pausa al servidor');
    }
  }, [radarActive]);

  const toggleTelemetry = useCallback(() => {
    const next = !telemetryEnabled;
    setTelemetryEnabled(next);
    localStorage.setItem(TELEMETRY_KEY, String(next));
    toast(next ? 'Telemetría activada' : 'Telemetría desactivada');
    const ws = readJSON<Record<string, any>>(WORKSPACE_SETTINGS_KEY, {});
    ws[activeWorkspaceId] = { ...(ws[activeWorkspaceId] ?? {}), telemetryEnabled: next };
    localStorage.setItem(WORKSPACE_SETTINGS_KEY, JSON.stringify(ws));
  }, [telemetryEnabled]);

  const toggleAnimations = useCallback(() => {
    const next = !animationsEnabled;
    setAnimationsEnabled(next);
    localStorage.setItem(ANIMATION_KEY, String(next));
    toast(next ? 'Animaciones activadas' : 'Animaciones desactivadas');
    const ws = readJSON<Record<string, any>>(WORKSPACE_SETTINGS_KEY, {});
    ws[activeWorkspaceId] = { ...(ws[activeWorkspaceId] ?? {}), animationsEnabled: next };
    localStorage.setItem(WORKSPACE_SETTINGS_KEY, JSON.stringify(ws));
  }, [animationsEnabled]);

  const togglePanLock = useCallback(() => {
    setPanLocked((prev) => {
      const next = !prev;
      localStorage.setItem(PAN_LOCK_KEY, String(next));
      toast(next ? 'Pan bloqueado' : 'Pan desbloqueado');
      const ws = readJSON<Record<string, any>>(WORKSPACE_SETTINGS_KEY, {});
      ws[activeWorkspaceId] = { ...(ws[activeWorkspaceId] ?? {}), panLocked: next };
      localStorage.setItem(WORKSPACE_SETTINGS_KEY, JSON.stringify(ws));
      return next;
    });
  }, []);

  useEffect(() => {
    const initFetch = async () => {
      try {
        const contextResponse = await fetch(`${API_BASE}/network/context`);
        if (contextResponse.ok) {
          const context = (await contextResponse.json()) as {
            activeNetworkId?: string;
            activeNetworkLabel?: string;
          };
          if (context.activeNetworkId) {
            const workspace = {
              id: context.activeNetworkId,
              label: context.activeNetworkLabel || context.activeNetworkId,
            };
            upsertWorkspace(workspace);
            const activeWorkspace = workspaces.find(
              (workspaceItem) => workspaceItem.id === activeWorkspaceId
            );
            if (
              !activeWorkspace ||
              activeWorkspaceId === 'default' ||
              !localStorage.getItem(ACTIVE_WORKSPACE_KEY)
            ) {
              setActiveWorkspaceId(workspace.id);
            }
          }
        }
      } catch {
        // no-op
      }
    };
    void initFetch();
  }, [activeWorkspaceId, upsertWorkspace, workspaces]);

  useEffect(() => {
    localStorage.setItem(ACTIVE_WORKSPACE_KEY, activeWorkspaceId);
  }, [activeWorkspaceId]);

  useEffect(() => {
    localStorage.setItem(RAR_STORAGE_KEY, String(radarActive));
    localStorage.setItem(TTL_STORAGE_KEY, String(ttlSeconds));
    const ws = readJSON<Record<string, any>>(WORKSPACE_SETTINGS_KEY, {});
    ws[activeWorkspaceId] = { ...(ws[activeWorkspaceId] ?? {}), radarActive, ttlSeconds };
    localStorage.setItem(WORKSPACE_SETTINGS_KEY, JSON.stringify(ws));
  }, [radarActive, ttlSeconds]);

  useEffect(() => {
    localStorage.setItem(TELEMETRY_KEY, String(telemetryEnabled));
    const ws = readJSON<Record<string, any>>(WORKSPACE_SETTINGS_KEY, {});
    ws[activeWorkspaceId] = { ...(ws[activeWorkspaceId] ?? {}), telemetryEnabled };
    localStorage.setItem(WORKSPACE_SETTINGS_KEY, JSON.stringify(ws));
  }, [telemetryEnabled]);

  useEffect(() => {
    localStorage.setItem(ANIMATION_KEY, String(animationsEnabled));
    const ws = readJSON<Record<string, any>>(WORKSPACE_SETTINGS_KEY, {});
    ws[activeWorkspaceId] = { ...(ws[activeWorkspaceId] ?? {}), animationsEnabled };
    localStorage.setItem(WORKSPACE_SETTINGS_KEY, JSON.stringify(ws));
    document.body.classList.toggle('hada-no-motion', !animationsEnabled);
  }, [animationsEnabled]);

  useEffect(() => {
    localStorage.setItem(THEME_KEY, darkMode ? 'dark' : 'light');
    document.body.classList.toggle('hada-dark', darkMode);
    const ws = readJSON<Record<string, any>>(WORKSPACE_SETTINGS_KEY, {});
    ws[activeWorkspaceId] = { ...(ws[activeWorkspaceId] ?? {}), darkMode };
    localStorage.setItem(WORKSPACE_SETTINGS_KEY, JSON.stringify(ws));
  }, [darkMode]);

  useEffect(() => {
    localStorage.setItem(PAN_LOCK_KEY, String(panLocked));
    const ws = readJSON<Record<string, any>>(WORKSPACE_SETTINGS_KEY, {});
    ws[activeWorkspaceId] = { ...(ws[activeWorkspaceId] ?? {}), panLocked };
    localStorage.setItem(WORKSPACE_SETTINGS_KEY, JSON.stringify(ws));
  }, [panLocked]);

  useEffect(() => {
    const previous = readJSON<
      Record<string, { total: number; active: number; compromised: number; down: number }>
    >('hada_metric_snapshot', {});
    const next = {
      ...previous,
      [activeWorkspaceId]: currentMetrics,
    };
    localStorage.setItem('hada_metric_snapshot', JSON.stringify(next));
  }, [activeWorkspaceId, currentMetrics]);

  return {
    selectedAsset,
    setSelectedAsset,
    showModal,
    setShowModal,
    radarActive,
    setRadarActive,
    ttlSeconds,
    setTtlSeconds,
    workspaces,
    activeWorkspaceId,
    assets,
    loading,
    portScans,
    events,
    filteredAssets,
    scanningAssetId,
    handleScan,
    cancelScan,
    handleCreateAsset,
    handleDelete,
    handleStatusChange,
    handleCriticalityChange,
    query,
    setQuery,
    statusFilter,
    setStatusFilter,
    riskFilter,
    setRiskFilter,
    duplicateMacDetected,
    osChartData,
    statusChartData,
    topologyData,
    totalAssets,
    activeAssets,
    compromisedAssets,
    downAssets,
    metricDeltas,
    latestScanForSelected,
    handleCreateWorkspace,
    handleRemoveWorkspace,
    handleSelectWorkspace,
    handleImportAssets,
    toggleRadar,
    telemetryEnabled,
    toggleTelemetry,
    animationsEnabled,
    toggleAnimations,
    darkMode,
    setDarkMode,
    panLocked,
    togglePanLock,
    openAssetModal,
    fetchAssets,
  } as const;
}
