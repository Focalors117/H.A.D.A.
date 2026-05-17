import { useCallback, useEffect, useMemo, useState } from 'react';
import { toast } from 'react-hot-toast';
import { resolveVulnerabilities, type VulnerabilityItem } from '../utils/vulnerabilities';
import type { Asset, PortScanResult, SecurityEvent } from '../types';

type CreateAssetPayload = {
  hostname: string;
  ip: string;
  mac: string;
  os: string;
  criticality: number;
  status: Asset['status'];
};

const API_BASE = 'http://localhost:3001/api';
const SCAN_STORAGE_KEY = 'hada_port_scans';
const KNOWN_MACS_KEY = 'hada_known_macs';

function readJSON<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function storageScanKey(networkId: string, assetId: string) {
  return `${networkId}:${assetId}`;
}

export default function useWorkspace(
  activeWorkspaceId: string,
  radarActive: boolean,
  ttlSeconds: number
) {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [portScans, setPortScans] = useState<Record<string, PortScanResult[]>>(() =>
    readJSON(SCAN_STORAGE_KEY, {})
  );
  const [scanControllers, setScanControllers] = useState<Record<string, AbortController>>(
    () => ({})
  );
  const [events, setEvents] = useState<SecurityEvent[]>([]);

  const scanningAssetId = useMemo(() => Object.keys(scanControllers)[0] ?? null, [scanControllers]);

  const fetchAssets = useCallback(async () => {
    try {
      const response = await fetch(
        `${API_BASE}/assets?networkId=${encodeURIComponent(activeWorkspaceId)}`
      );
      if (!response.ok) throw new Error('No fue posible leer el inventario');
      const data = (await response.json()) as Asset[];
      setAssets(data);
      setLoading(false);
    } catch (error) {
      console.error('Error al conectar con el backend:', error);
      toast.error('No se pudo cargar el inventario');
      setLoading(false);
    }
  }, [activeWorkspaceId]);

  const fetchEvents = useCallback(async () => {
    try {
      const response = await fetch(
        `${API_BASE}/events?networkId=${encodeURIComponent(activeWorkspaceId)}`
      );
      if (!response.ok) return;
      const data = (await response.json()) as SecurityEvent[];
      setEvents(data);
    } catch {
      // ignore transient errors
    }
  }, [activeWorkspaceId]);

  const persistScanResult = useCallback(
    (assetId: string, result: PortScanResult) => {
      setPortScans((previous) => {
        const key = storageScanKey(activeWorkspaceId, assetId);
        const next = {
          ...previous,
          [key]: [result, ...(previous[key] ?? [])].slice(0, 20),
        };
        localStorage.setItem(SCAN_STORAGE_KEY, JSON.stringify(next));
        return next;
      });
    },
    [activeWorkspaceId]
  );

  const detectUnknownDevices = useCallback((networkId: string, currentAssets: Asset[]) => {
    const knownMacMap = readJSON<Record<string, string[]>>(KNOWN_MACS_KEY, {});
    const knownSet = new Set(knownMacMap[networkId] ?? []);
    const discoveredNow: string[] = [];

    for (const asset of currentAssets) {
      if (!asset.mac || asset.mac === '00:00:00:00:00:00') continue;
      if (!knownSet.has(asset.mac)) discoveredNow.push(asset.mac);
      knownSet.add(asset.mac);
    }

    if (discoveredNow.length > 0) {
      toast.error(`NUEVO DISPOSITIVO DESCONOCIDO DETECTADO (${discoveredNow.length})`, {
        icon: '🚨',
      });
    }

    knownMacMap[networkId] = Array.from(knownSet);
    localStorage.setItem(KNOWN_MACS_KEY, JSON.stringify(knownMacMap));
  }, []);

  const handleCreateAsset = useCallback(
    async (formData: CreateAssetPayload) => {
      try {
        const response = await fetch(`${API_BASE}/assets`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...formData, networkId: activeWorkspaceId }),
        });

        if (!response.ok) throw new Error('No fue posible crear el activo');

        toast.success('Activo registrado en el inventario');
        await fetchAssets();
      } catch (error) {
        console.error('Error al guardar:', error);
        toast.error('No se pudo registrar el activo');
      }
    },
    [activeWorkspaceId, fetchAssets]
  );

  const handleDelete = useCallback(
    async (id: string) => {
      // Optimistic delete: remove from UI immediately
      setAssets((prev) => prev.filter((a) => a._id !== id));
      try {
        const response = await fetch(`${API_BASE}/assets/${id}`, {
          method: 'DELETE',
        });
        if (!response.ok) throw new Error('No fue posible eliminar el activo');
        toast.success('Activo eliminado de la red');
        // refresh in background
        void fetchAssets();
      } catch (error) {
        console.error('Error al eliminar:', error);
        toast.error('Fallo al intentar eliminar el activo — revirtiendo cambios');
        // revert: refetch assets from server
        void fetchAssets();
      }
    },
    [fetchAssets]
  );

  const handleImportAssets = useCallback(
    async (items: CreateAssetPayload[] | any[]) => {
      try {
        const response = await fetch(
          `${API_BASE}/assets/import?networkId=${encodeURIComponent(activeWorkspaceId)}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(items),
          }
        );
        if (!response.ok) throw new Error('No fue posible importar activos');
        const data = await response.json();
        toast.success(`Importados ${data.created ?? items.length} activos`);
        await fetchAssets();
      } catch (error) {
        console.error('Error al importar activos:', error);
        toast.error('Error al importar activos');
      }
    },
    [activeWorkspaceId, fetchAssets]
  );

  const handleStatusChange = useCallback(
    async (id: string, currentStatus: Asset['status']) => {
      const nextStatus: Asset['status'] =
        currentStatus === 'Active' ? 'Down' : currentStatus === 'Down' ? 'Compromised' : 'Active';

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
    },
    [fetchAssets]
  );

  const handleCriticalityChange = useCallback(async (id: string, newLevel: number) => {
    try {
      const response = await fetch(`${API_BASE}/assets/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ criticality: newLevel }),
      });

      if (response.ok) {
        setAssets((prev) =>
          prev.map((asset) => (asset._id === id ? { ...asset, criticality: newLevel } : asset))
        );
        toast.success(`Prioridad ajustada a Nivel ${newLevel}`, {
          icon: '📊',
        });
      }
    } catch {
      toast.error('Error al persistir la criticidad');
    }
  }, []);

  const handleScan = useCallback(
    async (asset: Asset, mode: 'normal' | 'stealth' = 'normal') => {
      const loadingId = `scan-${asset._id}`;
      toast.loading(
        `Escaneando ${asset.hostname} (${mode === 'stealth' ? 'sigilo' : 'rápido'})...`,
        { id: loadingId }
      );

      const controller = new AbortController();
      setScanControllers((prev) => ({ ...prev, [asset._id]: controller }));

      try {
        const response = await fetch(`${API_BASE}/scan`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: asset.ip, mode }),
          signal: controller.signal,
        });

        if (!response.ok) throw new Error('El escaneo falló');
        const data = (await response.json()) as {
          openPorts?: number[];
          services?: Array<{
            port: number;
            banner: string;
            fingerprint: string;
          }>;
          risks?: VulnerabilityItem[];
          cvssLikeScore?: number;
          mode?: 'normal' | 'stealth';
          recommendations?: Array<{
            port: number;
            cve: string;
            title: string;
            recommendation: string;
          }>;
        };
        const openPorts = Array.isArray(data.openPorts) ? data.openPorts : [];
        const risks = Array.isArray(data.risks) ? data.risks : [];

        const result: PortScanResult = {
          openPorts,
          services: Array.isArray(data.services) ? data.services : [],
          risks,
          cvssLikeScore: typeof data.cvssLikeScore === 'number' ? data.cvssLikeScore : undefined,
          recommendations: Array.isArray(data.recommendations) ? data.recommendations : [],
          mode: data.mode === 'stealth' ? 'stealth' : 'normal',
          timestamp: new Date().toISOString(),
          vulnerable: openPorts.length > 0,
        };

        persistScanResult(asset._id, result);

        if (openPorts.length > 0) {
          toast.success(`Puertos encontrados: ${openPorts.length}`, {
            id: loadingId,
          });
          if (resolveVulnerabilities(openPorts, risks).some((risk) => risk.severity === 'high')) {
            toast.error('Se detectaron riesgos críticos en el activo', {
              icon: '🚨',
            });
          }
        } else {
          toast.success('Sin puertos abiertos detectados', { id: loadingId });
        }
      } catch (error: unknown) {
        const maybeError = error as Error & { name?: string };
        if (maybeError.name === 'AbortError') {
          toast('Escaneo cancelado', { icon: '⚠️' });
        } else {
          console.error('Error en escaneo:', error);
          toast.error('Error al ejecutar el escaneo', { id: loadingId });
        }
      } finally {
        setScanControllers((prev) => {
          const next = { ...prev };
          delete next[asset._id];
          return next;
        });
      }
    },
    [persistScanResult]
  );

  const cancelScan = useCallback(
    (assetId: string) => {
      const controller = scanControllers[assetId];
      if (controller) controller.abort();
      setScanControllers((prev) => {
        const next = { ...prev };
        delete next[assetId];
        return next;
      });
    },
    [scanControllers]
  );

  useEffect(() => {
    if (!radarActive) return undefined;

    const timer = window.setInterval(() => {
      void fetchAssets();
      void fetchEvents();
    }, Math.max(1000, ttlSeconds * 1000));

    return () => window.clearInterval(timer);
  }, [fetchAssets, fetchEvents, radarActive, ttlSeconds]);

  useEffect(() => {
    // re-fetch when workspace changes
    let mounted = true;
    const loadData = async () => {
      setLoading(true);
      await Promise.all([fetchAssets(), fetchEvents()]);
      if (mounted) setLoading(false);
    };
    void loadData();
    return () => {
      mounted = false;
    };
  }, [activeWorkspaceId, fetchAssets, fetchEvents]);

  useEffect(() => {
    if (assets.length > 0) detectUnknownDevices(activeWorkspaceId, assets);
  }, [activeWorkspaceId, assets, detectUnknownDevices]);

  return {
    assets,
    loading,
    portScans,
    events,
    handleImportAssets,
    fetchAssets,
    fetchEvents,
    persistScanResult,
    scanningAssetId,
    handleScan,
    cancelScan,
    handleCreateAsset,
    handleDelete,
    handleStatusChange,
    handleCriticalityChange,
  } as const;
}
