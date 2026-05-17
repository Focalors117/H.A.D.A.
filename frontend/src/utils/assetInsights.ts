import type { Asset, PortScanResult } from '../types';

export function getAssetProfile(asset: Asset) {
  const osLower = asset.os.toLowerCase();

  if (asset.vendor && asset.vendor !== 'Generic Vendor' && asset.vendor !== 'Desconocido') {
    return asset.vendor;
  }

  const isWindows = osLower.includes('windows');
  const isUnix =
    osLower.includes('linux') || osLower.includes('android') || osLower.includes('ios');
  const isRouter =
    /router|gateway|switch/i.test(asset.hostname.toLowerCase()) || osLower.includes('network');

  if (isWindows) return 'Endpoint Windows';
  if (isUnix) return 'Linux / Móvil';
  if (isRouter) return 'Infraestructura de Red';

  return 'Perfil genérico';
}

export function getCriticalityHint(asset: Asset, latestScan?: PortScanResult) {
  const ports = latestScan?.openPorts.length ?? 0;
  if (asset.criticality >= 8) return 'Alta por diseño: activo sensible o expuesto.';
  if (ports >= 4) return 'Alta exposición: varios puertos críticos abiertos.';
  if (ports >= 1) return 'Exposición moderada: revisar superficie de ataque.';
  return 'Baja exposición visible en el último escaneo.';
}

export function getRiskScore(asset: Asset, latestScan?: PortScanResult) {
  const openPorts = latestScan?.openPorts.length ?? 0;
  const base = asset.criticality;
  const scanBonus = Math.min(3, openPorts);
  const statusBonus = asset.status === 'Compromised' ? 3 : asset.status === 'Down' ? 1 : 0;
  return Math.min(10, base + scanBonus + statusBonus);
}

export function formatDate(value?: string) {
  if (!value) return 'Sin datos';
  return new Date(value).toLocaleString();
}

export function getDisplayProfile(asset: Asset) {
  if (asset.os && asset.os !== 'Detectando...' && asset.os !== 'Unknown') {
    return asset.os;
  }

  if (asset.vendor && asset.vendor !== 'Desconocido') {
    return asset.vendor;
  }

  return 'Analizando dispositivo...';
}
