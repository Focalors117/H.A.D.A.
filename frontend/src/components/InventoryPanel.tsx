import type { Dispatch, SetStateAction } from 'react';
import type { Asset, PortScanResult } from '../types';
import { getAssetProfile, getDisplayProfile, getRiskScore } from '../utils/assetInsights';
import { calculateRiskLevel, riskToCss } from '../utils/risk';
import StatusBadge from './StatusBadge';

export default function InventoryPanel({
  loading,
  filteredAssets,
  activeWorkspaceId,
  portScans,
  query,
  setQuery,
  statusFilter,
  setStatusFilter,
  riskFilter,
  setRiskFilter,
  onOpenAsset,
  onCriticalityChange,
  onScan,
  scanningAssetId,
  onCancelScan,
  onStatusChange,
  onDelete,
}: {
  loading: boolean;
  filteredAssets: Asset[];
  activeWorkspaceId: string;
  portScans: Record<string, PortScanResult[]>;
  query: string;
  setQuery: Dispatch<SetStateAction<string>>;
  statusFilter: 'all' | Asset['status'];
  setStatusFilter: Dispatch<SetStateAction<'all' | Asset['status']>>;
  riskFilter: 'all' | 'high' | 'medium' | 'low' | 'none';
  setRiskFilter: Dispatch<SetStateAction<'all' | 'high' | 'medium' | 'low' | 'none'>>;
  onOpenAsset: (asset: Asset) => void;
  onCriticalityChange: (id: string, newLevel: number) => void;
  onScan: (asset: Asset, mode?: 'normal' | 'stealth') => void;
  scanningAssetId?: string | null;
  onCancelScan?: (assetId: string) => void;
  onStatusChange: (id: string, currentStatus: Asset['status']) => void;
  onDelete: (id: string) => void;
}) {
  // scanningAssetId and onCancelScan are controlled by App.tsx through props

  const buildExportRows = () => {
    return filteredAssets.map((asset) => {
      const latestScan = portScans[`${activeWorkspaceId}:${asset._id}`]?.[0];
      const riskLevel = calculateRiskLevel(latestScan?.openPorts);
      return {
        id: asset._id,
        hostname: asset.hostname,
        ip: asset.ip,
        mac: asset.mac,
        networkId: asset.networkId,
        status: asset.status,
        os: asset.os,
        profile: getAssetProfile(asset),
        criticality: asset.criticality,
        riskScore: getRiskScore(asset, latestScan),
        riskLevel,
        latestOpenPorts: latestScan?.openPorts ?? [],
        latestCvssLikeScore: latestScan?.cvssLikeScore ?? null,
        lastScanAt: latestScan?.timestamp ?? null,
      };
    });
  };

  const downloadFile = (content: string, filename: string, mime: string) => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  };

  const exportAsJson = () => {
    const rows = buildExportRows();
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    downloadFile(
      JSON.stringify(rows, null, 2),
      `hada-assets-${activeWorkspaceId}-${stamp}.json`,
      'application/json;charset=utf-8'
    );
  };

  const exportAsCsv = () => {
    const rows = buildExportRows();
    const headers = [
      'id',
      'hostname',
      'ip',
      'mac',
      'networkId',
      'status',
      'os',
      'profile',
      'criticality',
      'riskScore',
      'riskLevel',
      'latestOpenPorts',
      'latestCvssLikeScore',
      'lastScanAt',
    ];

    const escapeCsv = (value: string | number | null) => {
      const stringValue = value === null ? '' : String(value);
      return `"${stringValue.replace(/"/g, '""')}"`;
    };

    const lines = rows.map((row) =>
      [
        row.id,
        row.hostname,
        row.ip,
        row.mac,
        row.networkId,
        row.status,
        row.os,
        row.profile,
        row.criticality,
        row.riskScore,
        row.riskLevel,
        row.latestOpenPorts.join(';'),
        row.latestCvssLikeScore,
        row.lastScanAt,
      ]
        .map(escapeCsv)
        .join(',')
    );

    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const content = [headers.join(','), ...lines].join('\n');
    downloadFile(
      content,
      `hada-assets-${activeWorkspaceId}-${stamp}.csv`,
      'text/csv;charset=utf-8'
    );
  };

  return (
    <section className="panel panel-table">
      <div className="panel-header">
        <div>
          <h2>Inventario de red</h2>
          <p>Haz clic en un dispositivo para abrir su panel de detalle y ver datos persistidos.</p>
        </div>
        <div className="filter-row">
          <button type="button" className="ghost-button" onClick={exportAsCsv}>
            Exportar CSV
          </button>
          <button type="button" className="ghost-button" onClick={exportAsJson}>
            Exportar JSON
          </button>
          <input
            type="text"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Buscar por hostname, IP o MAC"
            className="field-input filter-input"
          />
          <select
            title="Filtrar por estado"
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value as 'all' | Asset['status'])}
            className="field-input filter-select"
          >
            <option value="all">Todos los estados</option>
            <option value="Active">Operativo</option>
            <option value="Compromised">Comprometido</option>
            <option value="Down">Caído</option>
          </select>
          <select
            title="Filtrar por nivel de riesgo"
            value={riskFilter}
            onChange={(event) =>
              setRiskFilter(event.target.value as 'all' | 'high' | 'medium' | 'low' | 'none')
            }
            className="field-input filter-select"
          >
            <option value="all">Todo riesgo</option>
            <option value="high">Riesgo alto</option>
            <option value="medium">Riesgo medio</option>
            <option value="low">Riesgo bajo</option>
            <option value="none">Sin riesgo</option>
          </select>
        </div>
      </div>

      {loading ? (
        <p className="state-text">Escaneando base de datos...</p>
      ) : filteredAssets.length === 0 ? (
        <p className="state-text">
          No hay activos registrados. Empieza con el formulario de arriba.
        </p>
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
              {filteredAssets.map((asset) => {
                const latestScan = portScans[`${activeWorkspaceId}:${asset._id}`]?.[0];
                const riskScore = getRiskScore(asset, latestScan);
                const riskLevel = calculateRiskLevel(latestScan?.openPorts);
                const rowClass = `${riskToCss(riskLevel)} ${
                  asset.status === 'Compromised' ? 'ring-2 ring-rose-600/30' : ''
                }`;
                return (
                  <tr key={asset._id} className={rowClass} onClick={() => onOpenAsset(asset)}>
                    <td>
                      <div className="asset-name">{asset.hostname}</div>
                      <div className="asset-subtext">ID {asset._id.slice(-6)}</div>
                    </td>
                    <td>
                      <div className="mono-strong">{asset.ip}</div>
                      <div className="asset-subtext">{asset.mac || 'Sin MAC'}</div>
                    </td>
                    <td>
                      <div className="asset-profile">{getDisplayProfile(asset)}</div>
                      <div className="asset-subtext">
                        {asset.os !== 'Detectando...'
                          ? getAssetProfile(asset)
                          : 'Sincronizando sensores...'}
                      </div>
                    </td>
                    <td>
                      <div className="criticality-wrap">
                        <span
                          className={`criticality-dot level-${
                            asset.criticality >= 8 ? 'high' : asset.criticality >= 5 ? 'mid' : 'low'
                          }`}
                        />
                        <select
                          title="Cambiar nivel de criticidad"
                          value={asset.criticality || 5}
                          onChange={(event) =>
                            onCriticalityChange(asset._id, parseInt(event.target.value))
                          }
                          onClick={(event) => event.stopPropagation()}
                          className="bg-transparent text-slate-100 font-bold border-none focus:ring-0 cursor-pointer text-sm outline-none"
                        >
                          {[...Array(10)].map((_, index) => (
                            <option
                              key={index + 1}
                              value={index + 1}
                              className="bg-slate-900 text-white"
                            >
                              Nivel {index + 1}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div className="asset-subtext">Riesgo sugerido {riskScore}/10</div>
                    </td>
                    <td>
                      <StatusBadge status={asset.status} />
                    </td>
                    <td>
                      <div className="action-row" onClick={(event) => event.stopPropagation()}>
                        {/** Scan / cancel buttons now controlled from App */}
                        {(() => {
                          const isScanning = scanningAssetId === asset._id;
                          return (
                            <>
                              <button
                                type="button"
                                className="action-button scan"
                                onClick={() => void onScan(asset, 'normal')}
                                disabled={isScanning}
                              >
                                {isScanning ? 'Escaneando…' : 'Escanear'}
                              </button>
                              <button
                                type="button"
                                className="action-button stealth"
                                onClick={() => void onScan(asset, 'stealth')}
                                disabled={isScanning}
                              >
                                {isScanning ? 'Sigilo…' : 'Escanear (Sigilo)'}
                              </button>
                              {isScanning && onCancelScan && (
                                <button
                                  type="button"
                                  className="action-button danger"
                                  onClick={() => onCancelScan(asset._id)}
                                >
                                  Cancelar
                                </button>
                              )}
                            </>
                          );
                        })()}
                        <button
                          type="button"
                          className="action-button status"
                          onClick={() => void onStatusChange(asset._id, asset.status)}
                        >
                          Mod
                        </button>
                        <button
                          type="button"
                          className="action-button danger"
                          onClick={() => void onDelete(asset._id)}
                        >
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
  );
}
