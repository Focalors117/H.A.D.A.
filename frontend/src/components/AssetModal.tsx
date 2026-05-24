import type { Asset, PortScanResult, SecurityEvent } from '../types';
import toast from 'react-hot-toast';
import VulnerabilityBadge from './VulnerabilityBadge';
import StatusBadge from './StatusBadge';
import { formatDate, getDisplayProfile, getRiskScore } from '../utils/assetInsights';

export default function AssetModal({
  asset,
  scans,
  latestScan,
  onClose,
  onScan,
  scanningAssetId,
  onCancelScan,
  events = [],
}: {
  asset: Asset;
  scans: PortScanResult[];
  latestScan?: PortScanResult;
  onClose: () => void;
  onScan: (mode: 'normal' | 'stealth') => void;
  scanningAssetId?: string | null;
  onCancelScan?: (assetId: string) => void;
  events?: SecurityEvent[];
}) {
  const relatedEvents = events.filter((e) => e.ip === asset.ip || e.mac === asset.mac);
  const riskScore = getRiskScore(asset, latestScan);

  return (
    <div className="modal-backdrop">
      <div className="modal-card">
        <div className="modal-header">
          <div>
            <p className="modal-kicker">Detalles del dispositivo</p>
            <h3 className="modal-title">{asset.hostname}</h3>
            <p className="modal-subtitle">
              {asset.ip} • {asset.mac}
            </p>
          </div>

          <div className="modal-actions">
            <button
              type="button"
              className="primary-button small"
              onClick={() => onScan('normal')}
              disabled={scanningAssetId === asset._id}
            >
              {scanningAssetId === asset._id ? 'Escaneando…' : 'Escanear'}
            </button>
            <button
              type="button"
              className="secondary-button small"
              onClick={() => onScan('stealth')}
              disabled={scanningAssetId === asset._id}
            >
              {scanningAssetId === asset._id ? 'Sigilo…' : 'Escanear (sigilo)'}
            </button>
            <button
              type="button"
              className="secondary-button small"
              onClick={async () => {
                const key = `isolate-${asset._id}`;
                toast.promise(
                  (async () => {
                    const res = await fetch(`/api/assets/${encodeURIComponent(asset._id)}/isolate`, {
                      method: 'POST',
                    });
                    if (!res.ok) throw new Error('failed');
                    return res.json();
                  })(),
                  {
                    loading: 'Enviando comando de aislamiento...',
                    success: 'Comando de aislamiento enviado',
                    error: 'No se pudo enviar el comando de aislamiento',
                  },
                  { id: key }
                );
              }}
            >
              Aislar
            </button>
            <button
              type="button"
              className="secondary-button small"
              onClick={async () => {
                toast.promise(
                  fetch('/api/firewall/block', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: asset.ip }),
                  }).then((r) => {
                    if (!r.ok) throw new Error('failed');
                    return r.json();
                  }),
                  {
                    loading: 'Solicitando bloqueo de IP...',
                    success: 'IP enviada para bloqueo',
                    error: 'No se pudo bloquear la IP',
                  }
                );
              }}
            >
              Bloquear IP
            </button>
            {scanningAssetId === asset._id && onCancelScan ? (
              <button
                type="button"
                className="secondary-button small"
                onClick={() => onCancelScan(asset._id)}
              >
                Cancelar
              </button>
            ) : null}
            <button type="button" className="secondary-button small" onClick={onClose}>
              Cerrar
            </button>
          </div>
        </div>

        <div className="modal-grid">
          <section className="detail-card">
            <span className="detail-label">Resumen</span>
            <strong>
              {getDisplayProfile(asset)} — {asset.criticality}/10
            </strong>
            <p className="short">
              {asset.ip} • {asset.mac} • {asset.status}
            </p>
            <p className="short">
              Riesgo: {riskScore}/10 · Último scan:{' '}
              {latestScan ? formatDate(latestScan.timestamp) : '—'}
            </p>
            <p className="short">
              CVSS-like:{' '}
              {typeof latestScan?.cvssLikeScore === 'number'
                ? `${latestScan.cvssLikeScore}/10`
                : 'N/D'}
            </p>
          </section>
        </div>

        <div className="modal-columns">
          <section className="modal-panel">
            <h4>Puertos y hallazgos</h4>
            {scans.length === 0 ? (
              <p className="state-text">No hay resultados guardados para este dispositivo.</p>
            ) : (
              <div className="scan-list">
                {scans.map((scan, index) => (
                  <article key={`${scan.timestamp}-${index}`} className="scan-item">
                    <div className="scan-item-top">
                      <span>{formatDate(scan.timestamp)}</span>
                      <span className={`scan-pill ${scan.vulnerable ? 'is-danger' : 'is-safe'}`}>
                        {scan.vulnerable ? 'Vulnerable' : 'Sin hallazgos'}
                      </span>
                    </div>
                    {typeof scan.cvssLikeScore === 'number' && (
                      <p className="short">CVSS-like: {scan.cvssLikeScore}/10</p>
                    )}
                    <div className="scan-ports">
                      {scan.openPorts.length > 0
                        ? scan.openPorts.join(', ')
                        : 'No se detectaron puertos abiertos'}
                    </div>
                    {scan.services.length > 0 && (
                      <div className="scan-signatures">
                        {scan.services.slice(0, 3).map((service) => (
                          <p key={`${scan.timestamp}-${service.port}`}>
                            <strong>{service.port}</strong>: {service.fingerprint}
                          </p>
                        ))}
                      </div>
                    )}
                  </article>
                ))}
              </div>
            )}
          </section>

          <section className="modal-panel">
            <h4>Riesgos detectados</h4>
            <VulnerabilityBadge ports={latestScan?.openPorts ?? []} risks={latestScan?.risks} />

            {latestScan?.risks && latestScan.risks.length > 0 && (
              <div className="mt-4 space-y-3">
                <h4 className="summary-title">Detalles por puerto</h4>
                <div className="space-y-2">
                  {latestScan.risks.map((risk) => (
                    <article
                      key={`${risk.port}-${risk.message}`}
                      className="rounded-2xl border border-slate-700/70 bg-slate-950/60 p-3"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <strong>Puerto {risk.port}</strong>
                        <span
                          className={`scan-pill ${
                            risk.severity === 'high'
                              ? 'is-danger'
                              : risk.severity === 'medium'
                              ? 'is-warning'
                              : 'is-safe'
                          }`}
                        >
                          {risk.severity.toUpperCase()}
                        </span>
                      </div>
                      <p className="short mt-2">{risk.message}</p>
                      {latestScan.recommendations?.find((item) => item.port === risk.port) && (
                        <p className="short mt-2 text-slate-300">
                          Recomendación:{' '}
                          {
                            latestScan.recommendations.find((item) => item.port === risk.port)
                              ?.recommendation
                          }
                        </p>
                      )}
                    </article>
                  ))}
                </div>
              </div>
            )}

            {latestScan?.recommendations && latestScan.recommendations.length > 0 && (
              <>
                <h4 className="summary-title">Recomendaciones rápidas</h4>
                <ul>
                  {latestScan.recommendations.map((rec) => (
                    <li key={`${rec.port}-${rec.cve}`}>
                      <strong>{rec.cve}</strong> ({rec.port}) — {rec.title}: {rec.recommendation}
                    </li>
                  ))}
                </ul>
              </>
            )}

            <h4 className="summary-title">Resumen</h4>
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
              <p>
                El sistema usa mDNS para obtener nombres de dispositivo cuando está disponible y
                registra títulos y cabeceras HTTP para puertos 80/443.
              </p>
            </div>
          </section>
        </div>

        <div className="modal-columns">
          <section className="modal-panel">
            <h4>Actividad reciente</h4>
            {relatedEvents.length === 0 ? (
              <p className="state-text">No hay actividad registrada para este activo.</p>
            ) : (
              <ul className="space-y-2">
                {relatedEvents.map((ev) => (
                  <li key={ev.id} className="rounded p-2 bg-slate-800/60">
                    <div className="flex items-center justify-between">
                      <span className="text-sm">{new Date(ev.timestamp).toLocaleString()}</span>
                      <span className="text-xs text-slate-400">{ev.type}</span>
                    </div>
                    <p className="mt-1 text-sm">{ev.message}</p>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}
