import type { NetworkWorkspace, SecurityEvent } from '../types';
import { formatDate } from '../utils/assetInsights';

export default function DashboardHeader({
  workspaces,
  activeWorkspaceId,
  radarActive,
  ttlSeconds,
  events,
  compromisedAssets,
  duplicateMacDetected,
  onSelectWorkspace,
  onCreateWorkspace,
  onToggleRadar,
  telemetryEnabled,
  onToggleTelemetry,
  animationsEnabled,
  onToggleAnimations,
  panLocked,
  onTogglePanLock,
  onTtlChange,
  onRefresh,
  onRemoveWorkspace,
  onOpenImport,
  onOpenFeedback,
}: {
  workspaces: NetworkWorkspace[];
  activeWorkspaceId: string;
  radarActive: boolean;
  ttlSeconds: number;
  events: SecurityEvent[];
  compromisedAssets: number;
  duplicateMacDetected: boolean;
  onSelectWorkspace: (workspaceId: string) => void;
  onCreateWorkspace: () => void;
  onToggleRadar: () => void;
  telemetryEnabled?: boolean;
  onToggleTelemetry?: () => void;
  animationsEnabled?: boolean;
  onToggleAnimations?: () => void;
  panLocked?: boolean;
  onTogglePanLock?: () => void;
  onTtlChange: (value: number) => void;
  onRefresh: () => void;
  onRemoveWorkspace?: (workspaceId: string) => void;
  onOpenImport?: () => void;
  onOpenFeedback?: () => void;
}) {
  return (
    <>
      <header className="hada-header">
        <div className="hada-brand">
          <div className="space-y-1">
            <p className="hada-kicker">Interfaz de operaciones</p>
            <h1 className="hada-title" data-text="H.A.D.A">
              H.A.D.A
            </h1>
            <p className="hada-subtitle">Hub de Análisis y Defensa Avanzada</p>
          </div>
          <p className="hada-brand-note">
            Radar, telemetría y controles secundarios se agrupan en un solo panel para que la
            cabecera respire mejor.
          </p>
        </div>

        <div className="hada-controls">
          <div className="control-chip workspace-chip">
            <span className="control-label">Red</span>
            <div className="workspace-tabs">
              {workspaces.map((workspace) => (
                <div key={workspace.id} className="workspace-tab-wrap">
                  <button
                    type="button"
                    className={`workspace-tab ${
                      activeWorkspaceId === workspace.id ? 'is-active' : ''
                    }`}
                    onClick={() => onSelectWorkspace(workspace.id)}
                  >
                    {workspace.label}
                  </button>
                  {onRemoveWorkspace && (
                    <button
                      type="button"
                      className="workspace-remove"
                      onClick={() => onRemoveWorkspace(workspace.id)}
                      aria-label={`Eliminar ${workspace.label}`}
                    >
                      ×
                    </button>
                  )}
                </div>
              ))}
              <button type="button" className="workspace-tab add" onClick={onCreateWorkspace}>
                + Red
              </button>
            </div>
          </div>

          <details className="operations-drawer">
            <summary className="operations-summary">
              <span>Controles rápidos</span>
              <span className="operations-summary-badge">Abrir</span>
            </summary>
            <div className="operations-panel">
              <div className="operations-grid">
                <div className="control-chip">
                  <span className="control-label">Radar</span>
                  <button
                    type="button"
                    className={`control-button ${radarActive ? 'is-on' : 'is-off'}`}
                    onClick={onToggleRadar}
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
                    onChange={(event) => onTtlChange(Number(event.target.value) || 10)}
                    className="control-input"
                  />
                </label>

                <div className="control-chip">
                  <span className="control-label">Telemetría</span>
                  <button
                    type="button"
                    className={`control-button ${telemetryEnabled ? 'is-on' : 'is-off'}`}
                    onClick={() => onToggleTelemetry?.()}
                  >
                    {telemetryEnabled ? 'ACTIVADA' : 'DESACTIVADA'}
                  </button>
                </div>

                <div className="control-chip">
                  <span className="control-label">Animaciones</span>
                  <button
                    type="button"
                    className={`control-button ${animationsEnabled ? 'is-on' : 'is-off'}`}
                    onClick={() => onToggleAnimations?.()}
                  >
                    {animationsEnabled ? 'ACTIVAS' : 'INACTIVAS'}
                  </button>
                </div>

                <div className="control-chip">
                  <span className="control-label">Paneo</span>
                  <button
                    type="button"
                    className={`control-button ${panLocked ? 'is-off' : 'is-on'}`}
                    onClick={() => onTogglePanLock?.()}
                  >
                    {panLocked ? 'BLOQUEADO' : 'LIBRE'}
                  </button>
                </div>
              </div>

              <div className="operations-actions">
                <button type="button" className="ghost-button" onClick={onRefresh}>
                  Refrescar
                </button>
                <button type="button" className="ghost-button" onClick={() => onOpenImport?.()}>
                  Importar
                </button>
                <button type="button" className="ghost-button" onClick={() => onOpenFeedback?.()}>
                  Feedback
                </button>
              </div>
            </div>
          </details>
        </div>
      </header>

      {!radarActive && (
        <section className="passive-strip">
          <span className="alert-title">Modo pasivo</span>
          <span>
            El radar está pausado: no se están actualizando datos en tiempo real para evitar
            lecturas viejas engañosas.
          </span>
        </section>
      )}

      {events.length > 0 && (
        <section className="events-strip">
          <strong>Última alerta:</strong>
          <span>{events[0].message}</span>
          <small>{formatDate(events[0].timestamp)}</small>
        </section>
      )}

      {compromisedAssets > 0 && (
        <section className="alert-strip">
          <span className="alert-title">Alerta activa</span>
          <span>{compromisedAssets} activo(s) comprometido(s) requieren atención.</span>
        </section>
      )}

      {duplicateMacDetected && (
        <section className="alert-strip">
          <span className="alert-title">MAC duplicada</span>
          <span>
            Se detectó al menos una MAC con más de una IP en esta red. Revisa posible spoofing o
            MITM.
          </span>
        </section>
      )}
    </>
  );
}
