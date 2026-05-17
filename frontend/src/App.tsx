import { Toaster } from 'react-hot-toast';
import useDashboardState from './hooks/useDashboardState';
import DashboardHeader from './components/DashboardHeader';
import MetricsPanel from './components/MetricsPanel';
import ChartPanel from './components/ChartPanel';
import TopologyPanel from './components/TopologyPanel';
import AssetModal from './components/AssetModal';
import AssetForm from './components/AssetForm';
import InventoryPanel from './components/InventoryPanel';
import './App.css';
import { useEffect } from 'react';
import { useState } from 'react';
import ImportModal from './components/ImportModal';
import FeedbackModal from './components/FeedbackModal';

function App() {
  const {
    selectedAsset,
    showModal,
    setShowModal,
    radarActive,
    ttlSeconds,
    setTtlSeconds,
    workspaces,
    activeWorkspaceId,
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
    latestScanForSelected,
    query,
    setQuery,
    statusFilter,
    setStatusFilter,
    riskFilter,
    setRiskFilter,
    duplicateMacDetected,
    filteredAssets,
    totalAssets,
    activeAssets,
    compromisedAssets,
    downAssets,
    metricDeltas,
    osChartData,
    statusChartData,
    topologyData,
    handleCreateWorkspace,
    handleRemoveWorkspace,
    handleSelectWorkspace,
    toggleRadar,
    telemetryEnabled,
    toggleTelemetry,
    animationsEnabled,
    toggleAnimations,
    panLocked,
    togglePanLock,
    openAssetModal,
    fetchAssets,
    handleImportAssets,
  } = useDashboardState();

  const [importOpen, setImportOpen] = useState(false);
  const [feedbackOpen, setFeedbackOpen] = useState(false);

  useEffect(() => {
    const handler = (ev: KeyboardEvent) => {
      const active = document.activeElement;
      if (
        active &&
        (active.tagName === 'INPUT' ||
          active.tagName === 'TEXTAREA' ||
          (active as HTMLElement).isContentEditable)
      )
        return;
      if (ev.key === 'r' || ev.key === 'R') {
        ev.preventDefault();
        void toggleRadar();
      }
      if ((ev.key === 's' || ev.key === 'S') && selectedAsset) {
        ev.preventDefault();
        const mode = ev.shiftKey ? 'stealth' : 'normal';
        void handleScan(selectedAsset, mode as 'normal' | 'stealth');
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [selectedAsset, toggleRadar, handleScan]);

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
        <DashboardHeader
          workspaces={workspaces}
          activeWorkspaceId={activeWorkspaceId}
          radarActive={radarActive}
          ttlSeconds={ttlSeconds}
          events={events}
          compromisedAssets={compromisedAssets}
          duplicateMacDetected={duplicateMacDetected}
          onSelectWorkspace={handleSelectWorkspace}
          onCreateWorkspace={handleCreateWorkspace}
          onRemoveWorkspace={handleRemoveWorkspace}
          onToggleRadar={toggleRadar}
          telemetryEnabled={telemetryEnabled}
          onToggleTelemetry={toggleTelemetry}
          animationsEnabled={animationsEnabled}
          onToggleAnimations={toggleAnimations}
          panLocked={panLocked}
          onTogglePanLock={togglePanLock}
          onTtlChange={(value) => setTtlSeconds(value)}
          onRefresh={() => void fetchAssets()}
          onOpenImport={() => setImportOpen(true)}
          onOpenFeedback={() => setFeedbackOpen(true)}
        />

        <MetricsPanel
          total={totalAssets}
          active={activeAssets}
          compromised={compromisedAssets}
          down={downAssets}
          deltas={metricDeltas}
        />

        <section className="info-grid">
          <AssetForm onSubmit={handleCreateAsset} />
          <div>
            <ChartPanel osChartData={osChartData} statusChartData={statusChartData} />
            <TopologyPanel
              nodes={topologyData.nodes}
              links={topologyData.links}
              panEnabled={!panLocked}
            />
          </div>
        </section>

        <InventoryPanel
          loading={loading}
          filteredAssets={filteredAssets}
          activeWorkspaceId={activeWorkspaceId}
          portScans={portScans}
          query={query}
          setQuery={setQuery}
          statusFilter={statusFilter}
          setStatusFilter={setStatusFilter}
          riskFilter={riskFilter}
          setRiskFilter={setRiskFilter}
          onOpenAsset={openAssetModal}
          onCriticalityChange={handleCriticalityChange}
          onScan={handleScan}
          scanningAssetId={scanningAssetId}
          onCancelScan={cancelScan}
          onStatusChange={handleStatusChange}
          onDelete={handleDelete}
        />
      </main>

      {showModal && selectedAsset && (
        <AssetModal
          asset={selectedAsset}
          scans={portScans[`${activeWorkspaceId}:${selectedAsset._id}`] ?? []}
          latestScan={latestScanForSelected}
          onClose={() => setShowModal(false)}
          onScan={(mode) => void handleScan(selectedAsset, mode)}
          scanningAssetId={scanningAssetId}
          onCancelScan={cancelScan}
            events={events}
        />
      )}

      {importOpen && (
        <ImportModal
          onClose={() => setImportOpen(false)}
          onImport={async (items) => {
            await handleImportAssets(items);
          }}
        />
      )}

      {feedbackOpen && <FeedbackModal onClose={() => setFeedbackOpen(false)} />}
    </div>
  );
}

export default App;
