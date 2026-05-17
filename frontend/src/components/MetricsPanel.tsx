import MetricCard from './MetricCard';
import type { FC } from 'react';

const MetricsPanel: FC<{
  total: number;
  active: number;
  compromised: number;
  down: number;
  deltas?: {
    total: number;
    active: number;
    compromised: number;
    down: number;
  };
}> = ({ total, active, compromised, down, deltas }) => {
  return (
    <section className="stats-grid">
      <MetricCard label="Total en Red" value={total} tone="blue" delta={deltas?.total} />
      <MetricCard label="Operativos" value={active} tone="green" delta={deltas?.active} />
      <MetricCard
        label="Bajo Ataque"
        value={compromised}
        tone="rose"
        pulse={compromised > 0}
        delta={deltas?.compromised}
      />
      <MetricCard label="Offline / Down" value={down} tone="amber" delta={deltas?.down} />
    </section>
  );
};

export default MetricsPanel;
