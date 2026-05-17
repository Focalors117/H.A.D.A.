import type { FC } from 'react';

const LegendItem: FC<{ color: string; label: string }> = ({ color, label }) => (
  <div className="flex items-center gap-2">
    <span style={{ background: color }} className="w-4 h-4 rounded-full" />
    <span className="text-sm text-slate-300">{label}</span>
  </div>
);

export default function TopologyLegend() {
  return (
    <div className="topology-legend">
      <h5 className="text-sm font-semibold mb-2">Leyenda</h5>
      <div className="grid grid-cols-2 gap-2">
        <LegendItem color="#22c55e" label="Activo (OK)" />
        <LegendItem color="#f43f5e" label="Comprometido" />
        <LegendItem color="#94a3b8" label="Offline" />
        <LegendItem color="#60a5fa" label="Router / Gateway" />
      </div>
    </div>
  );
}
