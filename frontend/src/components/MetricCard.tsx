export default function MetricCard({
  label,
  value,
  tone,
  pulse = false,
  delta,
}: {
  label: string;
  value: number;
  tone: 'blue' | 'green' | 'rose' | 'amber';
  pulse?: boolean;
  delta?: number;
}) {
  const deltaLabel =
    delta === undefined || delta === 0 ? 'Sin cambios' : `${delta > 0 ? '+' : ''}${delta}`;
  const deltaTone =
    delta === undefined || delta === 0 ? 'is-neutral' : delta > 0 ? 'is-up' : 'is-down';

  return (
    <article className={`metric-card tone-${tone} ${pulse ? 'is-pulse' : ''}`}>
      <span className="metric-label">{label}</span>
      <span className="metric-value">{value}</span>
      <span className={`metric-delta ${deltaTone}`}>{deltaLabel}</span>
    </article>
  );
}
