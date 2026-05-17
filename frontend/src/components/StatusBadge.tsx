import type { Asset } from '../types';

const STATUS_LABELS: Record<Asset['status'], string> = {
  Active: 'Operativo',
  Down: 'Caído',
  Compromised: 'Comprometido',
};

export default function StatusBadge({ status }: { status: Asset['status'] }) {
  return (
    <span className={`status-badge status-${status.toLowerCase()}`}>{STATUS_LABELS[status]}</span>
  );
}
