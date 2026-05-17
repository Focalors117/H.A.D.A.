export type RiskLevel = 'CRÍTICO' | 'MEDIO' | 'BAJO';

// compute a simple risk level from an array of open ports
export function calculateRiskLevel(openPorts: number[] | undefined): RiskLevel {
  if (!Array.isArray(openPorts) || openPorts.length === 0) return 'BAJO';
  if (openPorts.includes(445)) return 'CRÍTICO';
  if (openPorts.includes(80) || openPorts.includes(21)) return 'MEDIO';
  return 'BAJO';
}

export function riskToCss(level: RiskLevel) {
  switch (level) {
    case 'CRÍTICO':
      return 'bg-rose-900/10 animate-pulse';
    case 'MEDIO':
      return 'bg-amber-800/8';
    default:
      return '';
  }
}
