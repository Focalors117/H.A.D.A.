// Regla visual de riesgos para convertir puertos en advertencias comprensibles.
const PORT_RISK_RULES: Record<number, { severity: 'low' | 'medium' | 'high'; message: string }> = {
  21: {
    severity: 'high',
    message: 'FTP sin cifrado: riesgo de intercepción de credenciales.',
  },
  23: {
    severity: 'high',
    message: 'Telnet expuesto: canal inseguro y fácil de interceptar.',
  },
  445: {
    severity: 'high',
    message: 'SMB expuesto: vector típico de movimiento lateral.',
  },
  3389: {
    severity: 'medium',
    message: 'RDP abierto: objetivo frecuente de fuerza bruta.',
  },
  3306: {
    severity: 'medium',
    message: 'Motor SQL expuesto: valida ACL y origen de conexiones.',
  },
  80: {
    severity: 'low',
    message: 'HTTP abierto: tráfico potencialmente sin cifrar.',
  },
};

export type VulnerabilityItem = {
  port: number;
  severity: 'low' | 'medium' | 'high';
  message: string;
};

// Normaliza riesgos recibidos del backend y agrega fallback local por si faltan reglas.
export function resolveVulnerabilities(
  ports: number[],
  incomingRisks?: VulnerabilityItem[]
): VulnerabilityItem[] {
  const fromBackend = incomingRisks ?? [];
  if (fromBackend.length > 0) return fromBackend;

  return ports.flatMap((port) => {
    const rule = PORT_RISK_RULES[port];
    if (rule) return [{ port, ...rule }];
    return [];
  });
}
