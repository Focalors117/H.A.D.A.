export interface Asset {
  _id: string;
  hostname: string;
  ip: string;
  mac: string;
  os: string;
  vendor: string;
  criticality: number;
  status: 'Active' | 'Down' | 'Compromised';
  networkId: string;
}

export interface PortScanResult {
  openPorts: number[];
  services: Array<{ port: number; banner: string; fingerprint: string }>;
  risks: import('./utils/vulnerabilities').VulnerabilityItem[];
  cvssLikeScore?: number;
  recommendations?: Array<{
    port: number;
    cve: string;
    title: string;
    recommendation: string;
  }>;
  mode: 'normal' | 'stealth';
  timestamp: string;
  vulnerable: boolean;
}

export interface SecurityEvent {
  id: string;
  type: 'NEW_UNKNOWN_DEVICE' | 'DOUBLE_AGENT';
  networkId: string;
  ip: string;
  mac: string;
  message: string;
  timestamp: string;
}

export interface NetworkWorkspace {
  id: string;
  label: string;
}
