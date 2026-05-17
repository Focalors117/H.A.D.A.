import { describe, expect, it } from 'vitest';
import { calculateRiskLevel, riskToCss } from './risk';

describe('calculateRiskLevel', () => {
  it('returns CRÍTICO when port 445 is open', () => {
    expect(calculateRiskLevel([22, 445, 8080])).toBe('CRÍTICO');
  });

  it('returns MEDIO when port 80 or 21 is open', () => {
    expect(calculateRiskLevel([80])).toBe('MEDIO');
    expect(calculateRiskLevel([21])).toBe('MEDIO');
  });

  it('returns BAJO when there are no matching ports', () => {
    expect(calculateRiskLevel([22, 443])).toBe('BAJO');
    expect(calculateRiskLevel(undefined)).toBe('BAJO');
  });
});

describe('riskToCss', () => {
  it('returns the pulse styling for CRÍTICO', () => {
    expect(riskToCss('CRÍTICO')).toContain('animate-pulse');
  });
});
