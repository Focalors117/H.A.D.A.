# Security Review Checklist

## 1. API and Input Validation

- [ ] `/api/scan` blocks non-private, broadcast, and malformed IP targets.
- [ ] Request payloads are validated for required fields and accepted enum values.
- [ ] Error responses do not leak stack traces or infrastructure details.

## 2. Access and Abuse Controls

- [ ] Rate limiting is enabled for expensive endpoints (`/api/scan`).
- [ ] Alerts/logs exist for repeated 429 events from the same client.
- [ ] Workspace delete operations are authenticated/authorized in production.

## 3. Data Handling

- [ ] No credentials/secrets are committed in repository files.
- [ ] Sensitive runtime values are loaded from environment variables.
- [ ] Workspace deletion clears database + in-memory state consistently.

## 4. Network Scanning Safety

- [ ] Scans are limited to internal private network ranges.
- [ ] Stealth mode pacing is applied to reduce noisy traffic bursts.
- [ ] Scan fingerprints and recommendations are reviewed for false positives.

## 5. Frontend Safety

- [ ] User-provided strings are rendered safely (no unsafe HTML insertion).
- [ ] Telemetry and motion controls persist and can be disabled by users.
- [ ] Exported CSV/JSON content excludes secrets and internal tokens.

## 6. Dependency and Build Hygiene

- [ ] `npm audit` is reviewed for frontend and backend dependencies.
- [ ] CI runs lint/build/tests on pull requests.
- [ ] Production builds complete with no TypeScript errors.

## 7. Operational Readiness

- [ ] `/api/health` is monitored and alerts on degraded states.
- [ ] Backup/restore procedure exists for MongoDB data.
- [ ] Incident response contacts and rollback steps are documented.
