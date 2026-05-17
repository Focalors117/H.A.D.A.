import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { startTestServer } from './testServer.js';

let baseUrl = '';
let closeServer: (() => Promise<void>) | undefined;

before(async () => {
  const server = await startTestServer();
  baseUrl = server.baseUrl;
  closeServer = server.close;
});

after(async () => {
  await closeServer?.();
});

describe('/api/scan integration', () => {
  it('rejects public IP targets with a 400 response', async () => {
    const response = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: '8.8.8.8', mode: 'normal' }),
    });

    assert.equal(response.status, 400);
    const payload = (await response.json()) as { message?: string };
    assert.equal(payload.message, 'Solo se permiten IPs privadas para escaneo controlado.');
  });

  it('rate-limits repeated scans from the same client', async () => {
    const headers = {
      'Content-Type': 'application/json',
      'x-forwarded-for': '203.0.113.9',
    };

    const target = { ip: '10.255.255.1', mode: 'normal' };

    for (let index = 0; index < 3; index += 1) {
      const response = await fetch(`${baseUrl}/api/scan`, {
        method: 'POST',
        headers,
        body: JSON.stringify(target),
      });

      assert.notEqual(response.status, 429);
    }

    const blocked = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers,
      body: JSON.stringify(target),
    });

    assert.equal(blocked.status, 429);
    const payload = (await blocked.json()) as {
      message?: string;
      retryAfterSeconds?: number;
    };
    assert.equal(payload.message, 'Demasiadas solicitudes de escaneo. Intenta de nuevo más tarde.');
    assert.equal(typeof payload.retryAfterSeconds, 'number');
  });
});
