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

describe('/api/health integration', () => {
  it('returns runtime status for the backend', async () => {
    const response = await fetch(`${baseUrl}/api/health`);

    assert.equal(response.status, 200);
    const payload = (await response.json()) as {
      status?: string;
      mongoReady?: boolean;
      radarEnabled?: boolean;
      cachedAssets?: number;
      uptimeSeconds?: number;
    };

    assert.equal(payload.status, 'ok');
    assert.equal(typeof payload.mongoReady, 'boolean');
    assert.equal(typeof payload.radarEnabled, 'boolean');
    assert.equal(typeof payload.cachedAssets, 'number');
    assert.equal(typeof payload.uptimeSeconds, 'number');
  });
});
