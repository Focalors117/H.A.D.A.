import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createScanRateLimiter } from '../utils/scanRateLimit.js';

function createReq(ip = '192.168.1.50') {
  return {
    ip,
    socket: { remoteAddress: ip },
    headers: {},
  } as any;
}

function createRes() {
  const res: any = {
    statusCode: 200,
    headers: new Map<string, string>(),
    payload: undefined,
    setHeader(name: string, value: string) {
      this.headers.set(name, value);
    },
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(body: unknown) {
      this.payload = body;
      return this;
    },
  };
  return res;
}

describe('createScanRateLimiter', () => {
  it('allows requests until the limit is reached and then blocks with 429', () => {
    let current = 1_000;
    const limiter = createScanRateLimiter({
      windowMs: 10_000,
      max: 2,
      now: () => current,
    });

    let nextCalls = 0;
    const next = () => {
      nextCalls += 1;
    };

    const req = createReq();
    const res1 = createRes();
    limiter.middleware(req, res1, next);
    assert.equal(res1.statusCode, 200);

    const res2 = createRes();
    limiter.middleware(req, res2, next);
    assert.equal(res2.statusCode, 200);

    const res3 = createRes();
    limiter.middleware(req, res3, next);
    assert.equal(res3.statusCode, 429);
    assert.equal(
      (res3.payload as { message?: string }).message,
      'Demasiadas solicitudes de escaneo. Intenta de nuevo más tarde.'
    );
    assert.equal(nextCalls, 2);
  });
});
