import type { NextFunction, Request, Response } from 'express';

type Bucket = {
  count: number;
  resetAt: number;
};

type ScanRateLimitOptions = {
  windowMs?: number;
  max?: number;
  now?: () => number;
};

export function createScanRateLimiter({
  windowMs = 60_000,
  max = 3,
  now = () => Date.now(),
}: ScanRateLimitOptions = {}) {
  const buckets = new Map<string, Bucket>();

  const middleware = (req: Request, res: Response, next: NextFunction) => {
    const forwarded = String(req.headers['x-forwarded-for'] ?? '')
      .split(',')[0]
      ?.trim();
    const key = forwarded || req.ip || req.socket?.remoteAddress || 'unknown';
    const current = now();
    const bucket = buckets.get(key);

    if (!bucket || current >= bucket.resetAt) {
      buckets.set(key, { count: 1, resetAt: current + windowMs });
      return next();
    }

    if (bucket.count >= max) {
      const retryAfterSeconds = Math.max(1, Math.ceil((bucket.resetAt - current) / 1000));
      res.setHeader('Retry-After', String(retryAfterSeconds));
      return res.status(429).json({
        message: 'Demasiadas solicitudes de escaneo. Intenta de nuevo más tarde.',
        retryAfterSeconds,
      });
    }

    bucket.count += 1;
    buckets.set(key, bucket);
    return next();
  };

  return {
    middleware,
    reset: () => buckets.clear(),
  };
}
