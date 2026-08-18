import { createHash } from "node:crypto";

import { Redis } from "ioredis";

import { errors } from "../domain/errors.js";

export type RateLimitResult = {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
};

export type RateLimiter = {
  consume(key: string, limit: number, windowSeconds: number): Promise<RateLimitResult>;
  close(): Promise<void>;
  ping(): Promise<boolean>;
};

const LUA = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
return {current, ttl}
`;

export class RedisRateLimiter implements RateLimiter {
  private readonly redis: Redis;

  public constructor(url: string, private readonly failClosed: boolean) {
    this.redis = new Redis(url, {
      commandTimeout: 1_000,
      connectTimeout: 2_000,
      enableOfflineQueue: false,
      lazyConnect: true,
      maxRetriesPerRequest: 1,
    });
    this.redis.on("error", () => undefined);
  }

  public async consume(key: string, limit: number, windowSeconds: number): Promise<RateLimitResult> {
    try {
      if (this.redis.status === "wait") await this.redis.connect();
      const response = (await this.redis.eval(
        LUA,
        1,
        `rate:${key}`,
        String(windowSeconds),
      )) as [number, number];
      const current = response[0];
      const ttl = Math.max(response[1], 1);
      return {
        allowed: current <= limit,
        remaining: Math.max(limit - current, 0),
        retryAfterSeconds: ttl,
      };
    } catch {
      if (this.failClosed) throw errors.serviceUnavailable();
      return { allowed: true, remaining: limit, retryAfterSeconds: 0 };
    }
  }

  public async ping(): Promise<boolean> {
    try {
      if (this.redis.status === "wait") await this.redis.connect();
      await this.redis.ping();
      return true;
    } catch {
      return false;
    }
  }

  public close(): Promise<void> {
    if (this.redis.status !== "end") this.redis.disconnect();
    return Promise.resolve();
  }
}

export class MemoryRateLimiter implements RateLimiter {
  private readonly entries = new Map<string, { count: number; expiresAt: number }>();

  public consume(key: string, limit: number, windowSeconds: number): Promise<RateLimitResult> {
    const now = Date.now();
    const current = this.entries.get(key);
    const entry = !current || current.expiresAt <= now
      ? { count: 0, expiresAt: now + windowSeconds * 1_000 }
      : current;
    entry.count += 1;
    this.entries.set(key, entry);
    return Promise.resolve({
      allowed: entry.count <= limit,
      remaining: Math.max(limit - entry.count, 0),
      retryAfterSeconds: Math.max(Math.ceil((entry.expiresAt - now) / 1_000), 1),
    });
  }

  public ping(): Promise<boolean> {
    return Promise.resolve(true);
  }

  public close(): Promise<void> {
    return Promise.resolve();
  }
}

export function rateLimitKey(namespace: string, value: string): string {
  const digest = createHash("sha256").update(value.trim().toLowerCase()).digest("hex");
  return `${namespace}:${digest}`;
}
