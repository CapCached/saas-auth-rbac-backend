import { describe, expect, it } from "vitest";

import { MemoryRateLimiter, rateLimitKey } from "../../src/security/rate-limiter.js";

describe("rate limiting", () => {
  it("denies requests after the configured budget", async () => {
    const limiter = new MemoryRateLimiter();
    await expect(limiter.consume("login:ip", 2, 60)).resolves.toMatchObject({ allowed: true, remaining: 1 });
    await expect(limiter.consume("login:ip", 2, 60)).resolves.toMatchObject({ allowed: true, remaining: 0 });
    await expect(limiter.consume("login:ip", 2, 60)).resolves.toMatchObject({ allowed: false, remaining: 0 });
  });

  it("does not place emails or other identifiers in Redis keys", () => {
    const key = rateLimitKey("login-email", " Person@Example.com ");
    expect(key).toMatch(/^login-email:[a-f0-9]{64}$/);
    expect(key).not.toContain("person@example.com");
  });
});
