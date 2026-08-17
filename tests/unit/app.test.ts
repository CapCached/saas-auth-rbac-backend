import type { PoolClient, QueryResult, QueryResultRow } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { buildApp, type BuiltApp } from "../../src/app.js";
import type { Database } from "../../src/db/pool.js";
import { MemoryRateLimiter } from "../../src/security/rate-limiter.js";
import { testConfig } from "../helpers/config.js";

describe("HTTP boundary", () => {
  let built: BuiltApp;

  beforeAll(async () => {
    built = await buildApp({
      config: testConfig(),
      database: new HealthOnlyDatabase(),
      rateLimiter: new MemoryRateLimiter(),
    });
  });

  afterAll(async () => {
    await built.app.close();
  });

  it("returns stable health and JWKS endpoints", async () => {
    const live = await built.app.inject({ method: "GET", url: "/health/live" });
    expect(live.statusCode).toBe(200);
    expect(live.json()).toEqual({ status: "ok" });

    const jwks = await built.app.inject({ method: "GET", url: "/.well-known/jwks.json" });
    expect(jwks.statusCode).toBe(200);
    expect(jwks.json<{ keys: unknown[] }>().keys).toHaveLength(1);
  });

  it("uses a generic structured validation error", async () => {
    const response = await built.app.inject({
      method: "POST",
      payload: { email: "not-an-email", password: "short" },
      url: "/v1/auth/register",
    });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: { code: "VALIDATION_ERROR", message: "Request validation failed" },
    });
    expect(response.headers["cache-control"]).toBe("no-store");
  });

  it("rejects missing bearer authentication before domain logic", async () => {
    const response = await built.app.inject({ method: "GET", url: "/v1/organizations" });
    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({ error: { code: "AUTHENTICATION_REQUIRED" } });
  });

  it("does not expose unmatched routes", async () => {
    const response = await built.app.inject({ method: "GET", url: "/internal/secret" });
    expect(response.statusCode).toBe(404);
    expect(response.json()).toMatchObject({ error: { code: "NOT_FOUND" } });
  });

  it("allows only configured browser origins", async () => {
    const allowed = await built.app.inject({
      headers: { origin: "https://client.example" },
      method: "OPTIONS",
      url: "/v1/auth/login",
    });
    expect(allowed.headers["access-control-allow-origin"]).toBe("https://client.example");

    const denied = await built.app.inject({
      headers: { origin: "https://attacker.example" },
      method: "OPTIONS",
      url: "/v1/auth/login",
    });
    expect(denied.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("protects metrics with a separate operator token", async () => {
    const denied = await built.app.inject({ method: "GET", url: "/metrics" });
    expect(denied.statusCode).toBe(401);
    const allowed = await built.app.inject({
      headers: { authorization: "Bearer metrics-test-token-that-is-long-enough" },
      method: "GET",
      url: "/metrics",
    });
    expect(allowed.statusCode).toBe(200);
    expect(allowed.body).toContain("saas_auth_process_cpu");
  });
});

class HealthOnlyDatabase implements Database {
  public connect(): Promise<PoolClient> {
    return Promise.reject(new Error("No connection expected in HTTP unit tests"));
  }

  public end(): Promise<void> {
    return Promise.resolve();
  }

  public query<Row extends QueryResultRow = QueryResultRow>(): Promise<QueryResult<Row>> {
    return Promise.resolve({ command: "SELECT", fields: [], oid: 0, rowCount: 1, rows: [] });
  }
}
