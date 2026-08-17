import type { AppConfig } from "../../src/config.js";

export function testConfig(overrides: Partial<AppConfig> = {}): AppConfig {
  return {
    accessTokenTtlSeconds: 300,
    corsOrigins: ["https://client.example"],
    databaseSsl: false,
    databaseUrl: "postgres://auth:auth@localhost:5432/auth_test",
    host: "127.0.0.1",
    jwtActiveKid: "test-key",
    jwtAudience: "test-api",
    jwtIssuer: "test-issuer",
    jwtPrivateKeyPem: undefined,
    jwtPublicKeyPems: new Map(),
    logLevel: "silent",
    metricsToken: "metrics-test-token-that-is-long-enough",
    nodeEnv: "test",
    outboxWebhookSecret: "outbox-test-secret-that-is-long-enough",
    outboxWebhookUrl: "https://events.example.test/auth",
    passwordPepper: "password-test-pepper-with-at-least-32-characters",
    port: 3000,
    rateLimitFailClosed: true,
    redisUrl: "",
    refreshTokenTtlDays: 30,
    tokenPepper: "opaque-token-test-pepper-at-least-32-characters",
    trustProxy: false,
    workerEnabled: false,
    ...overrides,
  };
}
