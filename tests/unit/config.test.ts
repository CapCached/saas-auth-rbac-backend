import { describe, expect, it } from "vitest";

import { loadConfig } from "../../src/config.js";

const base = {
  DATABASE_URL: "postgres://localhost/test",
  PASSWORD_PEPPER: "p".repeat(32),
  TOKEN_PEPPER: "t".repeat(32),
};

describe("configuration", () => {
  it("accepts safe development defaults", () => {
    const config = loadConfig(base);
    expect(config.accessTokenTtlSeconds).toBe(300);
    expect(config.nodeEnv).toBe("development");
  });

  it("rejects short peppers", () => {
    expect(() => loadConfig({ ...base, TOKEN_PEPPER: "short" })).toThrow("Invalid configuration");
  });

  it("fails closed when production secrets and dependencies are absent", () => {
    expect(() => loadConfig({ ...base, NODE_ENV: "production" })).toThrow(
      /Unsafe production configuration/,
    );
  });

  it("caps access-token lifetime at fifteen minutes", () => {
    expect(() => loadConfig({ ...base, ACCESS_TOKEN_TTL_SECONDS: "901" })).toThrow(
      "Invalid configuration",
    );
  });

  it("rejects malformed public-key JSON", () => {
    expect(() => loadConfig({ ...base, JWT_PUBLIC_KEYS_JSON: "not-json" })).toThrow(
      "JWT_PUBLIC_KEYS_JSON must be valid JSON",
    );
  });
});
