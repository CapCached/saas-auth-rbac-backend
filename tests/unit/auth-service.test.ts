import { describe, expect, it } from "vitest";

import { AccessTokenService } from "../../src/security/access-token.js";
import { MemoryRateLimiter } from "../../src/security/rate-limiter.js";
import {
  AuthService,
  type AuthStorePort,
} from "../../src/services/auth-service.js";
import { testConfig } from "../helpers/config.js";

describe("authentication service", () => {
  it("normalizes registration identity and returns a verifiable token pair", async () => {
    let storedEmail = "";
    const store = fakeAuthStore({
      createTenantAccount: (input) => {
        storedEmail = input.email;
        return Promise.resolve({
          organizationId: "2195bf07-b2f9-452c-b31f-8b69afdf9252",
          principal: {
            authVersion: 1,
            email: input.email,
            sessionId: "31514a17-7026-459b-9252-04373ea591a7",
            userId: "7f73ed54-8c03-4482-8bc7-ecc27a4f2457",
          },
        });
      },
    });
    const accessTokens = await AccessTokenService.create(testConfig());
    const service = await AuthService.create({
      accessTokens,
      config: testConfig(),
      rateLimiter: new MemoryRateLimiter(),
      store,
    });
    const result = await service.register({
      audit: { ipAddress: "127.0.0.1", requestId: "request-1" },
      device: { deviceId: "test-device-0001", deviceName: "Test" },
      email: " Person@Example.COM ",
      organizationName: "Example",
      password: "a long and unique password",
    });
    expect(storedEmail).toBe("person@example.com");
    expect(result.tokens.refreshToken).toMatch(/^rt_/);
    await expect(accessTokens.verify(result.tokens.accessToken)).resolves.toMatchObject({
      userId: "7f73ed54-8c03-4482-8bc7-ecc27a4f2457",
    });
  });

  it("returns one generic error for missing users and wrong passwords", async () => {
    const service = await createService(fakeAuthStore({ findCredentialByEmail: () => Promise.resolve(null) }));
    await expect(
      service.login({
        audit: { ipAddress: "127.0.0.1" },
        device: { deviceId: "test-device-0001", deviceName: "Test" },
        email: "missing@example.com",
        password: "not-the-right-password",
      }),
    ).rejects.toMatchObject({ code: "INVALID_CREDENTIALS", statusCode: 401 });
  });

  it("turns refresh reuse into an explicit session-revocation error", async () => {
    const service = await createService(
      fakeAuthStore({ rotateRefreshToken: () => Promise.resolve({ kind: "reuse" }) }),
    );
    const refreshToken = `rt_${"A".repeat(43)}`;
    await expect(service.refresh({ audit: { ipAddress: "127.0.0.1" }, refreshToken })).rejects.toMatchObject({
      code: "REFRESH_TOKEN_REUSE",
      statusCode: 401,
    });
  });

  it("rejects malformed refresh tokens without querying token state", async () => {
    let called = false;
    const service = await createService(
      fakeAuthStore({
        rotateRefreshToken: () => {
          called = true;
          return Promise.resolve({ kind: "invalid" });
        },
      }),
    );
    await expect(
      service.refresh({ audit: { ipAddress: "127.0.0.1" }, refreshToken: "rt_short" }),
    ).rejects.toMatchObject({ code: "INVALID_OR_EXPIRED_TOKEN" });
    expect(called).toBe(false);
  });
});

async function createService(store: AuthStorePort): Promise<AuthService> {
  const config = testConfig();
  return AuthService.create({
    accessTokens: await AccessTokenService.create(config),
    config,
    rateLimiter: new MemoryRateLimiter(),
    store,
  });
}

function fakeAuthStore(overrides: Partial<AuthStorePort> = {}): AuthStorePort {
  return {
    consumePasswordReset: () => Promise.resolve(false),
    createPasswordReset: () => Promise.resolve(),
    createSession: () => Promise.reject(new Error("unused createSession")),
    createTenantAccount: () => Promise.reject(new Error("unused createTenantAccount")),
    findCredentialByEmail: () => Promise.resolve(null),
    listSessions: () => Promise.resolve([]),
    revokeSession: () => Promise.resolve(false),
    rotateRefreshToken: () => Promise.resolve({ kind: "invalid" }),
    validatePrincipal: () => Promise.resolve(null),
    writeAudit: () => Promise.resolve(),
    ...overrides,
  };
}
