import { randomUUID } from "node:crypto";

import type { AppConfig } from "../config.js";
import { errors } from "../domain/errors.js";
import { AccessTokenService } from "../security/access-token.js";
import {
  generateOpaqueToken,
  hashOpaqueToken,
  isWellFormedOpaqueToken,
} from "../security/opaque-token.js";
import { hashPassword, verifyPassword } from "../security/password.js";
import type { RateLimiter } from "../security/rate-limiter.js";
import { rateLimitKey } from "../security/rate-limiter.js";
import type { AuthStore } from "../store/auth-store.js";
import type { AuditContext, DeviceInput, Principal, SessionTokensInput } from "../store/types.js";

export type TokenPair = {
  accessToken: string;
  expiresIn: number;
  refreshToken: string;
  tokenType: "Bearer";
};

export type AuthenticationResult = {
  organizationId?: string;
  tokens: TokenPair;
  user: { email: string; id: string };
};

export type AuthStorePort = Pick<
  AuthStore,
  | "consumePasswordReset"
  | "createPasswordReset"
  | "createSession"
  | "createTenantAccount"
  | "findCredentialByEmail"
  | "listSessions"
  | "revokeSession"
  | "rotateRefreshToken"
  | "validatePrincipal"
  | "writeAudit"
>;

export class AuthService {
  private constructor(
    private readonly store: AuthStorePort,
    private readonly accessTokens: AccessTokenService,
    private readonly rateLimiter: RateLimiter,
    private readonly config: AppConfig,
    private readonly dummyPasswordHash: string,
  ) {}

  public static async create(input: {
    accessTokens: AccessTokenService;
    config: AppConfig;
    rateLimiter: RateLimiter;
    store: AuthStorePort;
  }): Promise<AuthService> {
    const dummyPasswordHash = await hashPassword(
      "not-a-real-user-password-for-timing-equalization",
      input.config.passwordPepper,
    );
    return new AuthService(
      input.store,
      input.accessTokens,
      input.rateLimiter,
      input.config,
      dummyPasswordHash,
    );
  }

  public async register(input: {
    audit: AuditContext;
    device: DeviceInput;
    email: string;
    organizationName: string;
    password: string;
  }): Promise<AuthenticationResult> {
    await this.enforceLimit(`register-ip:${input.audit.ipAddress ?? "unknown"}`, 10, 900);
    const email = normalizeEmail(input.email);
    await this.enforceLimit(rateLimitKey("register-email", email), 5, 3_600);
    const passwordHash = await hashPassword(input.password, this.config.passwordPepper);
    const refreshToken = generateOpaqueToken("rt");
    const sessionTokens = this.newSessionTokens(refreshToken);

    try {
      const created = await this.store.createTenantAccount({
        audit: { ...input.audit, eventType: "auth.registered", outcome: "success" },
        device: input.device,
        email,
        organizationName: input.organizationName.trim(),
        passwordHash,
        tokens: sessionTokens,
      });
      return {
        organizationId: created.organizationId,
        tokens: await this.issuePair(created.principal, refreshToken),
        user: { email: created.principal.email, id: created.principal.userId },
      };
    } catch (error) {
      if (isPostgresUniqueViolation(error)) throw errors.conflict("An account with this email already exists");
      throw error;
    }
  }

  public async login(input: {
    audit: AuditContext;
    device: DeviceInput;
    email: string;
    password: string;
  }): Promise<AuthenticationResult> {
    await this.enforceLimit(`login-ip:${input.audit.ipAddress ?? "unknown"}`, 20, 900);
    const email = normalizeEmail(input.email);
    await this.enforceLimit(rateLimitKey("login-email", email), 10, 900);
    const user = await this.store.findCredentialByEmail(email);
    const validPassword = await verifyPassword(
      user?.passwordHash ?? this.dummyPasswordHash,
      input.password,
      this.config.passwordPepper,
    );

    if (!user || !validPassword || user.status !== "active") {
      await this.store
        .writeAudit({
          ...input.audit,
          ...(user ? { actorUserId: user.id, targetId: user.id } : {}),
          eventType: "auth.login_failed",
          metadata: { reason: "invalid_credentials" },
          outcome: "failure",
          targetType: "user",
        })
        .catch(() => undefined);
      throw errors.invalidCredentials();
    }

    const refreshToken = generateOpaqueToken("rt");
    const principal = await this.store.createSession(
      user,
      input.device,
      this.newSessionTokens(refreshToken),
      { ...input.audit, eventType: "auth.login_succeeded", outcome: "success" },
    );
    return {
      tokens: await this.issuePair(principal, refreshToken),
      user: { email: principal.email, id: principal.userId },
    };
  }

  public async refresh(input: { audit: AuditContext; refreshToken: string }): Promise<AuthenticationResult> {
    await this.enforceLimit(`refresh-ip:${input.audit.ipAddress ?? "unknown"}`, 60, 900);
    if (!isWellFormedOpaqueToken(input.refreshToken, "rt")) throw errors.invalidToken();
    const nextRefreshToken = generateOpaqueToken("rt");
    const rotated = await this.store.rotateRefreshToken({
      audit: input.audit,
      currentTokenHash: hashOpaqueToken(input.refreshToken, this.config.tokenPepper),
      nextExpiresAt: refreshExpiry(this.config.refreshTokenTtlDays),
      nextTokenHash: hashOpaqueToken(nextRefreshToken, this.config.tokenPepper),
    });
    if (rotated.kind === "reuse") throw errors.refreshTokenReuse();
    if (rotated.kind === "invalid") throw errors.invalidToken();
    return {
      tokens: await this.issuePair(rotated.principal, nextRefreshToken),
      user: { email: rotated.principal.email, id: rotated.principal.userId },
    };
  }

  public async authenticate(accessToken: string): Promise<Principal> {
    try {
      const identity = await this.accessTokens.verify(accessToken);
      const principal = await this.store.validatePrincipal(identity);
      if (!principal) throw errors.authenticationRequired();
      return principal;
    } catch (error) {
      if (error instanceof Error && "statusCode" in error) throw error;
      throw errors.authenticationRequired();
    }
  }

  public async logout(input: { audit: AuditContext; principal: Principal }): Promise<void> {
    await this.store.revokeSession({
      actorUserId: input.principal.userId,
      audit: { ...input.audit, eventType: "auth.logout", outcome: "success" },
      sessionId: input.principal.sessionId,
    });
  }

  public async forgotPassword(input: { audit: AuditContext; email: string }): Promise<void> {
    await this.enforceLimit(`password-reset-ip:${input.audit.ipAddress ?? "unknown"}`, 10, 3_600);
    const email = normalizeEmail(input.email);
    await this.enforceLimit(rateLimitKey("password-reset-email", email), 3, 3_600);
    const startedAt = performance.now();
    const token = generateOpaqueToken("pr");
    await this.store.createPasswordReset({
      audit: { ...input.audit, eventType: "auth.password_reset_requested", outcome: "success" },
      email,
      expiresAt: new Date(Date.now() + 15 * 60 * 1_000),
      rawToken: token,
      tokenHash: hashOpaqueToken(token, this.config.tokenPepper),
    });
    await waitForMinimumDuration(startedAt, 250);
  }

  public async resetPassword(input: {
    audit: AuditContext;
    newPassword: string;
    token: string;
  }): Promise<void> {
    await this.enforceLimit(`password-reset-consume:${input.audit.ipAddress ?? "unknown"}`, 10, 3_600);
    if (!isWellFormedOpaqueToken(input.token, "pr")) throw errors.invalidToken();
    const consumed = await this.store.consumePasswordReset({
      audit: { ...input.audit, eventType: "auth.password_reset_completed", outcome: "success" },
      passwordHash: await hashPassword(input.newPassword, this.config.passwordPepper),
      tokenHash: hashOpaqueToken(input.token, this.config.tokenPepper),
    });
    if (!consumed) throw errors.invalidToken();
  }

  public async listSessions(principal: Principal) {
    return this.store.listSessions(principal.userId, principal.sessionId);
  }

  public async revokeOwnSession(input: {
    audit: AuditContext;
    principal: Principal;
    sessionId: string;
  }): Promise<void> {
    const revoked = await this.store.revokeSession({
      actorUserId: input.principal.userId,
      audit: { ...input.audit, eventType: "session.revoked", outcome: "success" },
      sessionId: input.sessionId,
    });
    if (!revoked) throw errors.notFound();
  }

  private newSessionTokens(refreshToken: string): SessionTokensInput {
    const expiresAt = refreshExpiry(this.config.refreshTokenTtlDays);
    return {
      familyId: randomUUID(),
      refreshExpiresAt: expiresAt,
      refreshTokenHash: hashOpaqueToken(refreshToken, this.config.tokenPepper),
      sessionExpiresAt: expiresAt,
    };
  }

  private async issuePair(principal: Principal, refreshToken: string): Promise<TokenPair> {
    return {
      accessToken: await this.accessTokens.issue({
        authVersion: principal.authVersion,
        sessionId: principal.sessionId,
        userId: principal.userId,
      }),
      expiresIn: this.config.accessTokenTtlSeconds,
      refreshToken,
      tokenType: "Bearer",
    };
  }

  private async enforceLimit(key: string, limit: number, windowSeconds: number): Promise<void> {
    const result = await this.rateLimiter.consume(key, limit, windowSeconds);
    if (!result.allowed) {
      throw new (await import("../domain/errors.js")).AppError(
        429,
        "RATE_LIMITED",
        "Too many requests",
        { retryAfterSeconds: result.retryAfterSeconds },
      );
    }
  }
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function refreshExpiry(days: number): Date {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1_000);
}

function isPostgresUniqueViolation(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "23505";
}

async function waitForMinimumDuration(startedAt: number, minimumMilliseconds: number): Promise<void> {
  const remaining = minimumMilliseconds - (performance.now() - startedAt);
  if (remaining > 0) await new Promise((resolve) => setTimeout(resolve, remaining));
}
