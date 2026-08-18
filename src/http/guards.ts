import type { FastifyRequest, preHandlerHookHandler } from "fastify";

import { AppError, errors } from "../domain/errors.js";
import { parse, uuid } from "./request.js";
import type { AuthService } from "../services/auth-service.js";
import type { RbacService } from "../services/rbac-service.js";
import type { Metrics } from "../observability/metrics.js";
import type { RateLimiter } from "../security/rate-limiter.js";

export class RequestGuards {
  public constructor(
    private readonly auth: AuthService,
    private readonly rbac: RbacService,
    private readonly metrics: Metrics,
    private readonly rateLimiter: RateLimiter,
  ) {}

  public readonly authenticate: preHandlerHookHandler = async (request) => {
    const authorization = request.headers.authorization;
    if (!authorization?.startsWith("Bearer ") || authorization.length <= 7) {
      throw errors.authenticationRequired();
    }
    request.principal = await this.auth.authenticate(authorization.slice(7));
    await enforceRateLimit(this.rateLimiter, `business-user:${request.principal.userId}`, 1_200, 60);
  };

  public readonly organization: preHandlerHookHandler = (request) => {
    const value = request.headers["x-organization-id"];
    if (typeof value !== "string") {
      throw errors.validation({ fields: [{ message: "x-organization-id is required", path: "headers" }] });
    }
    request.organizationId = parse(uuid, value);
    return Promise.resolve();
  };

  public permission(permission: string): preHandlerHookHandler {
    return async (request: FastifyRequest) => {
      if (!request.principal || !request.organizationId) throw errors.authenticationRequired();
      try {
        await enforceRateLimit(
          this.rateLimiter,
          `business-org-user:${request.organizationId}:${request.principal.userId}`,
          600,
          60,
        );
        await this.rbac.requirePermission({
          audit: { ipAddress: request.ip, requestId: request.id },
          organizationId: request.organizationId,
          permission,
          principal: request.principal,
        });
        this.metrics.authorization.inc({ outcome: "allowed", permission });
      } catch (error) {
        this.metrics.authorization.inc({ outcome: "denied", permission });
        throw error;
      }
    };
  }
}

async function enforceRateLimit(
  limiter: RateLimiter,
  key: string,
  limit: number,
  windowSeconds: number,
): Promise<void> {
  const result = await limiter.consume(key, limit, windowSeconds);
  if (!result.allowed) {
    throw new AppError(429, "RATE_LIMITED", "Too many requests", {
      retryAfterSeconds: result.retryAfterSeconds,
    });
  }
}
