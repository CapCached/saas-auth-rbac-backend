import type { FastifyInstance } from "fastify";
import { z } from "zod";

import type { RequestGuards } from "../http/guards.js";
import {
  auditFrom,
  deviceFrom,
  email,
  parse,
  password,
  requirePrincipal,
  uuid,
} from "../http/request.js";
import type { Metrics } from "../observability/metrics.js";
import type { AuthService, AuthenticationResult } from "../services/auth-service.js";

const deviceSchema = z.object({
  deviceId: z.string().min(8).max(200),
  deviceName: z.string().trim().max(120).default(""),
});
const registerSchema = deviceSchema.extend({
  email,
  organizationName: z.string().trim().min(1).max(120),
  password,
});
const loginSchema = deviceSchema.extend({ email, password });
const refreshSchema = z.object({ refreshToken: z.string().min(1).max(200) });
const forgotSchema = z.object({ email });
const resetSchema = z.object({ newPassword: password, token: z.string().min(1).max(200) });
const sessionParams = z.object({ sessionId: uuid });

export function registerAuthRoutes(
  app: FastifyInstance,
  dependencies: { auth: AuthService; guards: RequestGuards; metrics: Metrics },
): void {
  const { auth, guards, metrics } = dependencies;

  app.post("/v1/auth/register", async (request, reply) => {
    const body = parse(registerSchema, request.body);
    const result = await observeAuth(metrics, "register", () =>
      auth.register({
        audit: auditFrom(request),
        device: deviceFrom(request, body),
        email: body.email,
        organizationName: body.organizationName,
        password: body.password,
      }),
    );
    return reply.code(201).send(tokenResponse(result));
  });

  app.post("/v1/auth/login", async (request, reply) => {
    const body = parse(loginSchema, request.body);
    const result = await observeAuth(metrics, "login", () =>
      auth.login({
        audit: auditFrom(request),
        device: deviceFrom(request, body),
        email: body.email,
        password: body.password,
      }),
    );
    return reply.send(tokenResponse(result));
  });

  app.post("/v1/auth/refresh", async (request, reply) => {
    const body = parse(refreshSchema, request.body);
    const result = await observeAuth(metrics, "refresh", () =>
      auth.refresh({ audit: auditFrom(request), refreshToken: body.refreshToken }),
    );
    return reply.send(tokenResponse(result));
  });

  app.post(
    "/v1/auth/logout",
    { preHandler: [guards.authenticate] },
    async (request, reply) => {
      await auth.logout({ audit: auditFrom(request), principal: requirePrincipal(request) });
      metrics.authentication.inc({ operation: "logout", outcome: "success" });
      return reply.code(204).send();
    },
  );

  app.post("/v1/auth/password/forgot", async (request, reply) => {
    const body = parse(forgotSchema, request.body);
    await auth.forgotPassword({ audit: auditFrom(request), email: body.email });
    metrics.authentication.inc({ operation: "password_forgot", outcome: "accepted" });
    return reply.code(202).send({ message: "If the account exists, password reset instructions will be sent" });
  });

  app.post("/v1/auth/password/reset", async (request, reply) => {
    const body = parse(resetSchema, request.body);
    await observeAuth(metrics, "password_reset", () =>
      auth.resetPassword({ audit: auditFrom(request), newPassword: body.newPassword, token: body.token }),
    );
    return reply.code(204).send();
  });

  app.get("/v1/me", { preHandler: [guards.authenticate] }, (request) => {
    const principal = requirePrincipal(request);
    return { email: principal.email, id: principal.userId, session_id: principal.sessionId };
  });

  app.get("/v1/sessions", { preHandler: [guards.authenticate] }, async (request) => ({
    sessions: await auth.listSessions(requirePrincipal(request)),
  }));

  app.delete(
    "/v1/sessions/:sessionId",
    { preHandler: [guards.authenticate] },
    async (request, reply) => {
      const params = parse(sessionParams, request.params);
      await auth.revokeOwnSession({
        audit: auditFrom(request),
        principal: requirePrincipal(request),
        sessionId: params.sessionId,
      });
      return reply.code(204).send();
    },
  );
}

async function observeAuth<T>(metrics: Metrics, operation: string, action: () => Promise<T>): Promise<T> {
  try {
    const result = await action();
    metrics.authentication.inc({ operation, outcome: "success" });
    return result;
  } catch (error) {
    metrics.authentication.inc({ operation, outcome: "failure" });
    throw error;
  }
}

function tokenResponse(result: AuthenticationResult) {
  return {
    ...(result.organizationId ? { organization_id: result.organizationId } : {}),
    access_token: result.tokens.accessToken,
    expires_in: result.tokens.expiresIn,
    refresh_token: result.tokens.refreshToken,
    token_type: result.tokens.tokenType,
    user: result.user,
  };
}
