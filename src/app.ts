import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import Fastify, { type FastifyInstance } from "fastify";
import { ZodError } from "zod";

import type { AppConfig } from "./config.js";
import type { Database } from "./db/pool.js";
import { AppError, errors } from "./domain/errors.js";
import { RequestGuards } from "./http/guards.js";
import { Metrics } from "./observability/metrics.js";
import { registerAuthRoutes } from "./routes/auth-routes.js";
import { registerRbacRoutes } from "./routes/rbac-routes.js";
import { AccessTokenService } from "./security/access-token.js";
import { constantTimeEqual } from "./security/password.js";
import type { RateLimiter } from "./security/rate-limiter.js";
import { AuthService } from "./services/auth-service.js";
import { RbacService } from "./services/rbac-service.js";
import { AuthStore } from "./store/auth-store.js";
import { RbacStore } from "./store/rbac-store.js";

export type AppDependencies = {
  config: AppConfig;
  database: Database;
  rateLimiter: RateLimiter;
};

export type BuiltApp = {
  accessTokens: AccessTokenService;
  app: FastifyInstance;
  auth: AuthService;
  metrics: Metrics;
  rbac: RbacService;
};

export async function buildApp(dependencies: AppDependencies): Promise<BuiltApp> {
  const { config, database, rateLimiter } = dependencies;
  const app = Fastify({
    bodyLimit: 1_048_576,
    genReqId: (request) => {
      const candidate = request.headers["x-request-id"];
      return typeof candidate === "string" && /^[0-9a-f-]{36}$/i.test(candidate)
        ? candidate
        : randomUUID();
    },
    logger: {
      level: config.logLevel,
      redact: {
        censor: "[REDACTED]",
        paths: [
          "req.headers.authorization",
          "req.headers.cookie",
          "res.headers['set-cookie']",
          "body.password",
          "body.newPassword",
          "body.refreshToken",
          "body.token",
        ],
      },
    },
    requestIdHeader: false,
    trustProxy: config.trustProxy,
  });
  const metrics = new Metrics();
  const accessTokens = await AccessTokenService.create(config);
  const auth = await AuthService.create({
    accessTokens,
    config,
    rateLimiter,
    store: new AuthStore(database),
  });
  const rbac = new RbacService(new RbacStore(database), config);
  const guards = new RequestGuards(auth, rbac, metrics, rateLimiter);
  const openApiDocument = await readFile(resolve("openapi/openapi.yaml"), "utf8");

  await app.register(helmet, {
    contentSecurityPolicy: false,
    global: true,
    hsts: config.nodeEnv === "production" ? { includeSubDomains: true, maxAge: 31_536_000 } : false,
  });
  await app.register(cors, {
    allowedHeaders: ["authorization", "content-type", "x-organization-id", "x-request-id"],
    credentials: false,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    origin: (origin, callback) => {
      if (!origin) {
        callback(null, true);
        return;
      }
      callback(null, config.corsOrigins.includes(origin));
    },
    strictPreflight: true,
  });

  app.addHook("onRequest", (request, reply, done) => {
    if (request.url.startsWith("/v1/")) {
      void reply.header("cache-control", "no-store").header("pragma", "no-cache");
    }
    done();
  });
  app.addHook("onResponse", (request, reply, done) => {
    metrics.requests.observe(
      {
        method: request.method,
        route: request.routeOptions.url ?? "unmatched",
        status_code: reply.statusCode.toString(),
      },
      reply.elapsedTime / 1_000,
    );
    done();
  });

  app.setErrorHandler((error, request, reply) => {
    const normalized = normalizeError(error);
    const sourceError = error instanceof Error ? error : new Error("Unknown request error");
    if (normalized.statusCode >= 500) {
      request.log.error(
        {
          errorCode:
            typeof error === "object" && error !== null && "code" in error
              ? String(error.code)
              : undefined,
          errorName: sourceError.name,
          stack: sourceError.stack,
        },
        "request failed",
      );
    }
    const includeDetails = normalized.statusCode === 400 || normalized.statusCode === 429;
    const retryAfterSeconds = normalized.details?.retryAfterSeconds;
    if (normalized.statusCode === 429 && typeof retryAfterSeconds === "number") {
      void reply.header("retry-after", retryAfterSeconds.toString());
    }
    return reply.status(normalized.statusCode).send({
      error: {
        code: normalized.code,
        ...(includeDetails && normalized.details ? { details: normalized.details } : {}),
        message: normalized.statusCode >= 500 ? "Internal server error" : normalized.message,
        request_id: request.id,
      },
    });
  });
  app.setNotFoundHandler((request, reply) =>
    reply.status(404).send({
      error: { code: "NOT_FOUND", message: "Resource not found", request_id: request.id },
    }),
  );

  app.get("/health/live", () => ({ status: "ok" }));
  app.get("/health/ready", async (_request, reply) => {
    const [databaseReady, redisReady] = await Promise.all([
      database.query("SELECT 1").then(() => true).catch(() => false),
      rateLimiter.ping(),
    ]);
    const ready = databaseReady && redisReady;
    return reply.status(ready ? 200 : 503).send({
      checks: { database: databaseReady, redis: redisReady },
      status: ready ? "ready" : "not_ready",
    });
  });
  app.get("/.well-known/jwks.json", async (_request, reply) =>
    reply.header("cache-control", "public, max-age=300").send(accessTokens.jwks()),
  );
  app.get("/openapi.yaml", (_request, reply) =>
    reply
      .header("cache-control", "public, max-age=300")
      .header("content-type", "application/yaml; charset=utf-8")
      .send(openApiDocument),
  );
  app.get("/metrics", async (request, reply) => {
    if (config.metricsToken) {
      const authorization = request.headers.authorization;
      const supplied = authorization?.startsWith("Bearer ") ? authorization.slice(7) : "";
      if (!constantTimeEqual(supplied, config.metricsToken)) throw errors.authenticationRequired();
    }
    return reply.header("content-type", metrics.registry.contentType).send(await metrics.registry.metrics());
  });

  registerAuthRoutes(app, { auth, guards, metrics });
  registerRbacRoutes(app, { guards, rbac });
  await app.ready();
  return { accessTokens, app, auth, metrics, rbac };
}

function normalizeError(error: unknown): AppError {
  if (error instanceof AppError) return error;
  if (error instanceof ZodError) return errors.validation();
  if (typeof error === "object" && error !== null && "code" in error) {
    if (error.code === "23505") return errors.conflict();
    if (error.code === "23503" || error.code === "23514" || error.code === "22P02") {
      return errors.validation();
    }
  }
  return new AppError(500, "INTERNAL_ERROR", "Internal server error");
}
