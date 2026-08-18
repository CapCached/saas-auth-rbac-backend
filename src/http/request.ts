import { createHash } from "node:crypto";

import type { FastifyRequest } from "fastify";
import { z, type ZodType } from "zod";

import { errors } from "../domain/errors.js";
import type { AuditContext, DeviceInput, Principal } from "../store/types.js";

export const uuid = z.uuid();
export const email = z.email().trim().toLowerCase().max(254);
export const password = z.string().min(12).max(128);

export function parse<T>(schema: ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) {
    throw errors.validation({
      fields: result.error.issues.map((issue) => ({
        message: issue.message,
        path: issue.path.join("."),
      })),
    });
  }
  return result.data;
}

export function auditFrom(request: FastifyRequest): AuditContext {
  return {
    ipAddress: request.ip,
    requestId: request.id,
  };
}

export function deviceFrom(request: FastifyRequest, input: { deviceId: string; deviceName: string }): DeviceInput {
  const userAgent = request.headers["user-agent"];
  return {
    deviceId: input.deviceId,
    deviceName: input.deviceName,
    ipAddress: request.ip,
    ...(userAgent
      ? { userAgentHash: createHash("sha256").update(userAgent).digest("hex") }
      : {}),
  };
}

export function requirePrincipal(request: FastifyRequest): Principal {
  if (!request.principal) throw errors.authenticationRequired();
  return request.principal;
}

export function requireOrganization(request: FastifyRequest): string {
  if (!request.organizationId) throw errors.validation();
  return request.organizationId;
}
