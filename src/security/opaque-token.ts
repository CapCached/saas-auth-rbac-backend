import { createHmac, randomBytes } from "node:crypto";

const TOKEN_PATTERN = /^(rt|pr|iv)_[A-Za-z0-9_-]{43}$/;

export type OpaqueTokenPrefix = "iv" | "pr" | "rt";

export function generateOpaqueToken(prefix: OpaqueTokenPrefix): string {
  return `${prefix}_${randomBytes(32).toString("base64url")}`;
}

export function isWellFormedOpaqueToken(token: string, prefix?: OpaqueTokenPrefix): boolean {
  return TOKEN_PATTERN.test(token) && (prefix === undefined || token.startsWith(`${prefix}_`));
}

export function hashOpaqueToken(token: string, pepper: string): string {
  return createHmac("sha256", pepper).update(token, "utf8").digest("hex");
}
