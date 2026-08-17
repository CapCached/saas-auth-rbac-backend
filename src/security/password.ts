import { createHmac, timingSafeEqual } from "node:crypto";

import argon2 from "argon2";

const ARGON_OPTIONS = {
  hashLength: 32,
  memoryCost: 19_456,
  parallelism: 1,
  timeCost: 2,
  type: argon2.argon2id,
} as const;

function pepperPassword(password: string, pepper: string): Buffer {
  return createHmac("sha256", pepper).update(password, "utf8").digest();
}

export async function hashPassword(password: string, pepper: string): Promise<string> {
  return argon2.hash(pepperPassword(password, pepper), ARGON_OPTIONS);
}

export async function verifyPassword(
  storedHash: string,
  candidate: string,
  pepper: string,
): Promise<boolean> {
  try {
    return await argon2.verify(storedHash, pepperPassword(candidate, pepper));
  } catch {
    return false;
  }
}

export function constantTimeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}
