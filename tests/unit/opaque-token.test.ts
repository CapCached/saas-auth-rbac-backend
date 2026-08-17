import { describe, expect, it } from "vitest";

import {
  generateOpaqueToken,
  hashOpaqueToken,
  isWellFormedOpaqueToken,
} from "../../src/security/opaque-token.js";

describe("opaque tokens", () => {
  it("generates type-separated 256-bit tokens", () => {
    const refresh = generateOpaqueToken("rt");
    const reset = generateOpaqueToken("pr");
    expect(refresh).not.toBe(generateOpaqueToken("rt"));
    expect(isWellFormedOpaqueToken(refresh, "rt")).toBe(true);
    expect(isWellFormedOpaqueToken(reset, "pr")).toBe(true);
    expect(isWellFormedOpaqueToken(reset, "rt")).toBe(false);
  });

  it("stores only deterministic peppered digests", () => {
    const token = generateOpaqueToken("iv");
    const first = hashOpaqueToken(token, "a".repeat(32));
    expect(first).toMatch(/^[a-f0-9]{64}$/);
    expect(hashOpaqueToken(token, "a".repeat(32))).toBe(first);
    expect(hashOpaqueToken(token, "b".repeat(32))).not.toBe(first);
  });

  it("rejects malformed and truncated tokens", () => {
    expect(isWellFormedOpaqueToken("rt_short", "rt")).toBe(false);
    expect(isWellFormedOpaqueToken("xx_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).toBe(false);
  });
});
