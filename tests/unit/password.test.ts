import { describe, expect, it } from "vitest";

import { constantTimeEqual, hashPassword, verifyPassword } from "../../src/security/password.js";

const pepper = "test-pepper-that-is-definitely-more-than-thirty-two-characters";

describe("password security", () => {
  it("uses the configured Argon2id floor and verifies only the right password", async () => {
    const hash = await hashPassword("correct horse battery staple", pepper);
    expect(hash).toMatch(/^\$argon2id\$v=19\$m=19456,(?:p=1,t=2|t=2,p=1)\$/);
    await expect(verifyPassword(hash, "correct horse battery staple", pepper)).resolves.toBe(true);
    await expect(verifyPassword(hash, "wrong password", pepper)).resolves.toBe(false);
  });

  it("does not verify after a pepper change", async () => {
    const hash = await hashPassword("correct horse battery staple", pepper);
    await expect(verifyPassword(hash, "correct horse battery staple", `${pepper}-rotated`)).resolves.toBe(
      false,
    );
  });

  it("compares operational tokens without early-exit equality", () => {
    expect(constantTimeEqual("same-value", "same-value")).toBe(true);
    expect(constantTimeEqual("same-value", "different-value")).toBe(false);
    expect(constantTimeEqual("short", "much-longer")).toBe(false);
  });
});
