import { generateKeyPair } from "node:crypto";
import { promisify } from "node:util";

import { decodeProtectedHeader, exportPKCS8, exportSPKI } from "jose";
import { describe, expect, it } from "vitest";

import { AccessTokenService } from "../../src/security/access-token.js";
import { testConfig } from "../helpers/config.js";

describe("access tokens", () => {
  it("issues explicitly typed EdDSA tokens and validates identity", async () => {
    const service = await AccessTokenService.create(testConfig());
    const identity = {
      authVersion: 4,
      sessionId: "90ac57dc-f891-4aa2-8f96-e93f8335cbe7",
      userId: "906d8f5b-c4d8-48f5-895b-3ca7687b6ee7",
    };
    const token = await service.issue(identity);
    expect(decodeProtectedHeader(token)).toMatchObject({ alg: "EdDSA", kid: "test-key", typ: "at+jwt" });
    await expect(service.verify(token)).resolves.toEqual(identity);
  });

  it("rejects a tampered token", async () => {
    const service = await AccessTokenService.create(testConfig());
    const token = await service.issue({ authVersion: 1, sessionId: "session", userId: "user" });
    const parts = token.split(".");
    const signature = parts[2];
    if (!parts[0] || !parts[1] || !signature) throw new Error("Expected a compact JWT");
    const replacement = signature.startsWith("A") ? "B" : "A";
    await expect(service.verify(`${parts[0]}.${parts[1]}.${replacement}${signature.slice(1)}`)).rejects.toThrow();
  });

  it("rejects a token issued for another audience", async () => {
    const pair = await promisify(generateKeyPair)("ed25519");
    const privateKey = await exportPKCS8(pair.privateKey);
    const publicKey = await exportSPKI(pair.publicKey);
    const shared = {
      jwtActiveKid: "shared-key",
      jwtPrivateKeyPem: privateKey,
      jwtPublicKeyPems: new Map([["shared-key", publicKey]]),
    };
    const issuer = await AccessTokenService.create(testConfig({ ...shared, jwtAudience: "api-one" }));
    const verifier = await AccessTokenService.create(testConfig({ ...shared, jwtAudience: "api-two" }));
    const token = await issuer.issue({ authVersion: 1, sessionId: "session", userId: "user" });
    await expect(verifier.verify(token)).rejects.toThrow();
  });

  it("publishes public keys without private key material", async () => {
    const service = await AccessTokenService.create(testConfig());
    const [key] = service.jwks().keys;
    expect(key).toMatchObject({ alg: "EdDSA", kid: "test-key", kty: "OKP", use: "sig" });
    expect(key).not.toHaveProperty("d");
  });
});
