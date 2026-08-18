import { generateKeyPair, randomUUID } from "node:crypto";
import { promisify } from "node:util";

import {
  exportJWK,
  exportPKCS8,
  exportSPKI,
  importPKCS8,
  importSPKI,
  jwtVerify,
  SignJWT,
  type JWK,
  type JWTPayload,
  type KeyInput,
} from "jose";

import type { AppConfig } from "../config.js";

const generateKeyPairAsync = promisify(generateKeyPair);
const ALGORITHM = "EdDSA";
const TOKEN_TYPE = "at+jwt";

export type AccessIdentity = {
  authVersion: number;
  sessionId: string;
  userId: string;
};

type PublicKeyRecord = {
  jwk: JWK;
  key: KeyInput;
};

export class AccessTokenService {
  private constructor(
    private readonly activeKid: string,
    private readonly privateKey: KeyInput,
    private readonly publicKeys: ReadonlyMap<string, PublicKeyRecord>,
    private readonly issuer: string,
    private readonly audience: string,
    private readonly ttlSeconds: number,
    public readonly usingEphemeralDevelopmentKey: boolean,
  ) {}

  public static async create(config: AppConfig): Promise<AccessTokenService> {
    let privateKeyPem = config.jwtPrivateKeyPem;
    const publicKeyPems = new Map(config.jwtPublicKeyPems);
    let ephemeral = false;

    if (!privateKeyPem) {
      if (config.nodeEnv === "production") {
        throw new Error("JWT private key is required in production");
      }
      const pair = await generateKeyPairAsync("ed25519");
      privateKeyPem = await exportPKCS8(pair.privateKey);
      publicKeyPems.set(config.jwtActiveKid, await exportSPKI(pair.publicKey));
      ephemeral = true;
    }

    if (!publicKeyPems.has(config.jwtActiveKid)) {
      throw new Error("The active JWT public key is missing");
    }

    const privateKey = await importPKCS8(privateKeyPem, ALGORITHM);
    const keyEntries = await Promise.all(
      [...publicKeyPems.entries()].map(async ([kid, pem]) => {
        const key = await importSPKI(pem, ALGORITHM);
        const jwk = await exportJWK(key);
        return [kid, { jwk: { ...jwk, alg: ALGORITHM, kid, use: "sig" }, key }] as const;
      }),
    );

    const service = new AccessTokenService(
      config.jwtActiveKid,
      privateKey,
      new Map(keyEntries),
      config.jwtIssuer,
      config.jwtAudience,
      config.accessTokenTtlSeconds,
      ephemeral,
    );
    const probe = await service.issue({ authVersion: 1, sessionId: "startup-check", userId: "startup-check" });
    await service.verify(probe);
    return service;
  }

  public async issue(identity: AccessIdentity): Promise<string> {
    return new SignJWT({
      av: identity.authVersion,
      sid: identity.sessionId,
      token_use: "access",
    })
      .setProtectedHeader({ alg: ALGORITHM, kid: this.activeKid, typ: TOKEN_TYPE })
      .setSubject(identity.userId)
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .setJti(randomUUID())
      .setIssuedAt()
      .setExpirationTime(`${this.ttlSeconds}s`)
      .sign(this.privateKey);
  }

  public async verify(token: string): Promise<AccessIdentity> {
    const verified = await jwtVerify(
      token,
      (header) => {
        if (header.alg !== ALGORITHM || header.typ !== TOKEN_TYPE || !header.kid) {
          throw new Error("Unsupported JWT header");
        }
        const record = this.publicKeys.get(header.kid);
        if (!record) throw new Error("Unknown signing key");
        return record.key;
      },
      {
        algorithms: [ALGORITHM],
        audience: this.audience,
        clockTolerance: 30,
        issuer: this.issuer,
        requiredClaims: ["sub", "sid", "av", "jti", "iat", "exp"],
        typ: TOKEN_TYPE,
      },
    );
    return parseIdentity(verified.payload);
  }

  public jwks(): { keys: JWK[] } {
    return { keys: [...this.publicKeys.values()].map(({ jwk }) => jwk) };
  }
}

function parseIdentity(payload: JWTPayload): AccessIdentity {
  if (
    payload.token_use !== "access" ||
    typeof payload.sub !== "string" ||
    typeof payload.sid !== "string" ||
    typeof payload.av !== "number" ||
    !Number.isSafeInteger(payload.av)
  ) {
    throw new Error("Invalid access token claims");
  }
  return { authVersion: payload.av, sessionId: payload.sid, userId: payload.sub };
}
