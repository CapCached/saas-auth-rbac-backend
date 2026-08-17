import { generateKeyPair } from "node:crypto";
import { promisify } from "node:util";

import { exportPKCS8, exportSPKI } from "jose";

const pair = await promisify(generateKeyPair)("ed25519");
const privatePem = await exportPKCS8(pair.privateKey);
const publicPem = await exportSPKI(pair.publicKey);
const kid = `key-${new Date().toISOString().slice(0, 10)}`;

process.stdout.write(
  [
    `JWT_ACTIVE_KID=${kid}`,
    `JWT_PRIVATE_KEY_BASE64=${Buffer.from(privatePem).toString("base64")}`,
    `JWT_PUBLIC_KEYS_JSON=${JSON.stringify({ [kid]: Buffer.from(publicPem).toString("base64") })}`,
    "",
  ].join("\n"),
);
