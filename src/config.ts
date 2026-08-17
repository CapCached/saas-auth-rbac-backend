import { z } from "zod";

const booleanString = z
  .enum(["true", "false"])
  .transform((value) => value === "true");

const schema = z.object({
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(900).default(300),
  CORS_ORIGINS: z.string().default(""),
  DATABASE_SSL: booleanString.default(false),
  DATABASE_URL: z.string().min(1),
  HOST: z.string().default("0.0.0.0"),
  JWT_ACTIVE_KID: z.string().min(1).default("development-ephemeral"),
  JWT_AUDIENCE: z.string().min(1).default("saas-auth-api"),
  JWT_ISSUER: z.string().min(1).default("saas-auth-rbac-backend"),
  JWT_PRIVATE_KEY_BASE64: z.string().default(""),
  JWT_PUBLIC_KEYS_JSON: z.string().default("{}"),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
  METRICS_TOKEN: z.string().default(""),
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  OUTBOX_WEBHOOK_SECRET: z.string().default(""),
  OUTBOX_WEBHOOK_URL: z.union([z.url(), z.literal("")]).default(""),
  PASSWORD_PEPPER: z.string().min(32),
  PORT: z.coerce.number().int().min(1).max(65_535).default(3000),
  RATE_LIMIT_FAIL_CLOSED: booleanString.default(true),
  REDIS_URL: z.union([z.url(), z.literal("")]).default(""),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().min(1).max(90).default(30),
  TOKEN_PEPPER: z.string().min(32),
  TRUST_PROXY: booleanString.default(false),
  WORKER_ENABLED: booleanString.default(true),
});

export type AppConfig = {
  accessTokenTtlSeconds: number;
  corsOrigins: string[];
  databaseSsl: boolean;
  databaseUrl: string;
  host: string;
  jwtActiveKid: string;
  jwtAudience: string;
  jwtIssuer: string;
  jwtPrivateKeyPem: string | undefined;
  jwtPublicKeyPems: ReadonlyMap<string, string>;
  logLevel: z.infer<typeof schema>["LOG_LEVEL"];
  metricsToken: string;
  nodeEnv: z.infer<typeof schema>["NODE_ENV"];
  outboxWebhookSecret: string;
  outboxWebhookUrl: string;
  passwordPepper: string;
  port: number;
  rateLimitFailClosed: boolean;
  redisUrl: string;
  refreshTokenTtlDays: number;
  tokenPepper: string;
  trustProxy: boolean;
  workerEnabled: boolean;
};

function decodeBase64(value: string, name: string): string {
  try {
    const decoded = Buffer.from(value, "base64").toString("utf8");
    if (!decoded.includes("-----BEGIN")) {
      throw new Error("decoded value is not PEM");
    }
    return decoded;
  } catch (error) {
    throw new Error(`${name} must contain base64-encoded PEM`, { cause: error });
  }
}

function parsePublicKeys(value: string): ReadonlyMap<string, string> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch (error) {
    throw new Error("JWT_PUBLIC_KEYS_JSON must be valid JSON", { cause: error });
  }

  const keys = z.record(z.string().min(1), z.string().min(1)).parse(parsed);
  return new Map(
    Object.entries(keys).map(([kid, encodedPem]) => [
      kid,
      decodeBase64(encodedPem, `JWT_PUBLIC_KEYS_JSON.${kid}`),
    ]),
  );
}

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): AppConfig {
  const result = schema.safeParse(environment);
  if (!result.success) {
    throw new Error(`Invalid configuration: ${z.prettifyError(result.error)}`);
  }

  const env = result.data;
  const jwtPublicKeyPems = parsePublicKeys(env.JWT_PUBLIC_KEYS_JSON);
  const jwtPrivateKeyPem = env.JWT_PRIVATE_KEY_BASE64
    ? decodeBase64(env.JWT_PRIVATE_KEY_BASE64, "JWT_PRIVATE_KEY_BASE64")
    : undefined;

  if (env.NODE_ENV === "production") {
    const problems: string[] = [];
    if (!jwtPrivateKeyPem) problems.push("JWT_PRIVATE_KEY_BASE64 is required");
    if (!jwtPublicKeyPems.has(env.JWT_ACTIVE_KID)) {
      problems.push("JWT_PUBLIC_KEYS_JSON must contain JWT_ACTIVE_KID");
    }
    if (!env.REDIS_URL) problems.push("REDIS_URL is required");
    if (!env.METRICS_TOKEN) problems.push("METRICS_TOKEN is required");
    if (env.CORS_ORIGINS.trim() === "") problems.push("CORS_ORIGINS is required");
    if (!env.OUTBOX_WEBHOOK_URL) problems.push("OUTBOX_WEBHOOK_URL is required");
    if (env.OUTBOX_WEBHOOK_URL && !env.OUTBOX_WEBHOOK_URL.startsWith("https://")) {
      problems.push("OUTBOX_WEBHOOK_URL must use HTTPS");
    }
    if (env.OUTBOX_WEBHOOK_SECRET.length < 32) {
      problems.push("OUTBOX_WEBHOOK_SECRET must contain at least 32 characters");
    }
    if (problems.length > 0) {
      throw new Error(`Unsafe production configuration: ${problems.join("; ")}`);
    }
  }

  return {
    accessTokenTtlSeconds: env.ACCESS_TOKEN_TTL_SECONDS,
    corsOrigins: env.CORS_ORIGINS.split(",").map((item) => item.trim()).filter(Boolean),
    databaseSsl: env.DATABASE_SSL,
    databaseUrl: env.DATABASE_URL,
    host: env.HOST,
    jwtActiveKid: env.JWT_ACTIVE_KID,
    jwtAudience: env.JWT_AUDIENCE,
    jwtIssuer: env.JWT_ISSUER,
    jwtPrivateKeyPem,
    jwtPublicKeyPems,
    logLevel: env.LOG_LEVEL,
    metricsToken: env.METRICS_TOKEN,
    nodeEnv: env.NODE_ENV,
    outboxWebhookSecret: env.OUTBOX_WEBHOOK_SECRET,
    outboxWebhookUrl: env.OUTBOX_WEBHOOK_URL,
    passwordPepper: env.PASSWORD_PEPPER,
    port: env.PORT,
    rateLimitFailClosed: env.RATE_LIMIT_FAIL_CLOSED,
    redisUrl: env.REDIS_URL,
    refreshTokenTtlDays: env.REFRESH_TOKEN_TTL_DAYS,
    tokenPepper: env.TOKEN_PEPPER,
    trustProxy: env.TRUST_PROXY,
    workerEnabled: env.WORKER_ENABLED,
  };
}
