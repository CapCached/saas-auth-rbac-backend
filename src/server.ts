import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";
import { runMigrations } from "./db/migrate.js";
import { createPool } from "./db/pool.js";
import { MemoryRateLimiter, RedisRateLimiter } from "./security/rate-limiter.js";
import { OutboxWorker } from "./workers/outbox-worker.js";

const config = loadConfig();
const database = createPool(config);
const rateLimiter = config.redisUrl
  ? new RedisRateLimiter(config.redisUrl, config.rateLimitFailClosed)
  : new MemoryRateLimiter();

await runMigrations(database);
const { app, accessTokens } = await buildApp({ config, database, rateLimiter });
if (accessTokens.usingEphemeralDevelopmentKey) {
  app.log.warn("using an ephemeral development JWT key; all access tokens expire on restart");
}

const worker = config.workerEnabled ? new OutboxWorker(database, config, app.log) : undefined;
worker?.start();

let shuttingDown = false;
async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  app.log.info({ signal }, "graceful shutdown started");
  const forceExit = setTimeout(() => process.exit(1), 15_000);
  forceExit.unref();
  try {
    await app.close();
    await worker?.stop();
    await rateLimiter.close();
    await database.end();
    clearTimeout(forceExit);
  } catch (error) {
    app.log.error({ error }, "graceful shutdown failed");
    process.exitCode = 1;
  }
}

process.once("SIGINT", () => void shutdown("SIGINT"));
process.once("SIGTERM", () => void shutdown("SIGTERM"));

try {
  await app.listen({ host: config.host, port: config.port });
} catch (error) {
  app.log.fatal({ error }, "server failed to start");
  await shutdown("startup_failure");
  process.exitCode = 1;
}
