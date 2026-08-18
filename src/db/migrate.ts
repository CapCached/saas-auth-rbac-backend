import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import type { PoolClient } from "pg";

import { loadConfig } from "../config.js";
import { createPool, type Database } from "./pool.js";

const MIGRATION_LOCK_ID = 1_947_031_221;

export async function runMigrations(database: Database, directory = resolve("migrations")): Promise<void> {
  const client = await database.connect();
  try {
    await client.query("SELECT pg_advisory_lock($1)", [MIGRATION_LOCK_ID]);
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        name text PRIMARY KEY,
        checksum text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);

    const files = (await readdir(directory)).filter((file) => file.endsWith(".sql")).sort();
    for (const file of files) {
      await applyMigration(client, file, await readFile(resolve(directory, file), "utf8"));
    }
  } finally {
    await client.query("SELECT pg_advisory_unlock($1)", [MIGRATION_LOCK_ID]).catch(() => undefined);
    client.release();
  }
}

async function applyMigration(client: PoolClient, name: string, sql: string): Promise<void> {
  const checksum = createHash("sha256").update(sql).digest("hex");
  const existing = await client.query<{ checksum: string }>(
    "SELECT checksum FROM schema_migrations WHERE name = $1",
    [name],
  );
  if (existing.rowCount === 1) {
    if (existing.rows[0]?.checksum !== checksum) {
      throw new Error(`Migration ${name} was modified after being applied`);
    }
    return;
  }

  await client.query("BEGIN");
  try {
    await client.query("SET LOCAL lock_timeout = '5s'");
    await client.query("SET LOCAL statement_timeout = '60s'");
    await client.query(sql);
    await client.query("INSERT INTO schema_migrations(name, checksum) VALUES ($1, $2)", [name, checksum]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  }
}

async function main(): Promise<void> {
  const database = createPool(loadConfig());
  try {
    await runMigrations(database);
  } finally {
    await database.end();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
