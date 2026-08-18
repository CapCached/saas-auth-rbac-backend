import pg, { type PoolClient, type QueryResult, type QueryResultRow } from "pg";

import type { AppConfig } from "../config.js";

const { Pool } = pg;

export type Database = {
  connect(): Promise<PoolClient>;
  end(): Promise<void>;
  query<Row extends QueryResultRow = QueryResultRow>(
    text: string,
    values?: readonly unknown[],
  ): Promise<QueryResult<Row>>;
};

export function createPool(config: AppConfig): Database {
  return new Pool({
    allowExitOnIdle: false,
    application_name: "saas-auth-rbac-backend",
    connectionString: config.databaseUrl,
    connectionTimeoutMillis: 5_000,
    idleTimeoutMillis: 30_000,
    max: 20,
    ssl: config.databaseSsl ? { rejectUnauthorized: true } : false,
    statement_timeout: 10_000,
  });
}

export async function withTransaction<T>(
  database: Database,
  operation: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await database.connect();
  try {
    await client.query("BEGIN");
    const result = await operation(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
