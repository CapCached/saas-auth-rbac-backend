import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { buildApp, type BuiltApp } from "../../src/app.js";
import { runMigrations } from "../../src/db/migrate.js";
import { createPool, type Database } from "../../src/db/pool.js";
import { MemoryRateLimiter } from "../../src/security/rate-limiter.js";
import { testConfig } from "../helpers/config.js";

const run = process.env.RUN_INTEGRATION_TESTS === "true";

describe.skipIf(!run)("PostgreSQL security boundaries", () => {
  let built: BuiltApp;
  let database: Database;
  const limiter = new MemoryRateLimiter();

  beforeAll(async () => {
    const databaseUrl = process.env.TEST_DATABASE_URL;
    if (!databaseUrl) throw new Error("TEST_DATABASE_URL is required for integration tests");
    const config = testConfig({ databaseUrl });
    database = createPool(config);
    await runMigrations(database);
    await database.query("TRUNCATE users RESTART IDENTITY CASCADE");
    built = await buildApp({ config, database, rateLimiter: limiter });
  });

  afterAll(async () => {
    await built.app.close();
    await limiter.close();
    await database.end();
  });

  it("prevents horizontal and vertical escalation across the complete lifecycle", async () => {
    const alpha = await register("alpha@example.test", "Alpha");
    const beta = await register("beta@example.test", "Beta");

    const project = await request<{ project: { id: string } }>({
      accessToken: alpha.accessToken,
      expectedStatus: 201,
      method: "POST",
      organizationId: alpha.organizationId,
      payload: { name: "Alpha private project" },
      url: "/v1/projects",
    });

    await request({
      accessToken: beta.accessToken,
      expectedStatus: 404,
      method: "GET",
      organizationId: alpha.organizationId,
      url: "/v1/projects",
    });
    await request({
      accessToken: beta.accessToken,
      expectedStatus: 404,
      method: "PUT",
      organizationId: alpha.organizationId,
      payload: { name: "Stolen" },
      url: `/v1/projects/${project.project.id}`,
    });

    const permissions = await request<{ permissions: { id: string; key: string }[] }>({
      accessToken: alpha.accessToken,
      expectedStatus: 200,
      method: "GET",
      organizationId: alpha.organizationId,
      url: "/v1/permissions",
    });
    const projectRead = required(permissions.permissions.find((permission) => permission.key === "project:read"));
    const viewer = await request<{ role: { id: string } }>({
      accessToken: alpha.accessToken,
      expectedStatus: 201,
      method: "POST",
      organizationId: alpha.organizationId,
      payload: { description: "Read-only project access", name: "Viewer", permissionIds: [projectRead.id] },
      url: "/v1/roles",
    });
    await request({
      accessToken: alpha.accessToken,
      expectedStatus: 201,
      method: "POST",
      organizationId: alpha.organizationId,
      payload: { email: "beta@example.test", roleId: viewer.role.id },
      url: "/v1/invitations",
    });
    const outbox = await database.query<{ token: string }>(
      `SELECT payload->>'token' AS token FROM outbox_events
        WHERE topic = 'organization.invited' ORDER BY created_at DESC LIMIT 1`,
    );
    const invitationToken = required(outbox.rows[0]).token;
    const accepted = await request<{ organizationId: string }>({
      accessToken: beta.accessToken,
      expectedStatus: 200,
      method: "POST",
      payload: { token: invitationToken },
      url: "/v1/invitations/accept",
    });
    expect(accepted.organizationId).toBe(alpha.organizationId);

    const visible = await request<{ projects: { id: string }[] }>({
      accessToken: beta.accessToken,
      expectedStatus: 200,
      method: "GET",
      organizationId: alpha.organizationId,
      url: "/v1/projects",
    });
    expect(visible.projects.map((item) => item.id)).toContain(project.project.id);
    await request({
      accessToken: beta.accessToken,
      expectedStatus: 403,
      method: "POST",
      organizationId: alpha.organizationId,
      payload: { name: "Not allowed" },
      url: "/v1/projects",
    });

    await request({
      accessToken: alpha.accessToken,
      expectedStatus: 200,
      method: "PUT",
      organizationId: alpha.organizationId,
      payload: { description: "No permissions", name: "Viewer", permissionIds: [] },
      url: `/v1/roles/${viewer.role.id}`,
    });
    await request({
      accessToken: beta.accessToken,
      expectedStatus: 403,
      method: "GET",
      organizationId: alpha.organizationId,
      url: "/v1/projects",
    });
    await request({
      expectedCode: "INVALID_OR_EXPIRED_TOKEN",
      expectedStatus: 401,
      method: "POST",
      payload: { refreshToken: beta.refreshToken },
      url: "/v1/auth/refresh",
    });

    await request({
      accessToken: alpha.accessToken,
      expectedCode: "CONFLICT",
      expectedStatus: 409,
      method: "DELETE",
      organizationId: alpha.organizationId,
      url: `/v1/members/${alpha.userId}`,
    });
  });

  it("detects refresh-token replay and revokes the rotated token family", async () => {
    const user = await register("replay@example.test", "Replay");
    const rotated = await request<{ access_token: string; refresh_token: string }>({
      expectedStatus: 200,
      method: "POST",
      payload: { refreshToken: user.refreshToken },
      url: "/v1/auth/refresh",
    });
    expect(rotated.refresh_token).not.toBe(user.refreshToken);

    await request({
      expectedCode: "REFRESH_TOKEN_REUSE",
      expectedStatus: 401,
      method: "POST",
      payload: { refreshToken: user.refreshToken },
      url: "/v1/auth/refresh",
    });
    await request({
      expectedCode: "INVALID_OR_EXPIRED_TOKEN",
      expectedStatus: 401,
      method: "POST",
      payload: { refreshToken: rotated.refresh_token },
      url: "/v1/auth/refresh",
    });
  });

  async function register(email: string, organizationName: string): Promise<{
    accessToken: string;
    organizationId: string;
    refreshToken: string;
    userId: string;
  }> {
    const result = await request<{
      access_token: string;
      organization_id: string;
      refresh_token: string;
      user: { id: string };
    }>({
      expectedStatus: 201,
      method: "POST",
      payload: {
        deviceId: `device-${organizationName.toLowerCase()}-0001`,
        deviceName: "Integration test",
        email,
        organizationName,
        password: "a unique integration password",
      },
      url: "/v1/auth/register",
    });
    return {
      accessToken: result.access_token,
      organizationId: result.organization_id,
      refreshToken: result.refresh_token,
      userId: result.user.id,
    };
  }

  async function request<T = Record<string, unknown>>(input: {
    accessToken?: string;
    expectedCode?: string;
    expectedStatus: number;
    method: "DELETE" | "GET" | "POST" | "PUT";
    organizationId?: string;
    payload?: Record<string, unknown>;
    url: string;
  }): Promise<T> {
    const response = await built.app.inject({
      headers: {
        ...(input.accessToken ? { authorization: `Bearer ${input.accessToken}` } : {}),
        ...(input.organizationId ? { "x-organization-id": input.organizationId } : {}),
      },
      method: input.method,
      ...(input.payload === undefined ? {} : { payload: input.payload }),
      url: input.url,
    });
    expect(response.statusCode, response.body).toBe(input.expectedStatus);
    const body = response.body ? response.json<unknown>() : {};
    if (input.expectedCode) {
      expect(body).toMatchObject({ error: { code: input.expectedCode } });
    }
    return body as T;
  }
});

function required<T>(value: T | undefined): T {
  if (value === undefined) throw new Error("Expected value to be present");
  return value;
}
