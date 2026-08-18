import type { PoolClient } from "pg";

import type { Database } from "../db/pool.js";
import { withTransaction } from "../db/pool.js";
import type {
  AuditContext,
  AuditInput,
  CredentialUser,
  DeviceInput,
  Principal,
  RefreshRotationResult,
  SessionSummary,
  SessionTokensInput,
} from "./types.js";

type CredentialRow = {
  auth_version: number;
  email: string;
  id: string;
  password_hash: string;
  status: "active" | "disabled";
};

export class AuthStore {
  public constructor(private readonly database: Database) {}

  public async createTenantAccount(input: {
    audit: AuditInput;
    device: DeviceInput;
    email: string;
    organizationName: string;
    passwordHash: string;
    tokens: SessionTokensInput;
  }): Promise<{ organizationId: string; principal: Principal }> {
    return withTransaction(this.database, async (client) => {
      const user = await client.query<{ auth_version: number; id: string }>(
        `INSERT INTO users(email, password_hash) VALUES ($1, $2)
         RETURNING id, auth_version`,
        [input.email, input.passwordHash],
      );
      const userId = requiredRow(user.rows[0]).id;
      const authVersion = requiredRow(user.rows[0]).auth_version;
      const organization = await client.query<{ id: string }>(
        `INSERT INTO organizations(name, created_by) VALUES ($1, $2) RETURNING id`,
        [input.organizationName, userId],
      );
      const organizationId = requiredRow(organization.rows[0]).id;
      await client.query(
        `INSERT INTO organization_memberships(organization_id, user_id) VALUES ($1, $2)`,
        [organizationId, userId],
      );
      const ownerRole = await client.query<{ id: string }>(
        `INSERT INTO roles(organization_id, name, description, is_system, is_owner)
         VALUES ($1, 'Owner', 'Full organization access', true, true)
         RETURNING id`,
        [organizationId],
      );
      const ownerRoleId = requiredRow(ownerRole.rows[0]).id;
      await client.query(
        `INSERT INTO role_permissions(organization_id, role_id, permission_id)
         SELECT $1, $2, id FROM permissions`,
        [organizationId, ownerRoleId],
      );
      await client.query(
        `INSERT INTO user_roles(organization_id, user_id, role_id, assigned_by)
         VALUES ($1, $2, $3, $2)`,
        [organizationId, userId, ownerRoleId],
      );
      const sessionId = await this.upsertSession(client, userId, input.device, input.tokens);
      await insertAudit(client, {
        ...input.audit,
        actorUserId: userId,
        organizationId,
        targetId: organizationId,
        targetType: "organization",
      });
      return {
        organizationId,
        principal: { authVersion, email: input.email, sessionId, userId },
      };
    });
  }

  public async findCredentialByEmail(email: string): Promise<CredentialUser | null> {
    const result = await this.database.query<CredentialRow>(
      `SELECT id, email, password_hash, status, auth_version FROM users WHERE email = $1`,
      [email],
    );
    const row = result.rows[0];
    return row
      ? {
          authVersion: row.auth_version,
          email: row.email,
          id: row.id,
          passwordHash: row.password_hash,
          status: row.status,
        }
      : null;
  }

  public async createSession(
    user: CredentialUser,
    device: DeviceInput,
    tokens: SessionTokensInput,
    audit: AuditInput,
  ): Promise<Principal> {
    return withTransaction(this.database, async (client) => {
      const sessionId = await this.upsertSession(client, user.id, device, tokens);
      await insertAudit(client, { ...audit, actorUserId: user.id, targetId: sessionId, targetType: "session" });
      return {
        authVersion: user.authVersion,
        email: user.email,
        sessionId,
        userId: user.id,
      };
    });
  }

  public async rotateRefreshToken(input: {
    audit: AuditContext;
    currentTokenHash: string;
    nextExpiresAt: Date;
    nextTokenHash: string;
  }): Promise<RefreshRotationResult> {
    return withTransaction(this.database, async (client) => {
      const result = await client.query<{
        auth_version: number;
        consumed_at: Date | null;
        email: string;
        expires_at: Date;
        family_id: string;
        id: string;
        refresh_revoked_at: Date | null;
        session_expires_at: Date;
        session_id: string;
        session_revoked_at: Date | null;
        status: string;
        user_id: string;
      }>(
        `SELECT rt.id, rt.family_id, rt.session_id, rt.user_id, rt.expires_at,
                rt.consumed_at, rt.revoked_at AS refresh_revoked_at,
                s.revoked_at AS session_revoked_at, s.expires_at AS session_expires_at,
                u.email, u.status, u.auth_version
           FROM refresh_tokens rt
           JOIN sessions s ON s.id = rt.session_id
           JOIN users u ON u.id = rt.user_id
          WHERE rt.token_hash = $1
          FOR UPDATE OF rt, s, u`,
        [input.currentTokenHash],
      );
      const token = result.rows[0];
      if (!token) return { kind: "invalid" };

      if (token.consumed_at) {
        await client.query(
          `UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = 'reuse_detected'
            WHERE family_id = $1`,
          [token.family_id],
        );
        await client.query(
          `UPDATE sessions SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = 'refresh_token_reuse'
            WHERE id = $1`,
          [token.session_id],
        );
        await insertAudit(client, {
          ...input.audit,
          actorUserId: token.user_id,
          eventType: "auth.refresh_reuse",
          outcome: "failure",
          targetId: token.session_id,
          targetType: "session",
        });
        return { kind: "reuse" };
      }

      const invalid =
        token.refresh_revoked_at !== null ||
        token.session_revoked_at !== null ||
        token.expires_at <= new Date() ||
        token.session_expires_at <= new Date() ||
        token.status !== "active";
      if (invalid) return { kind: "invalid" };

      const replacement = await client.query<{ id: string }>(
        `INSERT INTO refresh_tokens(
           family_id, session_id, user_id, token_hash, parent_token_id, expires_at
         ) VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id`,
        [
          token.family_id,
          token.session_id,
          token.user_id,
          input.nextTokenHash,
          token.id,
          input.nextExpiresAt,
        ],
      );
      await client.query(
        `UPDATE refresh_tokens SET consumed_at = now(), replaced_by_token_id = $2 WHERE id = $1`,
        [token.id, requiredRow(replacement.rows[0]).id],
      );
      await client.query(`UPDATE sessions SET last_seen_at = now() WHERE id = $1`, [token.session_id]);
      await insertAudit(client, {
        ...input.audit,
        actorUserId: token.user_id,
        eventType: "auth.refresh_succeeded",
        outcome: "success",
        targetId: token.session_id,
        targetType: "session",
      });
      return {
        kind: "rotated",
        principal: {
          authVersion: token.auth_version,
          email: token.email,
          sessionId: token.session_id,
          userId: token.user_id,
        },
      };
    });
  }

  public async validatePrincipal(input: {
    authVersion: number;
    sessionId: string;
    userId: string;
  }): Promise<Principal | null> {
    const result = await this.database.query<{
      auth_version: number;
      email: string;
      session_id: string;
      user_id: string;
    }>(
      `SELECT u.id AS user_id, u.email, u.auth_version, s.id AS session_id
         FROM users u
         JOIN sessions s ON s.user_id = u.id
        WHERE u.id = $1 AND s.id = $2 AND u.auth_version = $3
          AND u.status = 'active' AND s.revoked_at IS NULL AND s.expires_at > now()`,
      [input.userId, input.sessionId, input.authVersion],
    );
    const row = result.rows[0];
    return row
      ? {
          authVersion: row.auth_version,
          email: row.email,
          sessionId: row.session_id,
          userId: row.user_id,
        }
      : null;
  }

  public async revokeSession(input: {
    actorUserId: string;
    audit: AuditInput;
    sessionId: string;
    targetUserId?: string;
  }): Promise<boolean> {
    return withTransaction(this.database, async (client) => {
      const result = await client.query<{ user_id: string }>(
        `UPDATE sessions SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = 'explicit_revocation'
          WHERE id = $1 AND user_id = COALESCE($2, $3) RETURNING user_id`,
        [input.sessionId, input.targetUserId, input.actorUserId],
      );
      const row = result.rows[0];
      if (!row) return false;
      await client.query(
        `UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = 'session_revoked'
          WHERE session_id = $1`,
        [input.sessionId],
      );
      await insertAudit(client, {
        ...input.audit,
        actorUserId: input.actorUserId,
        targetId: input.sessionId,
        targetType: "session",
      });
      return true;
    });
  }

  public async listSessions(userId: string, currentSessionId: string): Promise<SessionSummary[]> {
    const result = await this.database.query<{
      created_at: Date;
      device_id: string;
      device_name: string;
      expires_at: Date;
      id: string;
      last_seen_at: Date;
      revoked_at: Date | null;
    }>(
      `SELECT id, device_id, device_name, created_at, last_seen_at, expires_at, revoked_at
         FROM sessions WHERE user_id = $1 ORDER BY last_seen_at DESC LIMIT 100`,
      [userId],
    );
    return result.rows.map((row) => ({
      createdAt: row.created_at.toISOString(),
      current: row.id === currentSessionId,
      deviceId: row.device_id,
      deviceName: row.device_name,
      expiresAt: row.expires_at.toISOString(),
      id: row.id,
      lastSeenAt: row.last_seen_at.toISOString(),
      revokedAt: row.revoked_at?.toISOString() ?? null,
    }));
  }

  public async createPasswordReset(input: {
    audit: AuditInput;
    email: string;
    expiresAt: Date;
    rawToken: string;
    tokenHash: string;
  }): Promise<void> {
    await withTransaction(this.database, async (client) => {
      const user = await client.query<{ id: string }>(`SELECT id FROM users WHERE email = $1 AND status = 'active'`, [
        input.email,
      ]);
      const userId = user.rows[0]?.id;
      if (!userId) return;
      await client.query(
        `UPDATE password_reset_tokens SET consumed_at = now()
          WHERE user_id = $1 AND consumed_at IS NULL`,
        [userId],
      );
      await client.query(
        `INSERT INTO password_reset_tokens(user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
        [userId, input.tokenHash, input.expiresAt],
      );
      await client.query(
        `INSERT INTO outbox_events(topic, payload)
         VALUES ('password_reset.requested', jsonb_build_object('userId', $1::text, 'email', $2::text, 'token', $3::text))`,
        [userId, input.email, input.rawToken],
      );
      await insertAudit(client, { ...input.audit, actorUserId: userId, targetId: userId, targetType: "user" });
    });
  }

  public async consumePasswordReset(input: {
    audit: AuditInput;
    passwordHash: string;
    tokenHash: string;
  }): Promise<boolean> {
    return withTransaction(this.database, async (client) => {
      const token = await client.query<{ id: string; user_id: string }>(
        `SELECT id, user_id FROM password_reset_tokens
          WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
          FOR UPDATE`,
        [input.tokenHash],
      );
      const row = token.rows[0];
      if (!row) return false;
      await client.query(`UPDATE password_reset_tokens SET consumed_at = now() WHERE id = $1`, [row.id]);
      await client.query(
        `UPDATE users SET password_hash = $2, auth_version = auth_version + 1, updated_at = now() WHERE id = $1`,
        [row.user_id, input.passwordHash],
      );
      await client.query(
        `UPDATE sessions SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = 'password_reset'
          WHERE user_id = $1`,
        [row.user_id],
      );
      await client.query(
        `UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = 'password_reset'
          WHERE user_id = $1`,
        [row.user_id],
      );
      await client.query(
        `INSERT INTO outbox_events(topic, payload)
         SELECT 'password_reset.completed', jsonb_build_object('userId', id::text, 'email', email)
         FROM users WHERE id = $1`,
        [row.user_id],
      );
      await insertAudit(client, {
        ...input.audit,
        actorUserId: row.user_id,
        targetId: row.user_id,
        targetType: "user",
      });
      return true;
    });
  }

  public async writeAudit(input: AuditInput): Promise<void> {
    await this.database.query(
      `INSERT INTO audit_logs(
         organization_id, actor_user_id, event_type, outcome, target_type,
         target_id, request_id, ip_address, metadata
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      auditValues(input),
    );
  }

  private async upsertSession(
    client: PoolClient,
    userId: string,
    device: DeviceInput,
    tokens: SessionTokensInput,
  ): Promise<string> {
    const existing = await client.query<{ id: string }>(
      `SELECT id FROM sessions WHERE user_id = $1 AND device_id = $2 FOR UPDATE`,
      [userId, device.deviceId],
    );
    const previous = existing.rows[0];
    let sessionId: string;
    if (previous) {
      sessionId = previous.id;
      await client.query(
        `UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = 'device_reauthenticated'
          WHERE session_id = $1`,
        [sessionId],
      );
      await client.query(
        `UPDATE sessions SET device_name = $2, user_agent_hash = $3, ip_address = $4,
             created_at = now(), last_seen_at = now(), expires_at = $5,
             revoked_at = NULL, revoke_reason = NULL
          WHERE id = $1`,
        [
          sessionId,
          device.deviceName,
          device.userAgentHash ?? null,
          device.ipAddress ?? null,
          tokens.sessionExpiresAt,
        ],
      );
    } else {
      const inserted = await client.query<{ id: string }>(
        `INSERT INTO sessions(user_id, device_id, device_name, user_agent_hash, ip_address, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
        [
          userId,
          device.deviceId,
          device.deviceName,
          device.userAgentHash ?? null,
          device.ipAddress ?? null,
          tokens.sessionExpiresAt,
        ],
      );
      sessionId = requiredRow(inserted.rows[0]).id;
    }
    await client.query(
      `INSERT INTO refresh_tokens(family_id, session_id, user_id, token_hash, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [tokens.familyId, sessionId, userId, tokens.refreshTokenHash, tokens.refreshExpiresAt],
    );
    return sessionId;
  }
}

export async function insertAudit(client: PoolClient, input: AuditInput): Promise<void> {
  await client.query(
    `INSERT INTO audit_logs(
       organization_id, actor_user_id, event_type, outcome, target_type,
       target_id, request_id, ip_address, metadata
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    auditValues(input),
  );
}

function auditValues(input: AuditInput): unknown[] {
  return [
    input.organizationId ?? null,
    input.actorUserId ?? null,
    input.eventType,
    input.outcome,
    input.targetType ?? null,
    input.targetId ?? null,
    input.requestId ?? null,
    input.ipAddress ?? null,
    JSON.stringify(input.metadata ?? {}),
  ];
}

function requiredRow<T>(row: T | undefined): T {
  if (!row) throw new Error("Database operation did not return a row");
  return row;
}
