import type { PoolClient } from "pg";

import { withTransaction, type Database } from "../db/pool.js";
import { errors } from "../domain/errors.js";
import { insertAudit } from "./auth-store.js";
import type {
  AuditContext,
  AuditInput,
  AuditSummary,
  AuthorizationResult,
  MemberSummary,
  OrganizationSummary,
  PermissionSummary,
  ProjectSummary,
  RoleSummary,
} from "./types.js";

export class RbacStore {
  public constructor(private readonly database: Database) {}

  public async authorize(userId: string, organizationId: string, permission: string): Promise<AuthorizationResult> {
    const result = await this.database.query<{ allowed: boolean; member: boolean }>(
      `SELECT
         EXISTS (
           SELECT 1 FROM organization_memberships m
           JOIN organizations o ON o.id = m.organization_id
           WHERE m.organization_id = $2 AND m.user_id = $1
             AND m.status = 'active' AND o.deleted_at IS NULL
         ) AS member,
         EXISTS (
           SELECT 1 FROM user_roles ur
           JOIN role_permissions rp
             ON rp.organization_id = ur.organization_id AND rp.role_id = ur.role_id
           JOIN permissions p ON p.id = rp.permission_id
           JOIN organization_memberships m
             ON m.organization_id = ur.organization_id AND m.user_id = ur.user_id
           JOIN organizations o ON o.id = ur.organization_id
           WHERE ur.organization_id = $2 AND ur.user_id = $1
             AND p.permission_key = $3 AND m.status = 'active' AND o.deleted_at IS NULL
         ) AS allowed`,
      [userId, organizationId, permission],
    );
    const row = result.rows[0];
    if (!row?.member) return "not_member";
    return row.allowed ? "allowed" : "forbidden";
  }

  public async writeAudit(input: AuditInput): Promise<void> {
    await this.database.query(
      `INSERT INTO audit_logs(
         organization_id, actor_user_id, event_type, outcome, target_type,
         target_id, request_id, ip_address, metadata
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        input.organizationId ?? null,
        input.actorUserId ?? null,
        input.eventType,
        input.outcome,
        input.targetType ?? null,
        input.targetId ?? null,
        input.requestId ?? null,
        input.ipAddress ?? null,
        JSON.stringify(input.metadata ?? {}),
      ],
    );
  }

  public async listOrganizations(userId: string): Promise<OrganizationSummary[]> {
    const result = await this.database.query<{
      id: string;
      name: string;
      role_names: string[] | null;
    }>(
      `SELECT o.id, o.name,
              array_remove(array_agg(DISTINCT r.name ORDER BY r.name), NULL) AS role_names
         FROM organizations o
         JOIN organization_memberships m ON m.organization_id = o.id
         LEFT JOIN user_roles ur ON ur.organization_id = o.id AND ur.user_id = m.user_id
         LEFT JOIN roles r ON r.id = ur.role_id
        WHERE m.user_id = $1 AND m.status = 'active' AND o.deleted_at IS NULL
        GROUP BY o.id, o.name ORDER BY o.name`,
      [userId],
    );
    return result.rows.map((row) => ({ id: row.id, name: row.name, roleNames: row.role_names ?? [] }));
  }

  public async createOrganization(input: {
    audit: AuditContext;
    name: string;
    userId: string;
  }): Promise<{ id: string; name: string }> {
    return withTransaction(this.database, async (client) => {
      const organization = await client.query<{ id: string; name: string }>(
        `INSERT INTO organizations(name, created_by) VALUES ($1, $2) RETURNING id, name`,
        [input.name, input.userId],
      );
      const row = requiredRow(organization.rows[0]);
      await client.query(
        `INSERT INTO organization_memberships(organization_id, user_id) VALUES ($1, $2)`,
        [row.id, input.userId],
      );
      const role = await client.query<{ id: string }>(
        `INSERT INTO roles(organization_id, name, description, is_system, is_owner)
         VALUES ($1, 'Owner', 'Full organization access', true, true) RETURNING id`,
        [row.id],
      );
      const roleId = requiredRow(role.rows[0]).id;
      await client.query(
        `INSERT INTO role_permissions(organization_id, role_id, permission_id)
         SELECT $1, $2, id FROM permissions`,
        [row.id, roleId],
      );
      await client.query(
        `INSERT INTO user_roles(organization_id, user_id, role_id, assigned_by)
         VALUES ($1, $2, $3, $2)`,
        [row.id, input.userId, roleId],
      );
      await insertAudit(client, {
        ...input.audit,
        actorUserId: input.userId,
        eventType: "organization.created",
        organizationId: row.id,
        outcome: "success",
        targetId: row.id,
        targetType: "organization",
      });
      return row;
    });
  }

  public async archiveOrganization(input: {
    actorUserId: string;
    audit: AuditContext;
    organizationId: string;
  }): Promise<boolean> {
    return withTransaction(this.database, async (client) => {
      const organization = await client.query(
        `SELECT id FROM organizations WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`,
        [input.organizationId],
      );
      if (organization.rowCount !== 1) return false;
      const members = await client.query<{ user_id: string }>(
        `SELECT user_id FROM organization_memberships WHERE organization_id = $1`,
        [input.organizationId],
      );
      const userIds = members.rows.map((row) => row.user_id);
      await revokeRefreshForUsers(client, userIds, "organization_archived");
      if (userIds.length > 0) {
        await client.query(
          `UPDATE sessions SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = 'organization_archived'
            WHERE user_id = ANY($1::uuid[]) AND revoked_at IS NULL`,
          [userIds],
        );
      }
      await client.query(`UPDATE organizations SET deleted_at = now(), updated_at = now() WHERE id = $1`, [
        input.organizationId,
      ]);
      await insertAudit(client, {
        ...input.audit,
        actorUserId: input.actorUserId,
        eventType: "organization.archived",
        organizationId: input.organizationId,
        outcome: "success",
        targetId: input.organizationId,
        targetType: "organization",
      });
      return true;
    });
  }

  public async updateOrganization(input: {
    audit: AuditContext;
    name: string;
    organizationId: string;
    userId: string;
  }): Promise<{ id: string; name: string } | null> {
    return withTransaction(this.database, async (client) => {
      const result = await client.query<{ id: string; name: string }>(
        `UPDATE organizations SET name = $2, updated_at = now()
          WHERE id = $1 AND deleted_at IS NULL RETURNING id, name`,
        [input.organizationId, input.name],
      );
      const row = result.rows[0];
      if (!row) return null;
      await insertAudit(client, {
        ...input.audit,
        actorUserId: input.userId,
        eventType: "organization.updated",
        organizationId: input.organizationId,
        outcome: "success",
        targetId: input.organizationId,
        targetType: "organization",
      });
      return row;
    });
  }

  public async listPermissions(): Promise<PermissionSummary[]> {
    const result = await this.database.query<{ description: string; id: string; permission_key: string }>(
      `SELECT id, permission_key, description FROM permissions ORDER BY permission_key`,
    );
    return result.rows.map((row) => ({ description: row.description, id: row.id, key: row.permission_key }));
  }

  public async listRoles(organizationId: string): Promise<RoleSummary[]> {
    const result = await this.database.query<{
      description: string;
      id: string;
      is_owner: boolean;
      is_system: boolean;
      name: string;
      permissions: string[] | null;
      version: number;
    }>(
      `SELECT r.id, r.name, r.description, r.is_system, r.is_owner, r.version,
              array_remove(array_agg(p.permission_key ORDER BY p.permission_key), NULL) AS permissions
         FROM roles r
         LEFT JOIN role_permissions rp ON rp.role_id = r.id AND rp.organization_id = r.organization_id
         LEFT JOIN permissions p ON p.id = rp.permission_id
        WHERE r.organization_id = $1
        GROUP BY r.id ORDER BY r.is_owner DESC, lower(r.name)`,
      [organizationId],
    );
    return result.rows.map(mapRole);
  }

  public async createRole(input: {
    actorUserId: string;
    audit: AuditContext;
    description: string;
    name: string;
    organizationId: string;
    permissionIds: string[];
  }): Promise<RoleSummary> {
    return withTransaction(this.database, async (client) => {
      await assertPermissionsExist(client, input.permissionIds);
      const role = await client.query<{
        description: string;
        id: string;
        is_owner: boolean;
        is_system: boolean;
        name: string;
        version: number;
      }>(
        `INSERT INTO roles(organization_id, name, description)
         VALUES ($1, $2, $3)
         RETURNING id, name, description, is_system, is_owner, version`,
        [input.organizationId, input.name, input.description],
      );
      const row = requiredRow(role.rows[0]);
      await insertRolePermissions(client, input.organizationId, row.id, input.permissionIds);
      await insertAudit(client, {
        ...input.audit,
        actorUserId: input.actorUserId,
        eventType: "role.created",
        organizationId: input.organizationId,
        outcome: "success",
        targetId: row.id,
        targetType: "role",
      });
      const permissionKeys = await permissionKeysForIds(client, input.permissionIds);
      return mapRole({ ...row, permissions: permissionKeys });
    });
  }

  public async updateRole(input: {
    actorUserId: string;
    audit: AuditContext;
    description: string;
    name: string;
    organizationId: string;
    permissionIds: string[];
    roleId: string;
  }): Promise<RoleSummary | null> {
    return withTransaction(this.database, async (client) => {
      const locked = await client.query<{ is_system: boolean }>(
        `SELECT is_system FROM roles WHERE id = $1 AND organization_id = $2 FOR UPDATE`,
        [input.roleId, input.organizationId],
      );
      const current = locked.rows[0];
      if (!current) return null;
      if (current.is_system) throw errors.conflict("System roles cannot be modified");
      await assertPermissionsExist(client, input.permissionIds);
      const role = await client.query<{
        description: string;
        id: string;
        is_owner: boolean;
        is_system: boolean;
        name: string;
        version: number;
      }>(
        `UPDATE roles SET name = $3, description = $4, version = version + 1, updated_at = now()
          WHERE id = $1 AND organization_id = $2
          RETURNING id, name, description, is_system, is_owner, version`,
        [input.roleId, input.organizationId, input.name, input.description],
      );
      await client.query(`DELETE FROM role_permissions WHERE role_id = $1`, [input.roleId]);
      await insertRolePermissions(client, input.organizationId, input.roleId, input.permissionIds);
      await revokeRefreshForRole(client, input.organizationId, input.roleId, "role_updated");
      await insertAudit(client, {
        ...input.audit,
        actorUserId: input.actorUserId,
        eventType: "role.updated",
        organizationId: input.organizationId,
        outcome: "success",
        targetId: input.roleId,
        targetType: "role",
      });
      return mapRole({
        ...requiredRow(role.rows[0]),
        permissions: await permissionKeysForIds(client, input.permissionIds),
      });
    });
  }

  public async deleteRole(input: {
    actorUserId: string;
    audit: AuditContext;
    organizationId: string;
    roleId: string;
  }): Promise<boolean> {
    return withTransaction(this.database, async (client) => {
      const role = await client.query<{ is_system: boolean }>(
        `SELECT is_system FROM roles WHERE id = $1 AND organization_id = $2 FOR UPDATE`,
        [input.roleId, input.organizationId],
      );
      const row = role.rows[0];
      if (!row) return false;
      if (row.is_system) throw errors.conflict("System roles cannot be deleted");
      await revokeRefreshForRole(client, input.organizationId, input.roleId, "role_deleted");
      await client.query(`DELETE FROM roles WHERE id = $1 AND organization_id = $2`, [
        input.roleId,
        input.organizationId,
      ]);
      await insertAudit(client, {
        ...input.audit,
        actorUserId: input.actorUserId,
        eventType: "role.deleted",
        organizationId: input.organizationId,
        outcome: "success",
        targetId: input.roleId,
        targetType: "role",
      });
      return true;
    });
  }

  public async listMembers(organizationId: string): Promise<MemberSummary[]> {
    const result = await this.database.query<{
      email: string;
      joined_at: Date;
      roles: { id: string; name: string }[] | null;
      status: string;
      user_id: string;
    }>(
      `SELECT m.user_id, u.email, m.status, m.joined_at,
              COALESCE(
                jsonb_agg(DISTINCT jsonb_build_object('id', r.id, 'name', r.name))
                  FILTER (WHERE r.id IS NOT NULL), '[]'::jsonb
              ) AS roles
         FROM organization_memberships m
         JOIN users u ON u.id = m.user_id
         LEFT JOIN user_roles ur ON ur.organization_id = m.organization_id AND ur.user_id = m.user_id
         LEFT JOIN roles r ON r.id = ur.role_id
        WHERE m.organization_id = $1
        GROUP BY m.user_id, u.email, m.status, m.joined_at
        ORDER BY u.email`,
      [organizationId],
    );
    return result.rows.map((row) => ({
      email: row.email,
      joinedAt: row.joined_at.toISOString(),
      roles: row.roles ?? [],
      status: row.status,
      userId: row.user_id,
    }));
  }

  public async assignRoles(input: {
    actorUserId: string;
    audit: AuditContext;
    organizationId: string;
    roleIds: string[];
    targetUserId: string;
  }): Promise<void> {
    await withTransaction(this.database, async (client) => {
      await lockOrganization(client, input.organizationId);
      const membership = await client.query(
        `SELECT 1 FROM organization_memberships
          WHERE organization_id = $1 AND user_id = $2 AND status = 'active' FOR UPDATE`,
        [input.organizationId, input.targetUserId],
      );
      if (membership.rowCount !== 1) throw errors.notFound();
      await assertRolesBelongToOrg(client, input.organizationId, input.roleIds);

      const ownerRole = await client.query<{ id: string }>(
        `SELECT id FROM roles WHERE organization_id = $1 AND is_owner = true`,
        [input.organizationId],
      );
      const ownerRoleId = requiredRow(ownerRole.rows[0]).id;
      const targetWasOwner = await hasRole(client, input.organizationId, input.targetUserId, ownerRoleId);
      const targetWillBeOwner = input.roleIds.includes(ownerRoleId);
      if (targetWasOwner !== targetWillBeOwner) {
        const actorIsOwner = await hasRole(client, input.organizationId, input.actorUserId, ownerRoleId);
        if (!actorIsOwner) throw errors.forbidden();
        if (targetWasOwner && !targetWillBeOwner) {
          const owners = await ownerCount(client, input.organizationId);
          if (owners <= 1) throw errors.conflict("The last organization owner cannot be removed");
        }
      }

      await client.query(`DELETE FROM user_roles WHERE organization_id = $1 AND user_id = $2`, [
        input.organizationId,
        input.targetUserId,
      ]);
      for (const roleId of input.roleIds) {
        await client.query(
          `INSERT INTO user_roles(organization_id, user_id, role_id, assigned_by)
           VALUES ($1, $2, $3, $4)`,
          [input.organizationId, input.targetUserId, roleId, input.actorUserId],
        );
      }
      await revokeRefreshForUsers(client, [input.targetUserId], "role_assignment_changed");
      await insertAudit(client, {
        ...input.audit,
        actorUserId: input.actorUserId,
        eventType: "member.roles_changed",
        metadata: { roleIds: input.roleIds },
        organizationId: input.organizationId,
        outcome: "success",
        targetId: input.targetUserId,
        targetType: "user",
      });
    });
  }

  public async createInvitation(input: {
    actorUserId: string;
    audit: AuditContext;
    email: string;
    expiresAt: Date;
    organizationId: string;
    rawToken: string;
    roleId: string;
    tokenHash: string;
  }): Promise<{ expiresAt: string; id: string }> {
    return withTransaction(this.database, async (client) => {
      await assertRolesBelongToOrg(client, input.organizationId, [input.roleId]);
      const owner = await client.query<{ is_owner: boolean }>(
        `SELECT is_owner FROM roles WHERE id = $1 AND organization_id = $2`,
        [input.roleId, input.organizationId],
      );
      if (owner.rows[0]?.is_owner) {
        const actorIsOwner = await hasRole(client, input.organizationId, input.actorUserId, input.roleId);
        if (!actorIsOwner) throw errors.forbidden();
      }
      await client.query(
        `UPDATE organization_invitations SET revoked_at = now()
          WHERE organization_id = $1 AND email = $2 AND accepted_at IS NULL AND revoked_at IS NULL`,
        [input.organizationId, input.email],
      );
      const invitation = await client.query<{ expires_at: Date; id: string }>(
        `INSERT INTO organization_invitations(
           organization_id, email, role_id, token_hash, invited_by, expires_at
         ) VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, expires_at`,
        [
          input.organizationId,
          input.email,
          input.roleId,
          input.tokenHash,
          input.actorUserId,
          input.expiresAt,
        ],
      );
      const row = requiredRow(invitation.rows[0]);
      await client.query(
        `INSERT INTO outbox_events(topic, payload)
         VALUES ('organization.invited', jsonb_build_object(
           'invitationId', $1::text, 'organizationId', $2::text,
           'email', $3::text, 'token', $4::text
         ))`,
        [row.id, input.organizationId, input.email, input.rawToken],
      );
      await insertAudit(client, {
        ...input.audit,
        actorUserId: input.actorUserId,
        eventType: "member.invited",
        metadata: { email: input.email, roleId: input.roleId },
        organizationId: input.organizationId,
        outcome: "success",
        targetId: row.id,
        targetType: "invitation",
      });
      return { expiresAt: row.expires_at.toISOString(), id: row.id };
    });
  }

  public async acceptInvitation(input: {
    audit: AuditContext;
    email: string;
    tokenHash: string;
    userId: string;
  }): Promise<{ organizationId: string }> {
    return withTransaction(this.database, async (client) => {
      const invitation = await client.query<{ id: string; organization_id: string; role_id: string }>(
        `SELECT id, organization_id, role_id FROM organization_invitations
          WHERE token_hash = $1 AND email = $2 AND accepted_at IS NULL
            AND revoked_at IS NULL AND expires_at > now()
          FOR UPDATE`,
        [input.tokenHash, input.email],
      );
      const row = invitation.rows[0];
      if (!row) throw errors.invalidToken();
      await client.query(
        `INSERT INTO organization_memberships(organization_id, user_id, status)
         VALUES ($1, $2, 'active')
         ON CONFLICT (organization_id, user_id) DO UPDATE SET status = 'active'`,
        [row.organization_id, input.userId],
      );
      await client.query(
        `INSERT INTO user_roles(organization_id, user_id, role_id, assigned_by)
         SELECT $1, $2, $3, invited_by FROM organization_invitations WHERE id = $4
         ON CONFLICT DO NOTHING`,
        [row.organization_id, input.userId, row.role_id, row.id],
      );
      await client.query(`UPDATE organization_invitations SET accepted_at = now() WHERE id = $1`, [row.id]);
      await insertAudit(client, {
        ...input.audit,
        actorUserId: input.userId,
        eventType: "member.invitation_accepted",
        organizationId: row.organization_id,
        outcome: "success",
        targetId: input.userId,
        targetType: "user",
      });
      return { organizationId: row.organization_id };
    });
  }

  public async removeMember(input: {
    actorUserId: string;
    audit: AuditContext;
    organizationId: string;
    targetUserId: string;
  }): Promise<boolean> {
    return withTransaction(this.database, async (client) => {
      await lockOrganization(client, input.organizationId);
      const ownerRole = await client.query<{ id: string }>(
        `SELECT id FROM roles WHERE organization_id = $1 AND is_owner = true`,
        [input.organizationId],
      );
      const ownerRoleId = requiredRow(ownerRole.rows[0]).id;
      if (await hasRole(client, input.organizationId, input.targetUserId, ownerRoleId)) {
        if (!(await hasRole(client, input.organizationId, input.actorUserId, ownerRoleId))) {
          throw errors.forbidden();
        }
        if ((await ownerCount(client, input.organizationId)) <= 1) {
          throw errors.conflict("The last organization owner cannot be removed");
        }
      }
      const removed = await client.query(
        `DELETE FROM organization_memberships WHERE organization_id = $1 AND user_id = $2`,
        [input.organizationId, input.targetUserId],
      );
      if (removed.rowCount !== 1) return false;
      await revokeRefreshForUsers(client, [input.targetUserId], "organization_membership_removed");
      await insertAudit(client, {
        ...input.audit,
        actorUserId: input.actorUserId,
        eventType: "member.removed",
        organizationId: input.organizationId,
        outcome: "success",
        targetId: input.targetUserId,
        targetType: "user",
      });
      return true;
    });
  }

  public async listAuditEvents(organizationId: string, beforeId?: string): Promise<AuditSummary[]> {
    const result = await this.database.query<{
      actor_user_id: string | null;
      created_at: Date;
      event_type: string;
      id: string;
      metadata: Record<string, unknown>;
      outcome: string;
      target_id: string | null;
      target_type: string | null;
    }>(
      `SELECT id::text, actor_user_id, event_type, outcome, target_type, target_id, metadata, created_at
         FROM audit_logs
        WHERE organization_id = $1 AND ($2::bigint IS NULL OR id < $2::bigint)
        ORDER BY id DESC LIMIT 100`,
      [organizationId, beforeId ?? null],
    );
    return result.rows.map((row) => ({
      actorUserId: row.actor_user_id,
      createdAt: row.created_at.toISOString(),
      eventType: row.event_type,
      id: row.id,
      metadata: row.metadata,
      outcome: row.outcome,
      targetId: row.target_id,
      targetType: row.target_type,
    }));
  }

  public async createProject(input: {
    actorUserId: string;
    audit: AuditContext;
    name: string;
    organizationId: string;
  }): Promise<ProjectSummary> {
    return withTransaction(this.database, async (client) => {
      const result = await client.query<{
        created_at: Date;
        created_by: string;
        id: string;
        name: string;
        updated_at: Date;
      }>(
        `INSERT INTO projects(organization_id, name, created_by)
         VALUES ($1, $2, $3) RETURNING id, name, created_by, created_at, updated_at`,
        [input.organizationId, input.name, input.actorUserId],
      );
      const row = requiredRow(result.rows[0]);
      await insertAudit(client, {
        ...input.audit,
        actorUserId: input.actorUserId,
        eventType: "project.created",
        organizationId: input.organizationId,
        outcome: "success",
        targetId: row.id,
        targetType: "project",
      });
      return mapProject(row);
    });
  }

  public async listProjects(organizationId: string): Promise<ProjectSummary[]> {
    const result = await this.database.query<{
      created_at: Date;
      created_by: string;
      id: string;
      name: string;
      updated_at: Date;
    }>(
      `SELECT id, name, created_by, created_at, updated_at
         FROM projects WHERE organization_id = $1 ORDER BY created_at DESC LIMIT 500`,
      [organizationId],
    );
    return result.rows.map(mapProject);
  }

  public async updateProject(input: {
    actorUserId: string;
    audit: AuditContext;
    name: string;
    organizationId: string;
    projectId: string;
  }): Promise<ProjectSummary | null> {
    return withTransaction(this.database, async (client) => {
      const result = await client.query<{
        created_at: Date;
        created_by: string;
        id: string;
        name: string;
        updated_at: Date;
      }>(
        `UPDATE projects SET name = $3, updated_at = now()
          WHERE organization_id = $1 AND id = $2
          RETURNING id, name, created_by, created_at, updated_at`,
        [input.organizationId, input.projectId, input.name],
      );
      const row = result.rows[0];
      if (!row) return null;
      await insertAudit(client, {
        ...input.audit,
        actorUserId: input.actorUserId,
        eventType: "project.updated",
        organizationId: input.organizationId,
        outcome: "success",
        targetId: input.projectId,
        targetType: "project",
      });
      return mapProject(row);
    });
  }

  public async deleteProject(input: {
    actorUserId: string;
    audit: AuditContext;
    organizationId: string;
    projectId: string;
  }): Promise<boolean> {
    return withTransaction(this.database, async (client) => {
      const result = await client.query(
        `DELETE FROM projects WHERE organization_id = $1 AND id = $2`,
        [input.organizationId, input.projectId],
      );
      if (result.rowCount !== 1) return false;
      await insertAudit(client, {
        ...input.audit,
        actorUserId: input.actorUserId,
        eventType: "project.deleted",
        organizationId: input.organizationId,
        outcome: "success",
        targetId: input.projectId,
        targetType: "project",
      });
      return true;
    });
  }
}

async function assertPermissionsExist(client: PoolClient, permissionIds: string[]): Promise<void> {
  if (new Set(permissionIds).size !== permissionIds.length) throw errors.validation();
  if (permissionIds.length === 0) return;
  const result = await client.query<{ count: string }>(
    `SELECT count(*)::text AS count FROM permissions WHERE id = ANY($1::uuid[])`,
    [permissionIds],
  );
  if (Number(result.rows[0]?.count) !== permissionIds.length) throw errors.validation();
}

async function lockOrganization(client: PoolClient, organizationId: string): Promise<void> {
  const result = await client.query(
    `SELECT id FROM organizations WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`,
    [organizationId],
  );
  if (result.rowCount !== 1) throw errors.notFound();
}

async function assertRolesBelongToOrg(
  client: PoolClient,
  organizationId: string,
  roleIds: string[],
): Promise<void> {
  if (new Set(roleIds).size !== roleIds.length) throw errors.validation();
  if (roleIds.length === 0) return;
  const result = await client.query<{ count: string }>(
    `SELECT count(*)::text AS count FROM roles WHERE organization_id = $1 AND id = ANY($2::uuid[])`,
    [organizationId, roleIds],
  );
  if (Number(result.rows[0]?.count) !== roleIds.length) throw errors.validation();
}

async function insertRolePermissions(
  client: PoolClient,
  organizationId: string,
  roleId: string,
  permissionIds: string[],
): Promise<void> {
  for (const permissionId of permissionIds) {
    await client.query(
      `INSERT INTO role_permissions(organization_id, role_id, permission_id) VALUES ($1, $2, $3)`,
      [organizationId, roleId, permissionId],
    );
  }
}

async function permissionKeysForIds(client: PoolClient, permissionIds: string[]): Promise<string[]> {
  if (permissionIds.length === 0) return [];
  const result = await client.query<{ permission_key: string }>(
    `SELECT permission_key FROM permissions WHERE id = ANY($1::uuid[]) ORDER BY permission_key`,
    [permissionIds],
  );
  return result.rows.map((row) => row.permission_key);
}

async function hasRole(
  client: PoolClient,
  organizationId: string,
  userId: string,
  roleId: string,
): Promise<boolean> {
  const result = await client.query(
    `SELECT 1 FROM user_roles WHERE organization_id = $1 AND user_id = $2 AND role_id = $3`,
    [organizationId, userId, roleId],
  );
  return result.rowCount === 1;
}

async function ownerCount(client: PoolClient, organizationId: string): Promise<number> {
  const result = await client.query<{ count: string }>(
    `SELECT count(DISTINCT ur.user_id)::text AS count
       FROM user_roles ur JOIN roles r ON r.id = ur.role_id
      WHERE ur.organization_id = $1 AND r.is_owner = true`,
    [organizationId],
  );
  return Number(result.rows[0]?.count ?? 0);
}

async function revokeRefreshForRole(
  client: PoolClient,
  organizationId: string,
  roleId: string,
  reason: string,
): Promise<void> {
  const users = await client.query<{ user_id: string }>(
    `SELECT user_id FROM user_roles WHERE organization_id = $1 AND role_id = $2`,
    [organizationId, roleId],
  );
  await revokeRefreshForUsers(client, users.rows.map((row) => row.user_id), reason);
}

async function revokeRefreshForUsers(client: PoolClient, userIds: string[], reason: string): Promise<void> {
  if (userIds.length === 0) return;
  await client.query(
    `UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = $2
      WHERE user_id = ANY($1::uuid[]) AND revoked_at IS NULL`,
    [userIds, reason],
  );
}

function mapRole(row: {
  description: string;
  id: string;
  is_owner: boolean;
  is_system: boolean;
  name: string;
  permissions: string[] | null;
  version: number;
}): RoleSummary {
  return {
    description: row.description,
    id: row.id,
    isOwner: row.is_owner,
    isSystem: row.is_system,
    name: row.name,
    permissions: row.permissions ?? [],
    version: row.version,
  };
}

function mapProject(row: {
  created_at: Date;
  created_by: string;
  id: string;
  name: string;
  updated_at: Date;
}): ProjectSummary {
  return {
    createdAt: row.created_at.toISOString(),
    createdBy: row.created_by,
    id: row.id,
    name: row.name,
    updatedAt: row.updated_at.toISOString(),
  };
}

function requiredRow<T>(row: T | undefined): T {
  if (!row) throw new Error("Database operation did not return a row");
  return row;
}
