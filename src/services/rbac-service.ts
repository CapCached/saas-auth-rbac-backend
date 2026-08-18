import type { AuditContext, Principal } from "../store/types.js";
import { errors } from "../domain/errors.js";
import {
  generateOpaqueToken,
  hashOpaqueToken,
  isWellFormedOpaqueToken,
} from "../security/opaque-token.js";
import type { AppConfig } from "../config.js";
import type { RbacStore } from "../store/rbac-store.js";

export type RbacStorePort = Pick<
  RbacStore,
  | "acceptInvitation"
  | "archiveOrganization"
  | "assignRoles"
  | "authorize"
  | "createInvitation"
  | "createOrganization"
  | "createProject"
  | "createRole"
  | "deleteProject"
  | "deleteRole"
  | "listAuditEvents"
  | "listMembers"
  | "listOrganizations"
  | "listPermissions"
  | "listProjects"
  | "listRoles"
  | "removeMember"
  | "updateOrganization"
  | "updateProject"
  | "updateRole"
  | "writeAudit"
>;

export class RbacService {
  public constructor(
    private readonly store: RbacStorePort,
    private readonly config: AppConfig,
  ) {}

  public async requirePermission(input: {
    audit: AuditContext;
    organizationId: string;
    permission: string;
    principal: Principal;
  }): Promise<void> {
    const result = await this.store.authorize(
      input.principal.userId,
      input.organizationId,
      input.permission,
    );
    if (result === "allowed") return;
    await this.store
      .writeAudit({
        ...input.audit,
        actorUserId: input.principal.userId,
        eventType: "authorization.denied",
        metadata: { permission: input.permission, reason: result },
        organizationId: input.organizationId,
        outcome: "denied",
        targetId: input.organizationId,
        targetType: "organization",
      })
      .catch(() => undefined);
    if (result === "not_member") throw errors.notFound();
    throw errors.forbidden();
  }

  public listOrganizations(userId: string) {
    return this.store.listOrganizations(userId);
  }

  public createOrganization(input: { audit: AuditContext; name: string; principal: Principal }) {
    return this.store.createOrganization({
      audit: input.audit,
      name: input.name.trim(),
      userId: input.principal.userId,
    });
  }

  public updateOrganization(input: {
    audit: AuditContext;
    name: string;
    organizationId: string;
    principal: Principal;
  }) {
    return this.store.updateOrganization({
      audit: input.audit,
      name: input.name.trim(),
      organizationId: input.organizationId,
      userId: input.principal.userId,
    });
  }

  public archiveOrganization(input: {
    audit: AuditContext;
    organizationId: string;
    principal: Principal;
  }) {
    return this.store.archiveOrganization({
      actorUserId: input.principal.userId,
      audit: input.audit,
      organizationId: input.organizationId,
    });
  }

  public listPermissions() {
    return this.store.listPermissions();
  }

  public listRoles(organizationId: string) {
    return this.store.listRoles(organizationId);
  }

  public createRole(input: {
    audit: AuditContext;
    description: string;
    name: string;
    organizationId: string;
    permissionIds: string[];
    principal: Principal;
  }) {
    return this.store.createRole({
      actorUserId: input.principal.userId,
      audit: input.audit,
      description: input.description.trim(),
      name: input.name.trim(),
      organizationId: input.organizationId,
      permissionIds: input.permissionIds,
    });
  }

  public updateRole(input: {
    audit: AuditContext;
    description: string;
    name: string;
    organizationId: string;
    permissionIds: string[];
    principal: Principal;
    roleId: string;
  }) {
    return this.store.updateRole({
      actorUserId: input.principal.userId,
      audit: input.audit,
      description: input.description.trim(),
      name: input.name.trim(),
      organizationId: input.organizationId,
      permissionIds: input.permissionIds,
      roleId: input.roleId,
    });
  }

  public deleteRole(input: {
    audit: AuditContext;
    organizationId: string;
    principal: Principal;
    roleId: string;
  }) {
    return this.store.deleteRole({
      actorUserId: input.principal.userId,
      audit: input.audit,
      organizationId: input.organizationId,
      roleId: input.roleId,
    });
  }

  public listMembers(organizationId: string) {
    return this.store.listMembers(organizationId);
  }

  public assignRoles(input: {
    audit: AuditContext;
    organizationId: string;
    principal: Principal;
    roleIds: string[];
    targetUserId: string;
  }) {
    return this.store.assignRoles({
      actorUserId: input.principal.userId,
      audit: input.audit,
      organizationId: input.organizationId,
      roleIds: input.roleIds,
      targetUserId: input.targetUserId,
    });
  }

  public async invite(input: {
    audit: AuditContext;
    email: string;
    organizationId: string;
    principal: Principal;
    roleId: string;
  }) {
    const rawToken = generateOpaqueToken("iv");
    return this.store.createInvitation({
      actorUserId: input.principal.userId,
      audit: input.audit,
      email: input.email.trim().toLowerCase(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1_000),
      organizationId: input.organizationId,
      rawToken,
      roleId: input.roleId,
      tokenHash: hashOpaqueToken(rawToken, this.config.tokenPepper),
    });
  }

  public acceptInvitation(input: { audit: AuditContext; principal: Principal; token: string }) {
    if (!isWellFormedOpaqueToken(input.token, "iv")) throw errors.invalidToken();
    return this.store.acceptInvitation({
      audit: input.audit,
      email: input.principal.email,
      tokenHash: hashOpaqueToken(input.token, this.config.tokenPepper),
      userId: input.principal.userId,
    });
  }

  public removeMember(input: {
    audit: AuditContext;
    organizationId: string;
    principal: Principal;
    targetUserId: string;
  }) {
    return this.store.removeMember({
      actorUserId: input.principal.userId,
      audit: input.audit,
      organizationId: input.organizationId,
      targetUserId: input.targetUserId,
    });
  }

  public listAuditEvents(organizationId: string, beforeId?: string) {
    return this.store.listAuditEvents(organizationId, beforeId);
  }

  public createProject(input: {
    audit: AuditContext;
    name: string;
    organizationId: string;
    principal: Principal;
  }) {
    return this.store.createProject({
      actorUserId: input.principal.userId,
      audit: input.audit,
      name: input.name.trim(),
      organizationId: input.organizationId,
    });
  }

  public listProjects(organizationId: string) {
    return this.store.listProjects(organizationId);
  }

  public updateProject(input: {
    audit: AuditContext;
    name: string;
    organizationId: string;
    principal: Principal;
    projectId: string;
  }) {
    return this.store.updateProject({
      actorUserId: input.principal.userId,
      audit: input.audit,
      name: input.name.trim(),
      organizationId: input.organizationId,
      projectId: input.projectId,
    });
  }

  public deleteProject(input: {
    audit: AuditContext;
    organizationId: string;
    principal: Principal;
    projectId: string;
  }) {
    return this.store.deleteProject({
      actorUserId: input.principal.userId,
      audit: input.audit,
      organizationId: input.organizationId,
      projectId: input.projectId,
    });
  }
}
