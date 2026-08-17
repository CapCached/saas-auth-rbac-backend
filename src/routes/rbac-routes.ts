import type { FastifyInstance, preHandlerHookHandler } from "fastify";
import { z } from "zod";

import type { RequestGuards } from "../http/guards.js";
import {
  auditFrom,
  email,
  parse,
  requireOrganization,
  requirePrincipal,
  uuid,
} from "../http/request.js";
import type { RbacService } from "../services/rbac-service.js";
import { errors } from "../domain/errors.js";

const nameSchema = z.object({ name: z.string().trim().min(1).max(120) });
const roleBody = z.object({
  description: z.string().trim().max(500).default(""),
  name: z.string().trim().min(1).max(80),
  permissionIds: z.array(uuid).max(100),
});
const roleParams = z.object({ roleId: uuid });
const memberParams = z.object({ userId: uuid });
const assignRolesBody = z.object({ roleIds: z.array(uuid).max(50) });
const invitationBody = z.object({ email, roleId: uuid });
const invitationAcceptBody = z.object({ token: z.string().min(1).max(200) });
const auditQuery = z.object({ before: z.string().regex(/^\d+$/).optional() });
const projectParams = z.object({ projectId: uuid });

export function registerRbacRoutes(
  app: FastifyInstance,
  dependencies: { guards: RequestGuards; rbac: RbacService },
): void {
  const { guards, rbac } = dependencies;
  const authenticated = [guards.authenticate];
  const scoped = (permission: string): preHandlerHookHandler[] => [
    guards.authenticate,
    guards.organization,
    guards.permission(permission),
  ];

  app.get("/v1/organizations", { preHandler: authenticated }, async (request) => ({
    organizations: await rbac.listOrganizations(requirePrincipal(request).userId),
  }));

  app.post("/v1/organizations", { preHandler: authenticated }, async (request, reply) => {
    const body = parse(nameSchema, request.body);
    const organization = await rbac.createOrganization({
      audit: auditFrom(request),
      name: body.name,
      principal: requirePrincipal(request),
    });
    return reply.code(201).send({ organization });
  });

  app.patch(
    "/v1/organization",
    { preHandler: scoped("org:update") },
    async (request) => {
      const body = parse(nameSchema, request.body);
      const organization = await rbac.updateOrganization({
        audit: auditFrom(request),
        name: body.name,
        organizationId: requireOrganization(request),
        principal: requirePrincipal(request),
      });
      if (!organization) throw errors.notFound();
      return { organization };
    },
  );

  app.delete(
    "/v1/organization",
    { preHandler: scoped("org:delete") },
    async (request, reply) => {
      const archived = await rbac.archiveOrganization({
        audit: auditFrom(request),
        organizationId: requireOrganization(request),
        principal: requirePrincipal(request),
      });
      if (!archived) throw errors.notFound();
      return reply.code(204).send();
    },
  );

  app.get("/v1/permissions", { preHandler: scoped("permission:read") }, async () => ({
    permissions: await rbac.listPermissions(),
  }));

  app.get("/v1/roles", { preHandler: scoped("role:read") }, async (request) => ({
    roles: await rbac.listRoles(requireOrganization(request)),
  }));

  app.post("/v1/roles", { preHandler: scoped("role:create") }, async (request, reply) => {
    const body = parse(roleBody, request.body);
    const role = await rbac.createRole({
      audit: auditFrom(request),
      ...body,
      organizationId: requireOrganization(request),
      principal: requirePrincipal(request),
    });
    return reply.code(201).send({ role });
  });

  app.put("/v1/roles/:roleId", { preHandler: scoped("role:update") }, async (request) => {
    const body = parse(roleBody, request.body);
    const { roleId } = parse(roleParams, request.params);
    const role = await rbac.updateRole({
      audit: auditFrom(request),
      ...body,
      organizationId: requireOrganization(request),
      principal: requirePrincipal(request),
      roleId,
    });
    if (!role) throw errors.notFound();
    return { role };
  });

  app.delete("/v1/roles/:roleId", { preHandler: scoped("role:delete") }, async (request, reply) => {
    const { roleId } = parse(roleParams, request.params);
    const deleted = await rbac.deleteRole({
      audit: auditFrom(request),
      organizationId: requireOrganization(request),
      principal: requirePrincipal(request),
      roleId,
    });
    if (!deleted) throw errors.notFound();
    return reply.code(204).send();
  });

  app.get("/v1/members", { preHandler: scoped("member:read") }, async (request) => ({
    members: await rbac.listMembers(requireOrganization(request)),
  }));

  app.post("/v1/invitations", { preHandler: scoped("member:invite") }, async (request, reply) => {
    const body = parse(invitationBody, request.body);
    const invitation = await rbac.invite({
      audit: auditFrom(request),
      ...body,
      organizationId: requireOrganization(request),
      principal: requirePrincipal(request),
    });
    return reply.code(201).send({ invitation });
  });

  app.post(
    "/v1/invitations/accept",
    { preHandler: authenticated },
    async (request) => {
      const body = parse(invitationAcceptBody, request.body);
      return rbac.acceptInvitation({
        audit: auditFrom(request),
        principal: requirePrincipal(request),
        token: body.token,
      });
    },
  );

  app.put("/v1/members/:userId/roles", { preHandler: scoped("role:assign") }, async (request, reply) => {
    const { userId } = parse(memberParams, request.params);
    const body = parse(assignRolesBody, request.body);
    await rbac.assignRoles({
      audit: auditFrom(request),
      organizationId: requireOrganization(request),
      principal: requirePrincipal(request),
      roleIds: body.roleIds,
      targetUserId: userId,
    });
    return reply.code(204).send();
  });

  app.delete("/v1/members/:userId", { preHandler: scoped("member:remove") }, async (request, reply) => {
    const { userId } = parse(memberParams, request.params);
    const removed = await rbac.removeMember({
      audit: auditFrom(request),
      organizationId: requireOrganization(request),
      principal: requirePrincipal(request),
      targetUserId: userId,
    });
    if (!removed) throw errors.notFound();
    return reply.code(204).send();
  });

  app.get("/v1/audit-events", { preHandler: scoped("audit:read") }, async (request) => {
    const query = parse(auditQuery, request.query);
    return {
      events: await rbac.listAuditEvents(requireOrganization(request), query.before),
    };
  });

  app.get("/v1/projects", { preHandler: scoped("project:read") }, async (request) => ({
    projects: await rbac.listProjects(requireOrganization(request)),
  }));

  app.post("/v1/projects", { preHandler: scoped("project:create") }, async (request, reply) => {
    const body = parse(nameSchema, request.body);
    const project = await rbac.createProject({
      audit: auditFrom(request),
      name: body.name,
      organizationId: requireOrganization(request),
      principal: requirePrincipal(request),
    });
    return reply.code(201).send({ project });
  });

  app.put("/v1/projects/:projectId", { preHandler: scoped("project:update") }, async (request) => {
    const body = parse(nameSchema, request.body);
    const { projectId } = parse(projectParams, request.params);
    const project = await rbac.updateProject({
      audit: auditFrom(request),
      name: body.name,
      organizationId: requireOrganization(request),
      principal: requirePrincipal(request),
      projectId,
    });
    if (!project) throw errors.notFound();
    return { project };
  });

  app.delete(
    "/v1/projects/:projectId",
    { preHandler: scoped("project:delete") },
    async (request, reply) => {
      const { projectId } = parse(projectParams, request.params);
      const deleted = await rbac.deleteProject({
        audit: auditFrom(request),
        organizationId: requireOrganization(request),
        principal: requirePrincipal(request),
        projectId,
      });
      if (!deleted) throw errors.notFound();
      return reply.code(204).send();
    },
  );
}
