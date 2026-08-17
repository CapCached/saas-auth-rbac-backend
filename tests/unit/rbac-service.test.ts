import { describe, expect, it } from "vitest";

import { RbacService, type RbacStorePort } from "../../src/services/rbac-service.js";
import type { AuditInput, Principal } from "../../src/store/types.js";
import { testConfig } from "../helpers/config.js";

const principal: Principal = {
  authVersion: 1,
  email: "person@example.com",
  sessionId: "deeb23c6-822a-48ce-bd30-5bc7bed65e4c",
  userId: "064091c0-0ff3-4ea4-95d3-5080d325c35a",
};

describe("RBAC service", () => {
  it("allows only an explicit positive authorization decision", async () => {
    const service = new RbacService(fakeRbacStore({ authorize: () => Promise.resolve("allowed") }), testConfig());
    await expect(
      service.requirePermission({
        audit: { requestId: "request-1" },
        organizationId: "de7376cc-9a55-49bc-87aa-0dbde31d25be",
        permission: "project:read",
        principal,
      }),
    ).resolves.toBeUndefined();
  });

  it("denies missing permissions and records an audit event", async () => {
    let audit: AuditInput | undefined;
    const service = new RbacService(
      fakeRbacStore({
        authorize: () => Promise.resolve("forbidden"),
        writeAudit: (input) => {
          audit = input;
          return Promise.resolve();
        },
      }),
      testConfig(),
    );
    await expect(
      service.requirePermission({
        audit: { requestId: "request-2" },
        organizationId: "de7376cc-9a55-49bc-87aa-0dbde31d25be",
        permission: "project:delete",
        principal,
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN", statusCode: 403 });
    expect(audit).toMatchObject({
      actorUserId: principal.userId,
      eventType: "authorization.denied",
      outcome: "denied",
    });
  });

  it("does not reveal whether another tenant exists", async () => {
    const service = new RbacService(fakeRbacStore({ authorize: () => Promise.resolve("not_member") }), testConfig());
    await expect(
      service.requirePermission({
        audit: {},
        organizationId: "de7376cc-9a55-49bc-87aa-0dbde31d25be",
        permission: "project:read",
        principal,
      }),
    ).rejects.toMatchObject({ code: "NOT_FOUND", statusCode: 404 });
  });

  it("rejects malformed invitation tokens before the store is called", () => {
    let called = false;
    const service = new RbacService(
      fakeRbacStore({
        acceptInvitation: () => {
          called = true;
          return Promise.reject(new Error("must not be called"));
        },
      }),
      testConfig(),
    );
    expect(() => service.acceptInvitation({ audit: {}, principal, token: "iv_short" })).toThrow();
    expect(called).toBe(false);
  });
});

function fakeRbacStore(overrides: Partial<RbacStorePort> = {}): RbacStorePort {
  const unused = () => Promise.reject(new Error("unused store method"));
  return {
    acceptInvitation: unused,
    archiveOrganization: () => Promise.resolve(false),
    assignRoles: unused,
    authorize: () => Promise.resolve("forbidden"),
    createInvitation: unused,
    createOrganization: unused,
    createProject: unused,
    createRole: unused,
    deleteProject: () => Promise.resolve(false),
    deleteRole: () => Promise.resolve(false),
    listAuditEvents: () => Promise.resolve([]),
    listMembers: () => Promise.resolve([]),
    listOrganizations: () => Promise.resolve([]),
    listPermissions: () => Promise.resolve([]),
    listProjects: () => Promise.resolve([]),
    listRoles: () => Promise.resolve([]),
    removeMember: () => Promise.resolve(false),
    updateOrganization: () => Promise.resolve(null),
    updateProject: () => Promise.resolve(null),
    updateRole: () => Promise.resolve(null),
    writeAudit: () => Promise.resolve(),
    ...overrides,
  };
}
