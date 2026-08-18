export type AuditContext = {
  actorUserId?: string;
  ipAddress?: string;
  metadata?: Readonly<Record<string, unknown>>;
  organizationId?: string;
  requestId?: string;
  targetId?: string;
  targetType?: string;
};

export type AuditInput = AuditContext & {
  eventType: string;
  outcome: "denied" | "failure" | "success";
};

export type CredentialUser = {
  authVersion: number;
  email: string;
  id: string;
  passwordHash: string;
  status: "active" | "disabled";
};

export type DeviceInput = {
  deviceId: string;
  deviceName: string;
  ipAddress?: string;
  userAgentHash?: string;
};

export type SessionTokensInput = {
  familyId: string;
  refreshExpiresAt: Date;
  refreshTokenHash: string;
  sessionExpiresAt: Date;
};

export type Principal = {
  authVersion: number;
  email: string;
  sessionId: string;
  userId: string;
};

export type RefreshRotationResult =
  | { kind: "invalid" }
  | { kind: "reuse" }
  | { kind: "rotated"; principal: Principal };

export type AuthorizationResult = "allowed" | "forbidden" | "not_member";

export type OrganizationSummary = {
  id: string;
  name: string;
  roleNames: string[];
};

export type RoleSummary = {
  description: string;
  id: string;
  isOwner: boolean;
  isSystem: boolean;
  name: string;
  permissions: string[];
  version: number;
};

export type PermissionSummary = {
  description: string;
  id: string;
  key: string;
};

export type MemberSummary = {
  email: string;
  joinedAt: string;
  roles: { id: string; name: string }[];
  status: string;
  userId: string;
};

export type SessionSummary = {
  createdAt: string;
  current: boolean;
  deviceId: string;
  deviceName: string;
  expiresAt: string;
  id: string;
  lastSeenAt: string;
  revokedAt: string | null;
};

export type AuditSummary = {
  actorUserId: string | null;
  createdAt: string;
  eventType: string;
  id: string;
  metadata: Record<string, unknown>;
  outcome: string;
  targetId: string | null;
  targetType: string | null;
};

export type ProjectSummary = {
  createdAt: string;
  createdBy: string;
  id: string;
  name: string;
  updatedAt: string;
};
