# Production-Style SaaS Auth & RBAC Backend

## Problem Statement

Authentication and authorization systems in early-stage SaaS products
are frequently over-engineered or under-specified.
This leads to:
- permission bugs
- security gaps
- brittle role logic
- expensive rewrites later

This project demonstrates how I design a clean, auditable auth and RBAC
system for a cost- and team-constrained SaaS.

---

## Threat Model (Explicit)

This system assumes the following attacker classes:

- External attacker attempting token replay, brute force, or API abuse
- Authenticated user attempting privilege escalation
- Authenticated user attempting cross-organization data access
- Compromised access token or refresh token
- Internal logic bugs causing incorrect permission enforcement

The design prioritizes:
- strict organization boundary enforcement
- explicit permission evaluation
- auditable authorization decisions

Advanced threats such as insider database access or nation-state attackers
are out of scope for this reference system.

---

## Core Requirements

- Secure user authentication
- Explicit, reviewable permission rules
- Clear organization and user boundaries
- Minimal operational overhead
- Predictable failure modes

---

## System Overview

- Single backend service exposing REST APIs
- JWT-based authentication with refresh tokens
- Role-Based Access Control scoped to organizations
- PostgreSQL as the source of truth
- Redis for selective caching and rate limiting
- Async workers for non-critical side effects

The system is intentionally built as a monolith.

---

## Key Architecture Decisions

- Monolith over microservices  
  Reduces operational and cognitive overhead at early scale.

- JWT with refresh tokens  
  Access tokens are short-lived.  
  Refresh tokens are stored server-side, rotated on use,
  and invalidated on logout or role change.

- Explicit RBAC tables instead of implicit logic  
  Permissions remain auditable and debuggable as the system grows.

- PostgreSQL as the primary store  
  Strong consistency and relational modeling are critical for auth.

- Redis used only for hot paths  
  Avoids cache-driven complexity where it is not justified.

---

## Request Authorization Flow

Every protected request follows this sequence:

1. Validate access token (signature, expiry)
2. Resolve user identity from token
3. Load organization context from request
4. Verify user belongs to the organization
5. Resolve user roles within the organization
6. Resolve permissions granted by those roles
7. Enforce permission at API boundary

Authorization checks are centralized and enforced
before any domain logic executes.

Resource identifiers are validated to belong to the resolved organization before permission enforcement.  
Invitations are represented as pending organization memberships and resolved upon account creation.

---

## Credential Handling

- Passwords are hashed using a memory-hard algorithm (e.g., bcrypt or argon2).
- Plaintext passwords are never logged or stored.
- Password reset is handled via time-bound, single-use tokens.
- Brute-force protection is enforced at the application layer
  and complemented by rate limiting.

---

## Authentication and Authorization Error Model

- 401 Unauthorized:  
  Returned when authentication fails (missing, invalid, or expired token).

- 403 Forbidden:  
  Returned when authentication succeeds but required permission is missing.

Error responses are generic.  
Detailed failure reasons are logged internally but not exposed to clients.

---

## Token and Session Management

### Token Invalidation Strategy

- Access tokens expire quickly
- Refresh tokens are rotated on every use
- Compromised or stale refresh tokens are rejected
- Role changes invalidate existing refresh tokens

### Refresh Token Lifecycle and Edge Cases

- Refresh tokens are single-use.
- Every successful refresh rotates the token.
- Reuse of an already-consumed refresh token triggers
  revocation of the entire token family.

Token binding:
- Refresh tokens are bound to (user_id, device_id).
- Organization context is resolved at request time.

This system favors strict refresh-token reuse detection over retry tolerance. Clients are expected to serialize refresh requests.

### Device and Session Lifecycle

Devices can be revoked explicitly by the user.  
Inactive devices expire automatically after a defined period.

Revocation invalidates associated refresh tokens.

Concurrency handling:
- Concurrent refresh attempts result in one success.
- Subsequent attempts are treated as reuse and revoked.

Clock skew:
- Small clock skew (±30s) is tolerated for access token expiry.
- Refresh token expiry is enforced strictly server-side.

---

## RBAC Model

### RBAC Data Model (Simplified)

Core entities:

- users(id, email, status)
- organizations(id, name)
- roles(id, org_id, name)
- permissions(id, name)
- role_permissions(role_id, permission_id)
- user_roles(user_id, role_id)
- refresh_tokens(id, hashed_token, family_id, user_id, device_id, revoked_at, expires_at)
- org_memberships(user_id, org_id, status)

All authorization decisions are derived from these tables.  
No implicit permissions exist in application code.

### RBAC Change Discipline

- New permissions are additive by default.
- Permissions are never removed without a migration window.
- Deprecated permissions remain enforced until all roles are updated.
- Role changes are treated as high-risk and audited.
- Organization deletion revokes all active tokens and invalidates RBAC state before archival.

This avoids silent authorization regressions in live systems.

### RBAC Change Consistency

RBAC changes follow a strict ordering:

1. Persist role and permission changes in the database
2. Invalidate relevant cache entries
3. Revoke active refresh tokens for affected users

If cache invalidation or token revocation fails after the database commit,
the system tolerates short-lived inconsistency.
Retries are performed asynchronously until completion.

Authorization decisions always fall back to the database
if cached data is missing or invalidated.

### Permission Caching Strategy

Cached data includes:
- user → role mappings per organization
- role → permission sets

Cache entries are invalidated on role or permission changes.  
A small staleness window is acceptable but bounded by refresh token rotation.

---

## Organization Isolation

### Organization Isolation Guarantees

- Every domain record is scoped to an organization
- org_id is required at query boundaries
- Authorization checks ensure user-org membership before data access
- No cross-organization queries are permitted

Isolation is enforced at the application layer.  
Row-level security is intentionally not used to keep behavior explicit
and debuggable at this stage.

### Organization Isolation Guardrails

- org_id is injected into request context by middleware.
- All data access requires org_id explicitly.
- Repository/query helpers enforce org scoping by default.

Row-Level Security is intentionally deferred.  
It would be considered if isolation bugs or audit requirements increase.

---

## Background Worker Semantics

- Handlers are idempotent by design
- Retries use bounded backoff
- Repeated failures are logged and surfaced for operator visibility

Silent failure is treated as a defect.

---

## Audit Logging

The system records audit events for:
- authentication attempts
- permission denials
- role changes
- token revocation

Audit logs are:
- append-only
- retained for a fixed period (e.g., 90 days)
- accessible only to privileged operators

Logs are never modified or deleted within the retention window.

Audit logs are append-only and designed for later export.

---

## Rate Limiting Policy

- Authentication endpoints: per IP + per user
- Business APIs: per user + per organization
- Sensitive endpoints (login, refresh): stricter limits

Thresholds are conservative by default and configurable.

---

## Observability (Baseline)

From day one, the system exposes:
- authentication success/failure counts
- permission denial counts
- token refresh rates

These metrics help detect abuse, misconfiguration,
and authorization regressions early.

Authorization decisions log:
- user_id
- org_id
- permission
- decision outcome

Token revocations and refresh failures are traceable.

---

## Failure Modes and Risk Areas

- Token leakage or misuse
- Cache inconsistency during role updates
- Incorrect permission checks at boundaries
- Background job lag affecting non-critical flows

Mitigations are documented where applicable.

---

## Break-Glass and Key Compromise Procedures

- Global refresh-token revocation is supported.
- JWT signing keys can be rotated with overlapping validity.
- Key compromise triggers forced token invalidation.

These procedures are operator-only and auditable.

---

## Tradeoffs and Limitations

- Single service becomes a scaling bottleneck beyond moderate traffic
- RBAC rules require discipline to avoid role explosion
- No advanced policy language (e.g., ABAC)
- No built-in multi-region support

These tradeoffs are acceptable at this stage.

---

## What I Deliberately Did Not Build

- OAuth provider integrations
- Fine-grained policy engines
- Multi-tenant database isolation
- Frontend authentication flows

Each exclusion is intentional to keep the system focused and maintainable.

---

## Scaling Triggers

This design is revisited when:
- auth-related p95 latency consistently exceeds low hundreds of milliseconds, or
- sustained request volume grows beyond what a single service can handle reliably

Until then, simplicity and debuggability are preferred.

---

## API Versioning

Authentication and authorization APIs are versioned at the route level
(e.g., /v1/...), with no breaking changes within a version.

---

## Example Protected Endpoint

Endpoint:  
POST /api/projects

Required permission:  
project:create

Flow:
- Authenticate request
- Resolve org context
- Check project:create permission
- Proceed or return 403

---

## Test Strategy

- Unit tests for permission evaluation logic
- Integration tests enforcing organization boundaries
- Regression tests covering role changes and token invalidation

Auth logic is treated as high-risk and tested accordingly.

---

## Code Structure

- auth/        authentication and token handling
- rbac/        roles, permissions, enforcement
- middleware/  auth, org context, rate limiting
- workers/     async side effects

---

## Running Locally

- Docker-based setup `docker compose up`
- Environment variables documented in `.env.example`
- Single command to start all services

Example flow:  
create org → create user → assign role → call protected endpoint

This system is not designed for regulated workloads.  
Audit logging and access controls provide a foundation for future compliance work.
