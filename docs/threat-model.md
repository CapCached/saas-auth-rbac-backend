# Threat model

## Assets

- Password verifiers, refresh/reset/invitation tokens, and JWT signing keys
- Organization membership, roles, and permission assignments
- Tenant-scoped records and audit history
- Availability of login, refresh, and authorization decisions

## Trust boundaries

1. Untrusted clients to the HTTP API
2. API process to PostgreSQL and Redis
3. API/worker process to the configured outbound webhook
4. Operators and secret management to the application runtime

TLS termination, network policy, secret storage, database backups, and webhook receiver security are deployment
responsibilities. The service refuses incomplete production configuration but cannot validate the surrounding cloud
account.

## Primary threats and controls

| Threat | Control |
|---|---|
| Credential stuffing and brute force | Argon2id, generic failures, Redis-backed per-IP/per-identity rate limits |
| User enumeration | Same login error; password-reset always returns `202` |
| JWT confusion or forgery | Ed25519 only; fixed `alg`, `typ`, `kid`, issuer, audience, expiry, and required claims |
| Refresh-token theft/replay | 256-bit opaque tokens, HMAC-only storage, one-use rotation, row locking, family revocation |
| Logout/password/role-change persistence | Session and refresh revocation; `auth_version`; live DB permission checks |
| Horizontal tenant escape | Mandatory organization context, active membership check, org-scoped SQL predicates and composite FKs |
| Vertical privilege escalation | Deny-by-default permissions, centralized guards, protected system owner role, last-owner invariant |
| IDOR via guessed record IDs | All project updates/deletes require both record ID and organization ID |
| Sensitive log disclosure | Structured logging with auth/password/token redaction; generic public errors |
| Audit tampering | Append-only trigger; deletion blocked during the 90-day retention window |
| Worker duplication/failure | Transactional outbox, `SKIP LOCKED`, idempotent event IDs, bounded exponential retry |
| Webhook interception/tampering | Production HTTPS requirement and timestamped HMAC signature |

## Explicit non-goals

- Protection from a fully privileged database or host administrator
- OAuth/OIDC provider behavior, social login, MFA, ABAC, or delegated authorization
- Multi-region consistency and regulated-workload certification
- Browser token storage or frontend session design

## Abuse cases covered by automated tests

- Cross-organization resource-ID guessing
- Non-member organization probing
- A read-only member attempting project creation
- Permission removal taking effect before the access token expires
- Refresh-token replay invalidating the replacement token
- Removal of the only organization owner
- Malformed token rejection before state lookup

Run the PostgreSQL cases with `npm run test:integration` and `TEST_DATABASE_URL`.
