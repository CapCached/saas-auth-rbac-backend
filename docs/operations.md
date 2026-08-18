# Operations runbook

## Deployment contract

- Run at least PostgreSQL 15 and Redis 7.
- Terminate TLS before the service and forward only trusted proxy headers; set `TRUST_PROXY=true` only for a known
  proxy hop.
- Store JWT private keys and peppers in a secret manager, not image layers or environment files in source control.
- Keep the API and worker on a private network path to PostgreSQL/Redis.
- Restrict `/metrics` with its independent bearer token and network policy.
- Configure the webhook receiver to verify `x-auth-timestamp` and `x-auth-signature`, reject stale timestamps, and
  deduplicate `x-auth-event-id`.

## Key rotation

1. Generate a new Ed25519 pair with `npm run keys:generate` in a secure environment.
2. Add the new public key to `JWT_PUBLIC_KEYS_JSON` while retaining the previous public key.
3. Set the new private key and `JWT_ACTIVE_KID`, then deploy.
4. Wait longer than the maximum access-token lifetime plus clock tolerance.
5. Remove the previous public key and deploy again.

Do not rotate `PASSWORD_PEPPER` without forcing password resets. Rotating `TOKEN_PEPPER` invalidates all outstanding
refresh, reset, and invitation tokens.

## Incident actions

- Suspected JWT private-key compromise: rotate keys immediately and increment every user's `auth_version`; revoke all
  sessions and refresh tokens.
- Suspected refresh-token leak: revoke the affected session; reuse detection does this automatically when observed.
- Suspected authorization regression: disable the affected role/endpoint at the edge, preserve audit logs, and roll
  back only after confirming schema compatibility.
- Redis failure: authentication endpoints fail closed by default. Restore Redis; do not disable the control in
  production merely to recover login traffic.

## Backups and recovery

- Use encrypted PostgreSQL backups with periodic restore drills.
- Redis is not authoritative; losing it removes rate-limit/cached state but not identity or RBAC data.
- Apply migrations once per release. The runner uses a PostgreSQL advisory lock and rejects modified applied files.
- Monitor dead-letter outbox rows (`processed_at IS NULL AND attempts >= 10`) and replay only after fixing the receiver.

## Release gate

Before customer traffic: CI green, dependency audit reviewed, image scanned, staging restore tested, TLS/network policies
verified, webhook receiver exercised, alerts connected, and an independent security review completed.
