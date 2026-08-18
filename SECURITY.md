# Security policy

## Supported versions

Until the first stable release, only the latest commit on `main` receives security fixes.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use this repository's
[private vulnerability reporting form](https://github.com/CapCached/saas-auth-rbac-backend/security/advisories/new).

Include the affected endpoint, preconditions, reproduction steps, impact, and any suggested mitigation.
Do not access data that is not yours, degrade availability, or use automated scanning against a public deployment
without written permission.

Receipt should be acknowledged within three business days. A remediation timeline depends on severity and
reproducibility. Coordinated disclosure is requested until a fix is available.

## Security boundaries

The maintained threat model is in [docs/threat-model.md](docs/threat-model.md). This project is a production-style
reference implementation, not a compliance certification or authorization to process regulated data.
