# Production Operations Guide

- Use Node.js 22.5+; install dependencies from lockfile with `npm ci`.
- Production should use PostgreSQL via `DATABASE_URL`; SQLite is suitable for local or carefully scoped single-instance deployments only.
- Configure `NODE_ENV=production`, strong unique `SESSION_SECRET` (32+ random bytes), and only trusted `TRUST_PROXY` values.
- Set durable storage if SQLite or session-secret persistence is used. Avoid ephemeral serverless filesystems.
- Require HTTPS; review secure cookie and CSP behavior at the edge.
- Provision Super Admin using the controlled CLI and enable TOTP MFA. Remove bootstrap credentials from deployment environment after use.
- Public queue boards must not include customer names, phone numbers, notes or tracking keys.
- Ticket tracking requires both token and private lookup key. The browser sends the key via the `X-Ticket-Lookup-Key` header (never in the URL); do not log it or send it in public queue broadcasts.
- Schedule encrypted database backups; perform regular restore drills and document RPO/RTO.
- Monitor HTTP 5xx, DB readiness/connection saturation, authentication lockouts, queue action latency, socket connectivity and disk space.
- Logs should scrub passwords, tokens, MFA codes, private lookup keys, session IDs and reset secrets.
- Before release, review migration compatibility, HTTPS, backups/restores, alerting, accessibility, tests, security review, load testing and rollback.
