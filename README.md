# QueueFlow — Smart Queue & Appointment Platform

Multi-tenant service-business platform for clinics, salons, repair centres, public offices and customer service counters.

## Product modules
- Business owner signup/login and isolated business workspaces
- Multiple locations/branches per business with location-level ticket tagging
- Service catalogue, duration, pricing and active/inactive status
- Public booking page, appointment requests with check-in, and customer token lookup
- Walk-in digital token generation with atomic daily counters
- Live queue with scheduled, waiting, called, serving, completed, cancelled and no-show states
- Counter/staff assignment, staff workspace access and staff roles (`staff`, `counter`, `manager`)
- Owner dashboard, queue controls and service performance overview (wait/service averages)
- Live updates via authenticated Socket.IO rooms
- Super Admin Control Console (`/super-admin.html`) with platform KPIs, account lifecycle management, business moderation, active session revocation, login/security monitoring, immutable audit logs, and TOTP MFA
- Built-in `node:sqlite` persistence, bcrypt password hashing, SQLite-backed sessions, rate limits, account lockout, and Helmet CSP headers

## Run
Node.js 22.5+, `cp .env.example .env`, set `SESSION_SECRET`, then `npm install && npm start`.
Open http://localhost:4200.

Run the automated test suite with `npm test`.

### Initial Super Admin Setup (Controlled CLI)
Super Admin accounts cannot be created via public registration. Provision the initial Super Admin securely via CLI:
```bash
npm run setup:super-admin -- --name "Platform Owner" --email "superadmin@yourdomain.com" --enable-mfa true
```
(Omit `--password` to enter it interactively without shell history, or set `SUPER_ADMIN_PASSWORD` in your environment. Set `ALLOW_ADDITIONAL_SUPER_ADMINS=true` only if policy allows creating additional Super Admins.)

## Privacy & Security Notice
For security auditing and unauthorized-access prevention, QueueFlow logs authentication events (login/logout timestamps, success/failure, IP addresses, and browser/device summaries) and administrative audit trails. Super Admin actions cannot bypass audit logging.

## Production readiness
Before public deployment configure HTTPS, persistent session store, database backups, SMS/WhatsApp/email notifications, payment provider if required, monitoring, data retention, privacy notice, staff access policy and load testing. No payment gateway is enabled in this release.
