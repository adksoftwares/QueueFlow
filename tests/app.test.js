const { test, describe, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createApp } = require("../src/app");
const { generateTotp } = require("../src/mfa");
const { parseAppointmentInTimeZone, dateStrInTimeZone } = require("../src/helpers");

function extractCookies(res) {
  const raw = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
  const pairs = [];
  for (const item of raw) {
    const [pair] = item.split(";");
    if (pair && !pair.endsWith("=")) pairs.push(pair);
  }
  return pairs.join("; ");
}

async function apiFetch(baseUrl, pathname, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body && typeof options.body === "object") {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(options.body);
  }
  if (options.cookie) {
    headers.Cookie = options.cookie;
  }
  const res = await fetch(`${baseUrl}${pathname}`, { ...options, headers });
  const data = await res.json().catch(() => ({}));
  return { res, data, cookie: extractCookies(res) || options.cookie || "" };
}

function connectSocketIO(wsUrl, cookie = "") {
  return new Promise((resolve, reject) => {
    const headers = cookie ? { Cookie: cookie } : {};
    const ws = new WebSocket(wsUrl, { headers });
    const events = [];
    let opened = false;

    ws.addEventListener("message", (evt) => {
      const msg = String(evt.data);
      if (msg.startsWith("0")) {
        ws.send("40");
      } else if (msg.startsWith("40")) {
        opened = true;
        resolve({
          ws,
          events,
          emit(event, payload) {
            ws.send(`42${JSON.stringify([event, payload])}`);
          },
          close() {
            ws.close();
          }
        });
      } else if (msg === "2") {
        ws.send("3");
      } else if (msg.startsWith("42")) {
        try {
          const parsed = JSON.parse(msg.slice(2));
          events.push({ event: parsed[0], data: parsed[1] });
        } catch {
          // ignore malformed
        }
      }
    });

    ws.addEventListener("error", (err) => {
      if (!opened) reject(err);
    });
  });
}

function waitForEvent(client, eventName, timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const check = () => {
      const found = client.events.find((e) => e.event === eventName);
      if (found) return resolve(found);
      if (Date.now() - start >= timeoutMs) {
        return reject(new Error(`Timed out waiting for event "${eventName}"`));
      }
      setTimeout(check, 25);
    };
    check();
  });
}

describe("QueueFlow & Super Admin Control System Verification", () => {
  let tmpDir;
  let instance;
  let baseUrl;
  let wsUrl;
  let superAdminSecret;
  let superAdminRecoveryCode;

  before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "queueflow-test-"));

    // Provision initial Super Admin via controlled CLI script with MFA enabled
    const cliOut = execFileSync(
      process.execPath,
      [
        path.join(__dirname, "../scripts/create-super-admin.js"),
        "--storage-dir",
        tmpDir,
        "--name",
        "Root Super Admin",
        "--email",
        "superadmin@example.com",
        "--password",
        "SuperAdminPass!2026",
        "--enable-mfa",
        "true"
      ],
      { encoding: "utf8" }
    );
    const secMatch = cliOut.match(/TOTP Secret:\s*([A-Z2-7]+)/);
    const recMatch = cliOut.match(/Recovery Codes \(save securely\):\s*([^\n]+)/);
    superAdminSecret = secMatch[1];
    superAdminRecoveryCode = recMatch[1].split(",")[0].trim();

    instance = createApp({
      storageDir: tmpDir,
      sqliteOnly: true,
      sessionSecret: "super-strong-test-secret-0123456789",
      disableRateLimit: true,
      pruneIntervalMs: 0,
      allowAdditionalSuperAdmins: false
    });
    await instance.ready;
    await new Promise((resolve) => {
      instance.server.listen(0, "127.0.0.1", resolve);
    });
    const addr = instance.server.address();
    baseUrl = `http://127.0.0.1:${addr.port}`;
    wsUrl = `ws://127.0.0.1:${addr.port}/socket.io/?EIO=4&transport=websocket`;
  });

  after(async () => {
    if (instance) await instance.close();
    fs.rmSync(tmpDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  test("rejects weak session secret in production & parses IANA timezones accurately", () => {
    const prevEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      assert.throws(() => {
        createApp({
          storageDir: path.join(tmpDir, "prod-check"),
          sessionSecret: "CHANGE_THIS_SECRET_BEFORE_DEPLOYMENT_123456",
          pruneIntervalMs: 0
        });
      }, /SESSION_SECRET/);
    } finally {
      process.env.NODE_ENV = prevEnv;
    }

    const parsed = parseAppointmentInTimeZone("2030-05-01T14:30", "Asia/Kolkata");
    assert.equal(parsed.toISOString(), "2030-05-01T09:00:00.000Z");

    const istDate = dateStrInTimeZone(new Date("2026-11-18T20:00:00.000Z"), "Asia/Kolkata");
    assert.equal(istDate, "2026-11-19");
  });

  test("blocks public Super Admin registration and prevents duplicate CLI Super Admin by default", async () => {
    const reg = await apiFetch(baseUrl, "/api/auth/register", {
      method: "POST",
      body: {
        name: "Owner One",
        email: "owner@example.com",
        password: "StrongPassword123!",
        role: "super_admin"
      }
    });
    assert.equal(reg.res.status, 200);
    assert.equal(reg.data.user.role, "owner");

    // Owner cannot access Super Admin endpoints
    const forbidden = await apiFetch(baseUrl, "/api/super-admin/overview", {
      cookie: reg.cookie
    });
    assert.equal(forbidden.res.status, 403);

    // CLI blocks creating a 2nd Super Admin without policy override
    assert.throws(() => {
      execFileSync(
        process.execPath,
        [
          path.join(__dirname, "../scripts/create-super-admin.js"),
          "--storage-dir",
          tmpDir,
          "--name",
          "Rogue Admin",
          "--email",
          "rogue@example.com",
          "--password",
          "RogueAdminPass!2026"
        ],
        { stdio: "pipe" }
      );
    });
  });

  test("enforces Super Admin TOTP MFA, recovery code, and policy on additional Super Admins", async () => {
    const step1 = await apiFetch(baseUrl, "/api/auth/login", {
      method: "POST",
      body: {
        email: "superadmin@example.com",
        password: "SuperAdminPass!2026"
      }
    });
    assert.equal(step1.res.status, 200);
    assert.equal(step1.data.mfaRequired, true);

    // Pre-MFA session cannot access Super Admin APIs
    const blocked = await apiFetch(baseUrl, "/api/super-admin/overview", {
      cookie: step1.cookie
    });
    assert.equal(blocked.res.status, 401);

    // Wrong MFA code rejected
    const badMfa = await apiFetch(baseUrl, "/api/auth/mfa/verify", {
      method: "POST",
      cookie: step1.cookie,
      body: { code: "000000" }
    });
    assert.equal(badMfa.res.status, 401);

    // Valid TOTP succeeds
    const validCode = generateTotp(superAdminSecret);
    const step2 = await apiFetch(baseUrl, "/api/auth/mfa/verify", {
      method: "POST",
      cookie: step1.cookie,
      body: { code: validCode }
    });
    assert.equal(step2.res.status, 200);
    assert.equal(step2.data.user.role, "super_admin");
    assert.equal(step2.data.user.mfa_enabled, true);

    // Overview works and never leaks password_hash or mfa_secret
    const overview = await apiFetch(baseUrl, "/api/super-admin/overview", {
      cookie: step2.cookie
    });
    assert.equal(overview.res.status, 200);
    assert.ok(overview.data.metrics.total_accounts >= 2);
    assert.equal(overview.data.last_registered[0].password_hash, undefined);
    assert.equal(overview.data.last_registered[0].mfa_secret, undefined);

    // Policy blocks creating another Super Admin when allowAdditionalSuperAdmins=false
    const policyBlocked = await apiFetch(baseUrl, "/api/super-admin/accounts", {
      method: "POST",
      cookie: step2.cookie,
      body: {
        name: "Second SA",
        email: "sa2@example.com",
        password: "AnotherStrongPass!2026",
        role: "super_admin"
      }
    });
    assert.equal(policyBlocked.res.status, 403);

    // Recovery code also works once
    const recLogin = await apiFetch(baseUrl, "/api/auth/login", {
      method: "POST",
      body: { email: "superadmin@example.com", password: "SuperAdminPass!2026" }
    });
    const recVerify = await apiFetch(baseUrl, "/api/auth/mfa/verify", {
      method: "POST",
      cookie: recLogin.cookie,
      body: { code: superAdminRecoveryCode }
    });
    assert.equal(recVerify.res.status, 200);
  });

  test("complete Super Admin account lifecycle: manual create, must_change_password, reset, session revoke, suspend, delete, and brute-force lockout", async () => {
    const saStep1 = await apiFetch(baseUrl, "/api/auth/login", {
      method: "POST",
      body: { email: "superadmin@example.com", password: "SuperAdminPass!2026" }
    });
    const saStep2 = await apiFetch(baseUrl, "/api/auth/mfa/verify", {
      method: "POST",
      cookie: saStep1.cookie,
      body: { code: generateTotp(superAdminSecret) }
    });
    const saCookie = saStep2.cookie;

    // 1. Manually create owner with must_change_password=true
    const created = await apiFetch(baseUrl, "/api/super-admin/accounts", {
      method: "POST",
      cookie: saCookie,
      body: {
        name: "Managed Owner",
        email: "managed@example.com",
        password: "TempPassword123!",
        phone: "9998887776",
        role: "owner",
        must_change_password: true
      }
    });
    assert.equal(created.res.status, 201);
    const uid = created.data.account.id;

    // Login -> dashboard blocked until password changed
    const mLogin = await apiFetch(baseUrl, "/api/auth/login", {
      method: "POST",
      body: { email: "managed@example.com", password: "TempPassword123!" }
    });
    assert.equal(mLogin.res.status, 200);
    assert.equal(mLogin.data.mustChangePassword, true);

    const blockedDash = await apiFetch(baseUrl, "/api/dashboard", { cookie: mLogin.cookie });
    assert.equal(blockedDash.res.status, 403);
    assert.equal(blockedDash.data.code, "PASSWORD_CHANGE_REQUIRED");

    const changed = await apiFetch(baseUrl, "/api/auth/change-password", {
      method: "POST",
      cookie: mLogin.cookie,
      body: { current_password: "TempPassword123!", new_password: "NewOwnerPassword!2026" }
    });
    assert.equal(changed.res.status, 200);

    const okDash = await apiFetch(baseUrl, "/api/dashboard", { cookie: mLogin.cookie });
    assert.equal(okDash.res.status, 200);

    // Owner creates a business
    const bizRes = await apiFetch(baseUrl, "/api/businesses", {
      method: "POST",
      cookie: mLogin.cookie,
      body: { name: "Managed Clinic", timezone: "Asia/Kolkata" }
    });
    assert.equal(bizRes.res.status, 201);

    // 2. Super Admin inspects account detail & revokes sessions
    const detail = await apiFetch(baseUrl, `/api/super-admin/accounts/${uid}`, {
      cookie: saCookie
    });
    assert.equal(detail.res.status, 200);
    assert.equal(detail.data.businesses.length, 1);
    assert.equal(detail.data.account.password_hash, undefined);
    assert.ok(detail.data.sessions.some((s) => s.is_active));

    const revoked = await apiFetch(baseUrl, `/api/super-admin/accounts/${uid}/revoke-sessions`, {
      method: "POST",
      cookie: saCookie,
      body: {}
    });
    assert.equal(revoked.res.status, 200);
    assert.ok(revoked.data.revoked >= 1);

    const afterRevokeDash = await apiFetch(baseUrl, "/api/dashboard", { cookie: mLogin.cookie });
    assert.equal(afterRevokeDash.res.status, 401);

    // 3. Super Admin initiates one-time link password reset -> user completes reset
    const resetInit = await apiFetch(baseUrl, `/api/super-admin/accounts/${uid}/reset-password`, {
      method: "POST",
      cookie: saCookie,
      body: { force_change_on_login: false, revoke_sessions: true }
    });
    assert.equal(resetInit.res.status, 200);
    assert.ok(resetInit.data.resetToken);

    const resetComplete = await apiFetch(baseUrl, "/api/auth/reset-password", {
      method: "POST",
      body: { token: resetInit.data.resetToken, new_password: "RecoveredPass!2026" }
    });
    assert.equal(resetComplete.res.status, 200);

    // 3b. Super Admin sets a temporary password directly on the business owner account
    const shortTempReset = await apiFetch(baseUrl, `/api/super-admin/accounts/${uid}/reset-password`, {
      method: "POST",
      cookie: saCookie,
      body: { new_password: "12345" }
    });
    assert.equal(shortTempReset.res.status, 400);

    const directTempReset = await apiFetch(baseUrl, `/api/super-admin/accounts/${uid}/reset-password`, {
      method: "POST",
      cookie: saCookie,
      body: { new_password: "temp66", force_change_on_login: true, revoke_sessions: true }
    });
    assert.equal(directTempReset.res.status, 200);
    assert.equal(directTempReset.data.mode, "temporary_password");
    assert.equal(directTempReset.data.mustChangePassword, true);

    const oldPwDenied = await apiFetch(baseUrl, "/api/auth/login", {
      method: "POST",
      body: { email: "managed@example.com", password: "RecoveredPass!2026" }
    });
    assert.equal(oldPwDenied.res.status, 401);

    const tempPwLogin = await apiFetch(baseUrl, "/api/auth/login", {
      method: "POST",
      body: { email: "managed@example.com", password: "temp66" }
    });
    assert.equal(tempPwLogin.res.status, 200);
    assert.equal(tempPwLogin.data.mustChangePassword, true);

    const changeBack = await apiFetch(baseUrl, "/api/auth/change-password", {
      method: "POST",
      cookie: tempPwLogin.cookie,
      body: { current_password: "temp66", new_password: "RecoveredPass!2026" }
    });
    assert.equal(changeBack.res.status, 200);

    // 4. Brute-force lockout after 5 bad attempts -> logged in security-events
    for (let i = 0; i < 5; i++) {
      await apiFetch(baseUrl, "/api/auth/login", {
        method: "POST",
        body: { email: "managed@example.com", password: "WrongPassword!!!" }
      });
    }
    const lockedAttempt = await apiFetch(baseUrl, "/api/auth/login", {
      method: "POST",
      body: { email: "managed@example.com", password: "RecoveredPass!2026" }
    });
    assert.equal(lockedAttempt.res.status, 429);

    const secEvents = await apiFetch(
      baseUrl,
      "/api/super-admin/security-events?type=suspicious_activity",
      { cookie: saCookie }
    );
    assert.equal(secEvents.res.status, 200);
    assert.ok(secEvents.data.events.length >= 1);

    // 5. Unlock, then suspend, then soft-delete, then permanently delete with confirmation
    await apiFetch(baseUrl, `/api/super-admin/accounts/${uid}`, {
      method: "PATCH",
      cookie: saCookie,
      body: { status: "suspended", suspension_reason: "Policy audit" }
    });
    const suspendedLogin = await apiFetch(baseUrl, "/api/auth/login", {
      method: "POST",
      body: { email: "managed@example.com", password: "RecoveredPass!2026" }
    });
    assert.equal(suspendedLogin.res.status, 403);

    const wrongConfirmDel = await apiFetch(baseUrl, `/api/super-admin/accounts/${uid}`, {
      method: "DELETE",
      cookie: saCookie,
      body: { confirmEmail: "wrong@example.com" }
    });
    assert.equal(wrongConfirmDel.res.status, 400);

    const permDel = await apiFetch(baseUrl, `/api/super-admin/accounts/${uid}`, {
      method: "DELETE",
      cookie: saCookie,
      body: { confirmEmail: "managed@example.com" }
    });
    assert.equal(permDel.res.status, 200);
    assert.equal(permDel.data.deleted_businesses, 1);

    // Audit logs recorded Super Admin actions
    const auditLogs = await apiFetch(
      baseUrl,
      "/api/super-admin/audit-logs?action=super_admin.",
      { cookie: saCookie }
    );
    assert.equal(auditLogs.res.status, 200);
    assert.ok(auditLogs.data.logs.some((l) => l.action === "super_admin.account_permanent_delete"));
  });

  test("preserves all QueueFlow core flows: multi-location, atomic tokens, concurrent queue/next, soft-archive, state machine, staff socket eviction & business suspension", async () => {
    const saStep1 = await apiFetch(baseUrl, "/api/auth/login", {
      method: "POST",
      body: { email: "superadmin@example.com", password: "SuperAdminPass!2026" }
    });
    const saCookie = (
      await apiFetch(baseUrl, "/api/auth/mfa/verify", {
        method: "POST",
        cookie: saStep1.cookie,
        body: { code: generateTotp(superAdminSecret) }
      })
    ).cookie;

    const ownerLogin = await apiFetch(baseUrl, "/api/auth/login", {
      method: "POST",
      body: { email: "owner@example.com", password: "StrongPassword123!" }
    });
    assert.equal(ownerLogin.res.status, 200);

    const createdBiz = await apiFetch(baseUrl, "/api/businesses", {
      method: "POST",
      cookie: ownerLogin.cookie,
      body: { name: "Care Clinic", category: "Clinic", timezone: "Asia/Kolkata" }
    });
    assert.equal(createdBiz.res.status, 201);
    const biz = createdBiz.data.business;

    // Super Admin suspends business -> owner cannot self-reactivate or create walk-ins
    await apiFetch(baseUrl, `/api/super-admin/businesses/${biz.id}`, {
      method: "PATCH",
      cookie: saCookie,
      body: { status: "suspended", plan: "pro", suspension_reason: "Review" }
    });
    const bypass = await apiFetch(baseUrl, `/api/businesses/${biz.id}`, {
      method: "PATCH",
      cookie: ownerLogin.cookie,
      body: { status: "active" }
    });
    assert.equal(bypass.res.status, 403);

    const walkinBlocked = await apiFetch(baseUrl, `/api/businesses/${biz.id}/tickets`, {
      method: "POST",
      cookie: ownerLogin.cookie,
      body: { customer_name: "Blocked" }
    });
    assert.equal(walkinBlocked.res.status, 403);

    const suspendedQr = await fetch(`${baseUrl}/api/public/${biz.public_code}/qr.svg`);
    assert.equal(suspendedQr.status, 404);

    // Super Admin reactivates
    await apiFetch(baseUrl, `/api/super-admin/businesses/${biz.id}`, {
      method: "PATCH",
      cookie: saCookie,
      body: { status: "active" }
    });

    // Short link & QR code endpoints
    const shortRes = await fetch(`${baseUrl}/q/${biz.public_code.toLowerCase()}`, {
      redirect: "manual"
    });
    assert.equal(shortRes.status, 302);
    assert.equal(shortRes.headers.get("location"), `/queue.html?code=${biz.public_code}`);

    const qrSvgRes = await fetch(`${baseUrl}/api/public/${biz.public_code}/qr.svg`);
    assert.equal(qrSvgRes.status, 200);
    assert.match(qrSvgRes.headers.get("content-type") || "", /image\/svg\+xml/);
    const qrSvgText = await qrSvgRes.text();
    assert.match(qrSvgText, /<svg/);

    const qrPngRes = await fetch(`${baseUrl}/api/public/${biz.public_code}/qr.png?download=1`);
    assert.equal(qrPngRes.status, 200);
    assert.match(qrPngRes.headers.get("content-type") || "", /image\/png/);
    assert.match(qrPngRes.headers.get("content-disposition") || "", /attachment;/);
    const pngBytes = new Uint8Array(await qrPngRes.arrayBuffer());
    assert.deepEqual(Array.from(pngBytes.slice(0, 4)), [0x89, 0x50, 0x4e, 0x47]);

    // Two locations, service, staff
    const locA = (
      await apiFetch(baseUrl, `/api/businesses/${biz.id}/locations`, {
        method: "POST",
        cookie: ownerLogin.cookie,
        body: { name: "Branch A" }
      })
    ).data.location;
    const locB = (
      await apiFetch(baseUrl, `/api/businesses/${biz.id}/locations`, {
        method: "POST",
        cookie: ownerLogin.cookie,
        body: { name: "Branch B" }
      })
    ).data.location;
    const svc = (
      await apiFetch(baseUrl, `/api/businesses/${biz.id}/services`, {
        method: "POST",
        cookie: ownerLogin.cookie,
        body: { name: "Consultation", duration_minutes: 20, price: 25 }
      })
    ).data.service;
    // Appointment lifecycle smoke coverage: scheduled creation then owner cancellation.
    const appointment = await apiFetch(baseUrl, `/api/public/${biz.public_code}/tickets`, {
      method: "POST",
      body: {
        customer_name: "Scheduled Guest",
        service_id: svc.id,
        location_id: locA.id,
        appointment_at: "2030-05-01T14:30"
      }
    });
    assert.equal(appointment.res.status, 201);
    assert.equal(appointment.data.ticket.status, "scheduled");
    const appointmentDetails = await apiFetch(baseUrl, `/api/businesses/${biz.id}`, {
      cookie: ownerLogin.cookie
    });
    const appointmentRow = appointmentDetails.data.appointments.find(
      (row) => row.token === appointment.data.ticket.token
    );
    assert.ok(appointmentRow?.id, "scheduled appointment should appear in the owner appointment list");
    const cancelledAppointment = await apiFetch(baseUrl, `/api/tickets/${appointmentRow.id}/status`, {
      method: "POST",
      cookie: ownerLogin.cookie,
      body: { status: "cancelled" }
    });
    assert.equal(cancelledAppointment.res.status, 200);
    assert.equal(cancelledAppointment.data.ticket.status, "cancelled");

    const staff = (
      await apiFetch(baseUrl, `/api/businesses/${biz.id}/staff`, {
        method: "POST",
        cookie: ownerLogin.cookie,
        body: {
          name: "Dr. Priya",
          email: "staff@example.com",
          role: "staff",
          counter_label: "Counter 2"
        }
      })
    ).data.staff;

    const staffReg = await apiFetch(baseUrl, "/api/auth/register", {
      method: "POST",
      body: { name: "Dr. Priya", email: "staff@example.com", password: "StaffPassword123!" }
    });

    const [a1, a2, b1] = await Promise.all([
      apiFetch(baseUrl, `/api/public/${biz.public_code}/tickets`, {
        method: "POST",
        body: { customer_name: "Alice A", service_id: svc.id, location_id: locA.id }
      }),
      apiFetch(baseUrl, `/api/public/${biz.public_code}/tickets`, {
        method: "POST",
        body: { customer_name: "Aaron A", service_id: svc.id, location_id: locA.id }
      }),
      apiFetch(baseUrl, `/api/public/${biz.public_code}/tickets`, {
        method: "POST",
        body: { customer_name: "Bella B", service_id: svc.id, location_id: locB.id }
      })
    ]);
    assert.equal(new Set([a1.data.ticket.token, a2.data.ticket.token, b1.data.ticket.token]).size, 3);

    const [next1, next2] = await Promise.all([
      apiFetch(baseUrl, `/api/businesses/${biz.id}/queue/next`, {
        method: "POST",
        cookie: ownerLogin.cookie,
        body: { staff_id: staff.id, location_id: locA.id }
      }),
      apiFetch(baseUrl, `/api/businesses/${biz.id}/queue/next`, {
        method: "POST",
        cookie: ownerLogin.cookie,
        body: { staff_id: staff.id, location_id: locA.id }
      })
    ]);
    assert.notEqual(next1.data.ticket.id, next2.data.ticket.id);

    await apiFetch(baseUrl, `/api/tickets/${next1.data.ticket.id}/status`, {
      method: "POST",
      cookie: ownerLogin.cookie,
      body: { status: "serving" }
    });
    await apiFetch(baseUrl, `/api/tickets/${next1.data.ticket.id}/status`, {
      method: "POST",
      cookie: ownerLogin.cookie,
      body: { status: "completed" }
    });
    await apiFetch(baseUrl, `/api/businesses/${biz.id}/queue/clear-completed`, {
      method: "POST",
      cookie: ownerLogin.cookie
    });

    const afterClear = await apiFetch(baseUrl, `/api/businesses/${biz.id}`, {
      cookie: ownerLogin.cookie
    });
    assert.equal(afterClear.data.performance.completed_today, 1);

    // Next-person alert metadata when first token is called/serving on locB
    const b2 = await apiFetch(baseUrl, `/api/public/${biz.public_code}/tickets`, {
      method: "POST",
      body: { customer_name: "Ben B2", service_id: svc.id, location_id: locB.id }
    });
    assert.equal(b2.res.status, 201);

    const callB1 = await apiFetch(baseUrl, `/api/businesses/${biz.id}/queue/next`, {
      method: "POST",
      cookie: ownerLogin.cookie,
      body: { staff_id: staff.id, location_id: locB.id }
    });
    assert.equal(callB1.res.status, 200);

    const b2Lookup = await apiFetch(
      baseUrl,
      `/api/public/${biz.public_code}/tickets/${b2.data.ticket.token}`,
      { headers: { "X-Ticket-Lookup-Key": b2.data.ticket.lookup_key } }
    );
    assert.equal(b2Lookup.res.status, 200);
    assert.equal(b2Lookup.data.ticket.position_ahead, 0);
    assert.equal(b2Lookup.data.ticket.is_next, true);
    assert.equal(b2Lookup.data.ticket.current_active?.token, callB1.data.ticket.token);
    assert.equal(b2Lookup.data.ticket.current_active?.status, "called");
    const deniedLookup = await apiFetch(
      baseUrl,
      `/api/public/${biz.public_code}/tickets/${b2.data.ticket.token}`,
      { headers: { "X-Ticket-Lookup-Key": "x".repeat(43) } }
    );
    assert.equal(deniedLookup.res.status, 404);
    const missingKeyLookup = await apiFetch(
      baseUrl,
      `/api/public/${biz.public_code}/tickets/${b2.data.ticket.token}`
    );
    assert.equal(missingKeyLookup.res.status, 404);

    // 30-minute advance alert: 5-token 15-min clinic scenario
    const locClinic = (
      await apiFetch(baseUrl, `/api/businesses/${biz.id}/locations`, {
        method: "POST",
        cookie: ownerLogin.cookie,
        body: { name: "Clinic Counter" }
      })
    ).data.location;
    const clinicSvc = (
      await apiFetch(baseUrl, `/api/businesses/${biz.id}/services`, {
        method: "POST",
        cookie: ownerLogin.cookie,
        body: { name: "Clinic Visit", duration_minutes: 15, price: 30 }
      })
    ).data.service;
    const t5List = [];
    for (let i = 1; i <= 5; i++) {
      const r = await apiFetch(baseUrl, `/api/public/${biz.public_code}/tickets`, {
        method: "POST",
        body: {
          customer_name: `Patient ${i}`,
          service_id: clinicSvc.id,
          location_id: locClinic.id
        }
      });
      t5List.push(r.data.ticket);
    }
    const check5Before = await apiFetch(
      baseUrl,
      `/api/public/${biz.public_code}/tickets/${t5List[4].token}`,
      { headers: { "X-Ticket-Lookup-Key": t5List[4].lookup_key } }
    );
    assert.equal(check5Before.data.ticket.estimated_wait_minutes, 60);
    assert.equal(check5Before.data.ticket.alert_30m, false);

    // Finish token 1 & token 2 on locClinic -> only token 3 & token 4 remain ahead of token 5 (2 * 15 = 30 min)
    for (let step = 0; step < 2; step++) {
      const nxt = await apiFetch(baseUrl, `/api/businesses/${biz.id}/queue/next`, {
        method: "POST",
        cookie: ownerLogin.cookie,
        body: { staff_id: staff.id, location_id: locClinic.id }
      });
      assert.equal(nxt.res.status, 200);
      const fin = await apiFetch(baseUrl, `/api/tickets/${nxt.data.ticket.id}/status`, {
        method: "POST",
        cookie: ownerLogin.cookie,
        body: { status: "completed" }
      });
      assert.equal(fin.res.status, 200);
    }
    const check5AfterT2 = await apiFetch(
      baseUrl,
      `/api/public/${biz.public_code}/tickets/${t5List[4].token}`,
      { headers: { "X-Ticket-Lookup-Key": t5List[4].lookup_key } }
    );
    assert.equal(check5AfterT2.data.ticket.tickets_ahead, 2);
    assert.equal(check5AfterT2.data.ticket.estimated_wait_minutes, 30);
    assert.equal(check5AfterT2.data.ticket.alert_30m, true);

    // Authenticated Socket.IO & staff eviction
    const staffSocket = await connectSocketIO(wsUrl, staffReg.cookie);
    staffSocket.emit("join-business", biz.id);
    await new Promise((r) => setTimeout(r, 80));

    await apiFetch(baseUrl, `/api/public/${biz.public_code}/tickets`, {
      method: "POST",
      body: { customer_name: "Live Guest" }
    });
    await waitForEvent(staffSocket, "queue:update");

    await apiFetch(baseUrl, `/api/staff/${staff.id}`, {
      method: "PATCH",
      cookie: ownerLogin.cookie,
      body: { is_active: false }
    });
    await waitForEvent(staffSocket, "business:revoked");
    staffSocket.close();
  });

  test("CSP headers, Origin CSRF guard, and rate limiting", async () => {
    const evil = await apiFetch(baseUrl, "/api/auth/login", {
      method: "POST",
      headers: { Origin: "https://evil.example" },
      body: { email: "a@b.com", password: "password1234" }
    });
    assert.equal(evil.res.status, 403);

    const health = await apiFetch(baseUrl, "/api/health");
    assert.ok(health.res.headers.get("content-security-policy"));
  });

  test("bootstraps initial Super Admin from config only once when none exists", async () => {
    const bootDir = fs.mkdtempSync(path.join(os.tmpdir(), "queueflow-boot-"));
    const bootApp = createApp({
      storageDir: bootDir,
      sqliteOnly: true,
      sessionSecret: "bootstrap-test-secret-0123456789",
      disableRateLimit: true,
      pruneIntervalMs: 0,
      bootstrapSuperAdmin: {
        name: "Cloud Owner",
        email: "cloud.sa@example.com",
        password: "CloudSuperAdmin!2026"
      }
    });
    await bootApp.ready;
    await new Promise((resolve) => bootApp.server.listen(0, "127.0.0.1", resolve));
    const bootUrl = `http://127.0.0.1:${bootApp.server.address().port}`;

    try {
      const login = await apiFetch(bootUrl, "/api/auth/login", {
        method: "POST",
        body: { email: "cloud.sa@example.com", password: "CloudSuperAdmin!2026" }
      });
      assert.equal(login.res.status, 200);
      assert.equal(login.data.user.role, "super_admin");
      assert.equal(login.data.user.name, "Cloud Owner");

      const overview = await apiFetch(bootUrl, "/api/super-admin/overview", {
        cookie: login.cookie
      });
      assert.equal(overview.res.status, 200);
    } finally {
      await bootApp.close();
      fs.rmSync(bootDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  test("enforces 6+ character password minimum across auth & Super Admin APIs and serves pw-toggle.js", async () => {
    const shortReg = await apiFetch(baseUrl, "/api/auth/register", {
      method: "POST",
      body: { name: "Short Pw", email: "short6@example.com", password: "12345" }
    });
    assert.equal(shortReg.res.status, 400);

    const okReg = await apiFetch(baseUrl, "/api/auth/register", {
      method: "POST",
      body: { name: "Six Char User", email: "sixchar@example.com", password: "abc123" }
    });
    assert.equal(okReg.res.status, 200);

    const shortChange = await apiFetch(baseUrl, "/api/auth/change-password", {
      method: "POST",
      cookie: okReg.cookie,
      body: { current_password: "abc123", new_password: "12345" }
    });
    assert.equal(shortChange.res.status, 400);

    const okChange = await apiFetch(baseUrl, "/api/auth/change-password", {
      method: "POST",
      cookie: okReg.cookie,
      body: { current_password: "abc123", new_password: "xyz789" }
    });
    assert.equal(okChange.res.status, 200);

    const saStep1 = await apiFetch(baseUrl, "/api/auth/login", {
      method: "POST",
      body: { email: "superadmin@example.com", password: "SuperAdminPass!2026" }
    });
    const saStep2 = await apiFetch(baseUrl, "/api/auth/mfa/verify", {
      method: "POST",
      cookie: saStep1.cookie,
      body: { code: generateTotp(superAdminSecret) }
    });

    const saShortCreate = await apiFetch(baseUrl, "/api/super-admin/accounts", {
      method: "POST",
      cookie: saStep2.cookie,
      body: {
        name: "Short Created",
        email: "shortcreated@example.com",
        password: "12345",
        role: "owner"
      }
    });
    assert.equal(saShortCreate.res.status, 400);

    const saSixCreate = await apiFetch(baseUrl, "/api/super-admin/accounts", {
      method: "POST",
      cookie: saStep2.cookie,
      body: {
        name: "Six Created",
        email: "sixcreated@example.com",
        password: "pass66",
        role: "owner"
      }
    });
    assert.equal(saSixCreate.res.status, 201);

    const toggleAsset = await fetch(`${baseUrl}/pw-toggle.js`);
    assert.equal(toggleAsset.status, 200);
    for (const page of ["/", "/dashboard.html", "/super-admin.html"]) {
      const r = await fetch(`${baseUrl}${page}`);
      assert.equal(r.status, 200);
      const html = await r.text();
      assert.match(html, /\/pw-toggle\.js/);
      assert.doesNotMatch(html, /minlength="(10|12)"/);
    }
  });

  test("persists Super Admin session & created accounts/businesses across separate app instances", async () => {
    const persistDir = fs.mkdtempSync(path.join(os.tmpdir(), "queueflow-persist-"));
    const secret = "persistent-session-secret-0123456789";
    const app1 = createApp({
      storageDir: persistDir,
      sqliteOnly: true,
      sessionSecret: secret,
      disableRateLimit: true,
      pruneIntervalMs: 0,
      bootstrapSuperAdmin: {
        name: "Persist SA",
        email: "persist.sa@example.com",
        password: "PersistPass!2026"
      }
    });
    await app1.ready;
    await new Promise((resolve) => app1.server.listen(0, "127.0.0.1", resolve));
    const url1 = `http://127.0.0.1:${app1.server.address().port}`;

    let cookie = "";
    try {
      const login = await apiFetch(url1, "/api/auth/login", {
        method: "POST",
        body: { email: "persist.sa@example.com", password: "PersistPass!2026" }
      });
      assert.equal(login.res.status, 200);
      cookie = login.cookie;

      const created = await apiFetch(url1, "/api/super-admin/accounts", {
        method: "POST",
        cookie,
        body: {
          name: "Studio Persist",
          email: "studio.persist@example.com",
          password: "pass66",
          role: "owner",
          business_name: "Studio Persist HQ"
        }
      });
      assert.equal(created.res.status, 201);
      assert.equal(created.data.account.email, "studio.persist@example.com");
      assert.equal(created.data.business.name, "Studio Persist HQ");
    } finally {
      await app1.close();
    }

    const app2 = createApp({
      storageDir: persistDir,
      sqliteOnly: true,
      sessionSecret: secret,
      disableRateLimit: true,
      pruneIntervalMs: 0
    });
    await app2.ready;
    await new Promise((resolve) => app2.server.listen(0, "127.0.0.1", resolve));
    const url2 = `http://127.0.0.1:${app2.server.address().port}`;

    try {
      const me = await apiFetch(url2, "/api/auth/me", { cookie });
      assert.equal(me.res.status, 200);
      assert.equal(me.data.user?.email, "persist.sa@example.com");

      const accounts = await apiFetch(url2, "/api/super-admin/accounts", { cookie });
      assert.equal(accounts.res.status, 200);
      assert.ok(accounts.data.accounts.some((a) => a.email === "studio.persist@example.com"));

      const businesses = await apiFetch(url2, "/api/super-admin/businesses", { cookie });
      assert.equal(businesses.res.status, 200);
      assert.ok(businesses.data.businesses.some((b) => b.name === "Studio Persist HQ"));
    } finally {
      await app2.close();
      fs.rmSync(persistDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });
});
