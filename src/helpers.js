const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { v4: uuid } = require("uuid");

const PLACEHOLDER_SECRETS = new Set([
  "CHANGE_THIS_SECRET_BEFORE_DEPLOYMENT_123456",
  "replace-with-a-long-random-secret"
]);

function isValidTimeZone(tz) {
  if (!tz || typeof tz !== "string") return false;
  try {
    Intl.DateTimeFormat("en-US", { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

function dateStrInTimeZone(date = new Date(), timeZone = "UTC") {
  const safeTz = isValidTimeZone(timeZone) ? timeZone : "UTC";
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: safeTz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).formatToParts(date);

  const map = {};
  for (const p of parts) {
    if (p.type !== "literal") map[p.type] = p.value;
  }
  return `${map.year}-${map.month}-${map.day}`;
}

function addDaysToDateStr(dateStr, deltaDays) {
  const [y, m, d] = dateStr.split("-").map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d + deltaDays));
  return dt.toISOString().slice(0, 10);
}

function parseAppointmentInTimeZone(rawValue, timeZone = "UTC") {
  const str = String(rawValue || "").trim();
  if (!str) return null;

  if (/(?:Z|[+-]\d{2}:?\d{2})$/i.test(str)) {
    const dt = new Date(str);
    return Number.isNaN(dt.getTime()) ? null : dt;
  }

  const m = str.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?$/);
  if (!m) {
    const dt = new Date(str);
    return Number.isNaN(dt.getTime()) ? null : dt;
  }

  const safeTz = isValidTimeZone(timeZone) ? timeZone : "UTC";
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = Number(m[6] || 0);

  const utcGuess = Date.UTC(year, month - 1, day, hour, minute, second);
  const fmt = new Intl.DateTimeFormat("en-CA", {
    timeZone: safeTz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23"
  });

  const getOffsetMs = (ts) => {
    const parts = fmt.formatToParts(new Date(ts));
    const p = {};
    for (const part of parts) {
      if (part.type !== "literal") p[part.type] = Number(part.value);
    }
    const tzWallAsUtc = Date.UTC(
      p.year,
      p.month - 1,
      p.day,
      p.hour,
      p.minute,
      p.second
    );
    return tzWallAsUtc - ts;
  };

  const offset = getOffsetMs(utcGuess);
  let resolved = utcGuess - offset;
  const refinedOffset = getOffsetMs(resolved);
  if (refinedOffset !== offset) {
    resolved = utcGuess - refinedOffset;
  }
  return new Date(resolved);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || "").trim());
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex");
}

function resolveSessionSecret(explicitSecret, storageDir = null) {
  const secret = explicitSecret ?? process.env.SESSION_SECRET;
  const isProd = process.env.NODE_ENV === "production";
  const isWeak = !secret || PLACEHOLDER_SECRETS.has(secret) || secret.length < 16;

  if (isProd && isWeak) {
    throw new Error(
      "SESSION_SECRET must be set to a strong secret (at least 16 characters) in production."
    );
  }
  if (isWeak) {
    if (storageDir && !explicitSecret && process.env.NODE_ENV !== "test") {
      const secretFile = path.join(storageDir, ".dev-secret");
      try {
        if (fs.existsSync(secretFile)) {
          const saved = fs.readFileSync(secretFile, "utf8").trim();
          if (saved.length >= 32) return saved;
        }
        fs.mkdirSync(storageDir, { recursive: true });
        const generated = crypto.randomBytes(32).toString("hex");
        fs.writeFileSync(secretFile, generated, { encoding: "utf8", mode: 0o600 });
        return generated;
      } catch {
        // Fallback to ephemeral secret
      }
    }
    return crypto.randomBytes(32).toString("hex");
  }
  return secret;
}

function parseTrustProxy(value) {
  if (
    value === undefined ||
    value === null ||
    value === "" ||
    value === false ||
    value === "0" ||
    value === "false"
  ) {
    return false;
  }
  if (value === true || value === "true") return 1;
  const num = Number(value);
  return Number.isFinite(num) && num >= 0 ? num : false;
}

function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    name: u.name,
    email: u.email,
    role: u.role,
    phone: u.phone || "",
    status: u.status || "active",
    must_change_password: Boolean(u.must_change_password),
    mfa_enabled: Boolean(u.mfa_enabled),
    last_login_at: u.last_login_at || null,
    created_at: u.created_at || null
  };
}

function parseDeviceSummary(userAgent = "") {
  const ua = String(userAgent || "");
  if (!ua) return "Unknown client";

  let browser = "Browser";
  if (/Edg\//i.test(ua)) browser = "Edge";
  else if (/Chrome\//i.test(ua)) browser = "Chrome";
  else if (/Firefox\//i.test(ua)) browser = "Firefox";
  else if (/Safari\//i.test(ua) && !/Chrome\//i.test(ua)) browser = "Safari";
  else if (/node|undici|curl/i.test(ua)) browser = "API Client";

  let os = "Unknown OS";
  if (/Windows/i.test(ua)) os = "Windows";
  else if (/iPhone|iPad/i.test(ua)) os = "iOS";
  else if (/Android/i.test(ua)) os = "Android";
  else if (/Mac OS X/i.test(ua)) os = "macOS";
  else if (/Linux/i.test(ua)) os = "Linux";

  return `${browser} on ${os}`;
}

async function audit(
  db,
  userId,
  action,
  entityId,
  details = null,
  ip = "",
  actorRole = null,
  targetType = null,
  userAgent = ""
) {
  try {
    await db
      .prepare(
        `INSERT INTO audit_logs (
           id, user_id, actor_role, action, target_type, entity_id, details, ip, user_agent, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        uuid(),
        userId || null,
        actorRole || null,
        action,
        targetType || null,
        entityId || null,
        details ? JSON.stringify(details) : null,
        ip || "",
        String(userAgent || "").slice(0, 300),
        new Date().toISOString()
      );
  } catch (err) {
    // Keep the primary operation available, but make audit failures visible to operators.
    console.error("Audit log write failed:", String(err?.code || err?.name || "unknown error"));
  }
}

async function recordSecurityEvent(
  db,
  {
    userId = null,
    email = "",
    eventType,
    success = false,
    ip = "",
    userAgent = "",
    sessionId = null,
    details = null
  }
) {
  try {
    await db
      .prepare(
        `INSERT INTO login_events (
           id, user_id, email, event_type, success, ip, user_agent, device_info, session_id, details, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        uuid(),
        userId || null,
        String(email || "").toLowerCase().trim(),
        eventType,
        success ? 1 : 0,
        ip || "",
        String(userAgent || "").slice(0, 300),
        parseDeviceSummary(userAgent),
        sessionId || null,
        details ? JSON.stringify(details) : null,
        new Date().toISOString()
      );
  } catch (err) {
    // Security log failures must not crash the request, but must be observable.
    console.error("Security event log write failed:", String(err?.code || err?.name || "unknown error"));
  }
}

async function recordUserSession(db, { sid, userId, ip = "", userAgent = "" }) {
  const now = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO user_sessions (
         sid, user_id, ip, user_agent, device_info, created_at, last_seen_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(sid) DO UPDATE SET
         user_id = excluded.user_id,
         ip = excluded.ip,
         user_agent = excluded.user_agent,
         device_info = excluded.device_info,
         last_seen_at = excluded.last_seen_at,
         logout_at = NULL,
         revoked_at = NULL,
         revoked_by = NULL`
    )
    .run(
      sid,
      userId,
      ip || "",
      String(userAgent || "").slice(0, 300),
      parseDeviceSummary(userAgent),
      now,
      now
    );
}

async function touchUserSession(db, sid) {
  if (!sid) return;
  try {
    await db
      .prepare("UPDATE user_sessions SET last_seen_at = ? WHERE sid = ?")
      .run(new Date().toISOString(), sid);
  } catch {
    // ignore
  }
}

async function markUserSessionLogout(db, sid) {
  if (!sid) return;
  try {
    await db
      .prepare("UPDATE user_sessions SET logout_at = ? WHERE sid = ? AND logout_at IS NULL")
      .run(new Date().toISOString(), sid);
  } catch {
    // ignore
  }
}

function regenerateSession(req, patch = {}) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      Object.assign(req.session, patch);
      req.session.save((saveErr) => {
        if (saveErr) return reject(saveErr);
        resolve();
      });
    });
  });
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save((err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

module.exports = {
  isValidTimeZone,
  dateStrInTimeZone,
  addDaysToDateStr,
  parseAppointmentInTimeZone,
  isValidEmail,
  sha256Hex,
  resolveSessionSecret,
  parseTrustProxy,
  publicUser,
  parseDeviceSummary,
  audit,
  recordSecurityEvent,
  recordUserSession,
  touchUserSession,
  markUserSessionLogout,
  regenerateSession,
  saveSession
};
