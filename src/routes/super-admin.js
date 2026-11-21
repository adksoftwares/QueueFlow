const crypto = require("crypto");
const express = require("express");
const bcrypt = require("bcryptjs");
const { v4: uuid } = require("uuid");
const { withTransaction, isUniqueConstraintError } = require("../db");
const {
  isValidEmail,
  sha256Hex,
  publicUser,
  audit,
  recordSecurityEvent,
  dateStrInTimeZone
} = require("../helpers");
const { evictBusinessSockets, evictUserSockets } = require("../queue-service");

const VALID_PLANS = new Set(["starter", "pro", "enterprise"]);

function parsePagination(query, defaultLimit = 20) {
  const page = Math.max(1, parseInt(query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(query.limit, 10) || defaultLimit));
  const offset = (page - 1) * limit;
  return { page, limit, offset };
}

function createSuperAdminRouter({
  db,
  io,
  sessionStore,
  middleware,
  allowAdditionalSuperAdmins = false
}) {
  const router = express.Router();
  const { auth, superAdmin } = middleware;

  router.use(auth, superAdmin);

  async function revokeSessionsForUser(userId, actor, ip, ua, specificSid = null) {
    const nowIso = new Date().toISOString();
    const rows = specificSid
      ? await db
          .prepare(
            "SELECT sid FROM user_sessions WHERE user_id = ? AND sid = ? AND revoked_at IS NULL"
          )
          .all(userId, specificSid)
      : await db
          .prepare("SELECT sid FROM user_sessions WHERE user_id = ? AND revoked_at IS NULL")
          .all(userId);

    const sids = rows.map((r) => r.sid);
    if (specificSid) {
      await db
        .prepare(
          "UPDATE user_sessions SET revoked_at = ?, revoked_by = ? WHERE user_id = ? AND sid = ? AND revoked_at IS NULL"
        )
        .run(nowIso, actor.id, userId, specificSid);
    } else {
      await db
        .prepare(
          "UPDATE user_sessions SET revoked_at = ?, revoked_by = ? WHERE user_id = ? AND revoked_at IS NULL"
        )
        .run(nowIso, actor.id, userId);
    }

    await sessionStore.destroyMany(sids);
    if (!specificSid) {
      evictUserSockets(io, userId);
    }

    const target = await db.prepare("SELECT email FROM users WHERE id = ?").get(userId);
    await recordSecurityEvent(db, {
      userId,
      email: target?.email || "",
      eventType: "session_revoked",
      success: true,
      ip,
      userAgent: ua,
      sessionId: specificSid || null,
      details: { revoked_count: sids.length, by: actor.email }
    });

    return sids.length;
  }

  // 1. Overview & Analytics
  router.get("/overview", async (req, res, next) => {
    try {
      const now = new Date();
      const todayUtc = dateStrInTimeZone(now, "UTC");
      const sevenDaysAgo = new Date(now.getTime() - 7 * 86400000).toISOString();
      const oneDayAgo = new Date(now.getTime() - 86400000).toISOString();

      const [
        userCounts,
        rawOpenSessions,
        eventStats,
        bizStats,
        ticketStats,
        lastRegisteredRows,
        recentLogins,
        businessUsage
      ] = await Promise.all([
        db
          .prepare(
            `SELECT
               COUNT(*) AS total,
               SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active,
               SUM(CASE WHEN status = 'suspended' THEN 1 ELSE 0 END) AS suspended,
               SUM(CASE WHEN status = 'deleted' THEN 1 ELSE 0 END) AS deleted,
               SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) AS new_7d
             FROM users`
          )
          .get(sevenDaysAgo),
        db
          .prepare(
            "SELECT sid, user_id FROM user_sessions WHERE revoked_at IS NULL AND logout_at IS NULL"
          )
          .all(),
        db
          .prepare(
            `SELECT
               SUM(CASE WHEN event_type = 'login_success' THEN 1 ELSE 0 END) AS total_logins,
               SUM(CASE WHEN success = 0 AND created_at >= ? THEN 1 ELSE 0 END) AS failed_24h,
               SUM(CASE WHEN event_type = 'suspicious_activity' AND created_at >= ? THEN 1 ELSE 0 END) AS suspicious_24h
             FROM login_events`
          )
          .get(oneDayAgo, oneDayAgo),
        db
          .prepare(
            `SELECT
               COUNT(*) AS total,
               SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active,
               SUM(CASE WHEN status = 'suspended' THEN 1 ELSE 0 END) AS suspended
             FROM businesses`
          )
          .get(),
        db
          .prepare(
            `SELECT
               COUNT(*) AS total,
               SUM(CASE WHEN queue_date = ? THEN 1 ELSE 0 END) AS today
             FROM tickets`
          )
          .get(todayUtc),
        db
          .prepare(
            `SELECT id, name, email, role, phone, status, must_change_password, mfa_enabled, last_login_at, created_at
             FROM users
             ORDER BY created_at DESC
             LIMIT 8`
          )
          .all(),
        db
          .prepare(
            `SELECT l.*, u.name AS user_name
             FROM login_events l
             LEFT JOIN users u ON u.id = l.user_id
             ORDER BY l.created_at DESC
             LIMIT 15`
          )
          .all(),
        db
          .prepare(
            `SELECT b.id, b.name, b.category, b.public_code, b.status, b.plan, b.created_at,
                    u.name AS owner_name, u.email AS owner_email,
                    (SELECT COUNT(*) FROM tickets t WHERE t.business_id = b.id) AS tickets_total,
                    (SELECT COUNT(*) FROM tickets t WHERE t.business_id = b.id AND t.queue_date = ?) AS tickets_today,
                    (SELECT COUNT(*) FROM services s WHERE s.business_id = b.id) AS services_count,
                    (SELECT COUNT(*) FROM staff st WHERE st.business_id = b.id) AS staff_count
             FROM businesses b
             JOIN users u ON u.id = b.owner_id
             ORDER BY tickets_total DESC, b.created_at DESC
             LIMIT 10`
          )
          .all(todayUtc)
      ]);

      const activeSet = await sessionStore.filterActiveSids(rawOpenSessions.map((r) => r.sid));
      const openSessions = rawOpenSessions.filter((r) => activeSet.has(r.sid));
      const loggedInUsers = new Set(openSessions.map((s) => s.user_id)).size;

      res.json({
        metrics: {
          total_accounts: Number(userCounts?.total || 0),
          active_accounts: Number(userCounts?.active || 0),
          suspended_accounts: Number(userCounts?.suspended || 0),
          deleted_accounts: Number(userCounts?.deleted || 0),
          currently_logged_in: loggedInUsers,
          active_sessions: openSessions.length,
          total_logins: Number(eventStats?.total_logins || 0),
          new_registrations_7d: Number(userCounts?.new_7d || 0),
          failed_logins_24h: Number(eventStats?.failed_24h || 0),
          suspicious_events_24h: Number(eventStats?.suspicious_24h || 0),
          total_businesses: Number(bizStats?.total || 0),
          active_businesses: Number(bizStats?.active || 0),
          suspended_businesses: Number(bizStats?.suspended || 0),
          tickets_today: Number(ticketStats?.today || 0),
          tickets_total: Number(ticketStats?.total || 0)
        },
        last_registered: lastRegisteredRows.map(publicUser),
        recent_logins: recentLogins,
        business_usage: businessUsage.map((b) => ({
          ...b,
          tickets_total: Number(b.tickets_total || 0),
          tickets_today: Number(b.tickets_today || 0),
          services_count: Number(b.services_count || 0),
          staff_count: Number(b.staff_count || 0)
        })),
        policy: {
          allowAdditionalSuperAdmins: Boolean(allowAdditionalSuperAdmins)
        }
      });
    } catch (e) {
      next(e);
    }
  });

  // 2. Accounts List (Search, Filter, Pagination)
  router.get("/accounts", async (req, res, next) => {
    try {
      const { page, limit, offset } = parsePagination(req.query, 20);
      const q = String(req.query.q || "").trim().toLowerCase();
      const role = String(req.query.role || "").trim();
      const status = String(req.query.status || "").trim();

      const where = [];
      const params = [];

      if (q) {
        where.push("(lower(u.name) LIKE ? OR lower(u.email) LIKE ? OR lower(COALESCE(u.phone,'')) LIKE ?)");
        const like = `%${q}%`;
        params.push(like, like, like);
      }
      if (role && role !== "all") {
        where.push("u.role = ?");
        params.push(role);
      }
      if (status && status !== "all") {
        where.push("u.status = ?");
        params.push(status);
      }

      const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

      const totalRow = await db
        .prepare(`SELECT COUNT(*) AS n FROM users u ${whereSql}`)
        .get(...params);
      const total = Number(totalRow?.n || 0);

      const rows = await db
        .prepare(
          `SELECT u.id, u.name, u.email, u.role, u.phone, u.status,
                  u.must_change_password, u.mfa_enabled, u.last_login_at,
                  u.last_login_ip, u.failed_login_count, u.locked_until,
                  u.suspended_at, u.suspension_reason, u.deleted_at, u.created_at,
                  (SELECT COUNT(*) FROM businesses b WHERE b.owner_id = u.id) AS owned_businesses,
                  (SELECT COUNT(*) FROM login_events le WHERE le.user_id = u.id AND le.event_type = 'login_success') AS login_count
           FROM users u
           ${whereSql}
           ORDER BY u.created_at DESC
           LIMIT ? OFFSET ?`
        )
        .all(...params, limit, offset);

      res.json({
        accounts: rows.map((r) => ({
          ...publicUser(r),
          last_login_ip: r.last_login_ip || "",
          failed_login_count: Number(r.failed_login_count || 0),
          locked_until: r.locked_until || null,
          suspended_at: r.suspended_at || null,
          suspension_reason: r.suspension_reason || "",
          deleted_at: r.deleted_at || null,
          owned_businesses: Number(r.owned_businesses || 0),
          login_count: Number(r.login_count || 0)
        })),
        total,
        page,
        limit,
        totalPages: Math.max(1, Math.ceil(total / limit))
      });
    } catch (e) {
      next(e);
    }
  });

  // 3. Individual Account Detail
  router.get("/accounts/:id", async (req, res, next) => {
    try {
      const u = await db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
      if (!u) return res.status(404).json({ error: "Account not found" });

      const [ownedBusinesses, staffedBusinesses, sessionRows, loginHistory, auditHistory] =
        await Promise.all([
          db
            .prepare(
              `SELECT b.*, 'owner' AS access_role,
                      (SELECT COUNT(*) FROM tickets t WHERE t.business_id = b.id) AS tickets_total
               FROM businesses b
               WHERE b.owner_id = ?
               ORDER BY b.created_at DESC`
            )
            .all(u.id),
          db
            .prepare(
              `SELECT b.*, MIN(st.role) AS access_role,
                      (SELECT COUNT(*) FROM tickets t WHERE t.business_id = b.id) AS tickets_total
               FROM businesses b
               JOIN staff st ON st.business_id = b.id
               WHERE b.owner_id != ?
                 AND (st.user_id = ? OR (st.email IS NOT NULL AND st.email != '' AND lower(st.email) = lower(?)))
               GROUP BY b.id`
            )
            .all(u.id, u.id, u.email),
          db
            .prepare(
              `SELECT sid, ip, device_info, user_agent, created_at, last_seen_at, logout_at, revoked_at
               FROM user_sessions
               WHERE user_id = ?
               ORDER BY last_seen_at DESC
               LIMIT 25`
            )
            .all(u.id),
          db
            .prepare(
              `SELECT * FROM login_events
               WHERE user_id = ?
               ORDER BY created_at DESC
               LIMIT 40`
            )
            .all(u.id),
          db
            .prepare(
              `SELECT * FROM audit_logs
               WHERE entity_id = ? OR user_id = ?
               ORDER BY created_at DESC
               LIMIT 40`
            )
            .all(u.id, u.id)
        ]);

      const activeSet = await sessionStore.filterActiveSids(sessionRows.map((s) => s.sid));
      const sessions = sessionRows.map((s) => ({
        ...s,
        is_active: !s.revoked_at && !s.logout_at && activeSet.has(s.sid)
      }));

      res.json({
        account: {
          ...publicUser(u),
          last_login_ip: u.last_login_ip || "",
          failed_login_count: Number(u.failed_login_count || 0),
          locked_until: u.locked_until || null,
          suspended_at: u.suspended_at || null,
          suspension_reason: u.suspension_reason || "",
          deleted_at: u.deleted_at || null,
          privacy_notice_accepted_at: u.privacy_notice_accepted_at || null,
          updated_at: u.updated_at || null
        },
        businesses: [...ownedBusinesses, ...staffedBusinesses],
        sessions,
        login_history: loginHistory,
        audit_history: auditHistory
      });
    } catch (e) {
      next(e);
    }
  });

  // 4. Create Account Manually
  router.post("/accounts", async (req, res, next) => {
    try {
      const { name, email, password, phone, role, must_change_password, business_name } =
        req.body || {};
      const cleanName = String(name || "").trim();
      const cleanEmail = String(email || "").toLowerCase().trim();
      const targetRole = role === "super_admin" ? "super_admin" : "owner";
      const cleanBizName = targetRole === "owner" ? String(business_name || "").trim() : "";

      if (targetRole === "super_admin" && !allowAdditionalSuperAdmins) {
        return res.status(403).json({
          error: "Platform policy prohibits creating additional Super Admin accounts"
        });
      }

      const minLen = 6;
      if (!cleanName || !isValidEmail(cleanEmail) || !password || String(password).length < minLen) {
        return res.status(400).json({
          error: `Name, valid email and password (${minLen}+ characters) required`
        });
      }

      const uid = uuid();
      const hash = await bcrypt.hash(String(password), 12);
      const nowIso = new Date().toISOString();
      let createdBizId = null;

      await withTransaction(db, async (tx) => {
        await tx
          .prepare(
            `INSERT INTO users (
               id, name, email, password_hash, role, phone, status,
               must_change_password, updated_at, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`
          )
          .run(
            uid,
            cleanName,
            cleanEmail,
            hash,
            targetRole,
            String(phone || "").trim(),
            must_change_password === false ? 0 : 1,
            nowIso,
            nowIso
          );

        await tx
          .prepare("UPDATE staff SET user_id = ? WHERE lower(email) = ? AND user_id IS NULL")
          .run(uid, cleanEmail);

        if (cleanBizName) {
          createdBizId = uuid();
          const code = uuid().replace(/-/g, "").slice(0, 7).toUpperCase();
          await tx
            .prepare(
              `INSERT INTO businesses (
                 id, owner_id, name, category, timezone, public_code, created_at
               ) VALUES (?, ?, ?, 'General', 'UTC', ?, ?)`
            )
            .run(createdBizId, uid, cleanBizName, code, nowIso);
        }
      });

      await audit(
        db,
        req.user.id,
        "super_admin.account_create",
        uid,
        {
          email: cleanEmail,
          role: targetRole,
          must_change_password: must_change_password !== false,
          business_id: createdBizId
        },
        req.ip,
        req.user.role,
        "user",
        req.get("user-agent")
      );

      const created = await db.prepare("SELECT * FROM users WHERE id = ?").get(uid);
      const createdBiz = createdBizId
        ? await db.prepare("SELECT * FROM businesses WHERE id = ?").get(createdBizId)
        : null;
      res.status(201).json({ account: publicUser(created), business: createdBiz });
    } catch (e) {
      if (isUniqueConstraintError(e)) {
        return res.status(400).json({ error: "Email already registered" });
      }
      next(e);
    }
  });

  // 5. Edit / Suspend / Reactivate / Soft-Deactivate Account
  router.patch("/accounts/:id", async (req, res, next) => {
    try {
      const target = await db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
      if (!target) return res.status(404).json({ error: "Account not found" });

      const {
        name,
        email,
        phone,
        status,
        suspension_reason,
        must_change_password,
        unlock
      } = req.body || {};

      if (target.id === req.user.id && status && status !== "active") {
        return res.status(400).json({ error: "You cannot suspend or deactivate your own account" });
      }

      if (
        target.role === "super_admin" &&
        status &&
        status !== "active" &&
        target.status === "active"
      ) {
        const otherRow = await db
          .prepare(
            "SELECT COUNT(*) AS n FROM users WHERE role = 'super_admin' AND status = 'active' AND id != ?"
          )
          .get(target.id);
        if (Number(otherRow?.n || 0) < 1) {
          return res.status(400).json({ error: "Cannot suspend the last active Super Admin" });
        }
      }

      const nextName = name !== undefined ? String(name).trim() : target.name;
      if (!nextName) return res.status(400).json({ error: "Name required" });

      const nextEmail = email !== undefined ? String(email).toLowerCase().trim() : target.email;
      if (!isValidEmail(nextEmail)) return res.status(400).json({ error: "Valid email required" });

      const nextStatus = status !== undefined ? status : target.status;
      if (!["active", "suspended", "deleted"].includes(nextStatus)) {
        return res.status(400).json({ error: "Invalid account status" });
      }

      const nowIso = new Date().toISOString();
      let suspendedAt = target.suspended_at;
      let suspensionReason = target.suspension_reason;
      let deletedAt = target.deleted_at;

      if (nextStatus === "suspended") {
        suspendedAt = target.suspended_at || nowIso;
        suspensionReason =
          suspension_reason !== undefined
            ? String(suspension_reason).trim()
            : target.suspension_reason || "Suspended by Super Admin";
      } else if (nextStatus === "deleted") {
        deletedAt = target.deleted_at || nowIso;
        suspensionReason =
          suspension_reason !== undefined
            ? String(suspension_reason).trim()
            : target.suspension_reason || "Deactivated by Super Admin";
      } else if (nextStatus === "active") {
        suspendedAt = null;
        suspensionReason = null;
        deletedAt = null;
      }

      const nextMustChange =
        must_change_password !== undefined
          ? must_change_password
            ? 1
            : 0
          : target.must_change_password;

      const resetLock = unlock || (target.status !== "active" && nextStatus === "active");

      try {
        await db
          .prepare(
            `UPDATE users
             SET name = ?, email = ?, phone = ?, status = ?,
                 suspended_at = ?, suspension_reason = ?, deleted_at = ?,
                 must_change_password = ?,
                 failed_login_count = CASE WHEN ? = 1 THEN 0 ELSE failed_login_count END,
                 locked_until = CASE WHEN ? = 1 THEN NULL ELSE locked_until END,
                 updated_at = ?
             WHERE id = ?`
          )
          .run(
            nextName,
            nextEmail,
            phone !== undefined ? String(phone).trim() : target.phone,
            nextStatus,
            suspendedAt,
            suspensionReason,
            deletedAt,
            nextMustChange,
            resetLock ? 1 : 0,
            resetLock ? 1 : 0,
            nowIso,
            target.id
          );
      } catch (e) {
        if (isUniqueConstraintError(e)) {
          return res.status(400).json({ error: "Email already registered to another account" });
        }
        throw e;
      }

      let revokedCount = 0;
      if (nextStatus !== "active") {
        revokedCount = await revokeSessionsForUser(
          target.id,
          req.user,
          req.ip,
          req.get("user-agent")
        );
      }

      await audit(
        db,
        req.user.id,
        "super_admin.account_update",
        target.id,
        {
          status: nextStatus,
          must_change_password: Boolean(nextMustChange),
          revoked_sessions: revokedCount
        },
        req.ip,
        req.user.role,
        "user",
        req.get("user-agent")
      );

      const updated = await db.prepare("SELECT * FROM users WHERE id = ?").get(target.id);
      res.json({ ok: true, account: publicUser(updated) });
    } catch (e) {
      next(e);
    }
  });

  // 6. Initiate Secure Password Reset (One-Time Hashed Token)
  router.post("/accounts/:id/reset-password", async (req, res, next) => {
    try {
      const target = await db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
      if (!target) return res.status(404).json({ error: "Account not found" });
      if (target.status === "deleted") {
        return res.status(400).json({ error: "Cannot reset password for a deactivated account" });
      }

      const {
        force_change_on_login = true,
        revoke_sessions = true,
        new_password
      } = req.body || {};

      if (new_password !== undefined && String(new_password) !== "") {
        const cleanPass = String(new_password);
        if (cleanPass.length < 6) {
          return res.status(400).json({ error: "Temporary password must be at least 6 characters" });
        }
        const hash = await bcrypt.hash(cleanPass, 12);
        const nowIso = new Date().toISOString();
        const mustChange = force_change_on_login ? 1 : 0;

        await db
          .prepare(
            `UPDATE users
             SET password_hash = ?, must_change_password = ?,
                 failed_login_count = 0, locked_until = NULL, updated_at = ?
             WHERE id = ?`
          )
          .run(hash, mustChange, nowIso, target.id);

        if (revoke_sessions) {
          await revokeSessionsForUser(target.id, req.user, req.ip, req.get("user-agent"));
        }

        await recordSecurityEvent(db, {
          userId: target.id,
          email: target.email,
          eventType: "password_reset_completed",
          success: true,
          ip: req.ip,
          userAgent: req.get("user-agent"),
          details: { mode: "admin_temporary_password", initiated_by: req.user.email }
        });
        await audit(
          db,
          req.user.id,
          "super_admin.temporary_password_set",
          target.id,
          { email: target.email, force_change_on_login: Boolean(force_change_on_login) },
          req.ip,
          req.user.role,
          "user",
          req.get("user-agent")
        );

        return res.json({
          ok: true,
          mode: "temporary_password",
          mustChangePassword: Boolean(force_change_on_login)
        });
      }

      const rawToken = crypto.randomBytes(24).toString("hex");
      const tokenHash = sha256Hex(rawToken);
      const now = new Date();
      const nowIso = now.toISOString();
      const expiresAt = new Date(now.getTime() + 60 * 60000).toISOString();

      await withTransaction(db, async (tx) => {
        await tx
          .prepare(
            `INSERT INTO password_resets (id, user_id, token_hash, created_by_user_id, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?)`
          )
          .run(uuid(), target.id, tokenHash, req.user.id, expiresAt, nowIso);

        if (force_change_on_login) {
          await tx
            .prepare("UPDATE users SET must_change_password = 1, updated_at = ? WHERE id = ?")
            .run(nowIso, target.id);
        }
      });

      if (revoke_sessions) {
        await revokeSessionsForUser(target.id, req.user, req.ip, req.get("user-agent"));
      }

      await recordSecurityEvent(db, {
        userId: target.id,
        email: target.email,
        eventType: "password_reset_requested",
        success: true,
        ip: req.ip,
        userAgent: req.get("user-agent"),
        details: { initiated_by: req.user.email }
      });
      await audit(
        db,
        req.user.id,
        "super_admin.password_reset_initiated",
        target.id,
        { email: target.email, expires_at: expiresAt },
        req.ip,
        req.user.role,
        "user",
        req.get("user-agent")
      );

      res.json({
        ok: true,
        resetToken: rawToken,
        resetPath: `/?resetToken=${encodeURIComponent(rawToken)}`,
        expiresAt
      });
    } catch (e) {
      next(e);
    }
  });

  // 7. Revoke Sessions / Force Logout Across Devices
  router.post("/accounts/:id/revoke-sessions", async (req, res, next) => {
    try {
      const target = await db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
      if (!target) return res.status(404).json({ error: "Account not found" });

      const specificSid = req.body?.sid ? String(req.body.sid) : null;
      const count = await revokeSessionsForUser(
        target.id,
        req.user,
        req.ip,
        req.get("user-agent"),
        specificSid
      );

      await audit(
        db,
        req.user.id,
        "super_admin.sessions_revoked",
        target.id,
        { revoked_count: count, specific_sid: specificSid },
        req.ip,
        req.user.role,
        "user",
        req.get("user-agent")
      );

      res.json({ ok: true, revoked: count });
    } catch (e) {
      next(e);
    }
  });

  // 8. Permanent Account Deletion (Requires Exact Email Confirmation)
  router.delete("/accounts/:id", async (req, res, next) => {
    try {
      const target = await db.prepare("SELECT * FROM users WHERE id = ?").get(req.params.id);
      if (!target) return res.status(404).json({ error: "Account not found" });

      if (target.id === req.user.id) {
        return res.status(400).json({ error: "You cannot permanently delete your own account" });
      }

      if (target.role === "super_admin") {
        const otherRow = await db
          .prepare(
            "SELECT COUNT(*) AS n FROM users WHERE role = 'super_admin' AND status = 'active' AND id != ?"
          )
          .get(target.id);
        if (Number(otherRow?.n || 0) < 1) {
          return res.status(400).json({ error: "Cannot delete the last Super Admin account" });
        }
      }

      const confirmEmail = String(req.body?.confirmEmail || "").toLowerCase().trim();
      if (confirmEmail !== target.email.toLowerCase()) {
        return res.status(400).json({
          error: "Confirmation email does not match the target account email"
        });
      }

      const ownedRows = await db
        .prepare("SELECT id FROM businesses WHERE owner_id = ?")
        .all(target.id);
      const ownedBizIds = ownedRows.map((b) => b.id);

      for (const bid of ownedBizIds) {
        await evictBusinessSockets(io, db, bid);
      }

      await revokeSessionsForUser(target.id, req.user, req.ip, req.get("user-agent"));

      await withTransaction(db, async (tx) => {
        await tx.prepare("DELETE FROM businesses WHERE owner_id = ?").run(target.id);
        await tx.prepare("DELETE FROM users WHERE id = ?").run(target.id);
      });

      await audit(
        db,
        req.user.id,
        "super_admin.account_permanent_delete",
        target.id,
        { email: target.email, deleted_businesses: ownedBizIds.length },
        req.ip,
        req.user.role,
        "user",
        req.get("user-agent")
      );

      res.json({ ok: true, deleted_businesses: ownedBizIds.length });
    } catch (e) {
      next(e);
    }
  });

  // 9. Businesses Management
  router.get("/businesses", async (req, res, next) => {
    try {
      const { page, limit, offset } = parsePagination(req.query, 20);
      const q = String(req.query.q || "").trim().toLowerCase();
      const status = String(req.query.status || "").trim();
      const todayUtc = dateStrInTimeZone(new Date(), "UTC");

      const where = [];
      const params = [];

      if (q) {
        where.push(
          "(lower(b.name) LIKE ? OR lower(b.public_code) LIKE ? OR lower(u.email) LIKE ? OR lower(u.name) LIKE ?)"
        );
        const like = `%${q}%`;
        params.push(like, like, like, like);
      }
      if (status && status !== "all") {
        where.push("b.status = ?");
        params.push(status);
      }

      const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
      const totalRow = await db
        .prepare(
          `SELECT COUNT(*) AS n FROM businesses b JOIN users u ON u.id = b.owner_id ${whereSql}`
        )
        .get(...params);
      const total = Number(totalRow?.n || 0);

      const rows = await db
        .prepare(
          `SELECT b.*, u.name AS owner_name, u.email AS owner_email, u.status AS owner_status,
                  (SELECT COUNT(*) FROM tickets t WHERE t.business_id = b.id) AS tickets_total,
                  (SELECT COUNT(*) FROM tickets t WHERE t.business_id = b.id AND t.queue_date = ?) AS tickets_today,
                  (SELECT COUNT(*) FROM services s WHERE s.business_id = b.id) AS services_count,
                  (SELECT COUNT(*) FROM locations l WHERE l.business_id = b.id) AS locations_count,
                  (SELECT COUNT(*) FROM staff st WHERE st.business_id = b.id) AS staff_count
           FROM businesses b
           JOIN users u ON u.id = b.owner_id
           ${whereSql}
           ORDER BY b.created_at DESC
           LIMIT ? OFFSET ?`
        )
        .all(todayUtc, ...params, limit, offset);

      res.json({
        businesses: rows.map((b) => ({
          ...b,
          tickets_total: Number(b.tickets_total || 0),
          tickets_today: Number(b.tickets_today || 0),
          services_count: Number(b.services_count || 0),
          locations_count: Number(b.locations_count || 0),
          staff_count: Number(b.staff_count || 0)
        })),
        total,
        page,
        limit,
        totalPages: Math.max(1, Math.ceil(total / limit))
      });
    } catch (e) {
      next(e);
    }
  });

  router.get("/businesses/:id", async (req, res, next) => {
    try {
      const b = await db
        .prepare(
          `SELECT b.*, u.name AS owner_name, u.email AS owner_email, u.status AS owner_status
           FROM businesses b
           JOIN users u ON u.id = b.owner_id
           WHERE b.id = ?`
        )
        .get(req.params.id);
      if (!b) return res.status(404).json({ error: "Business not found" });

      const [locations, services, staff, recentTickets, activity] = await Promise.all([
        db.prepare("SELECT * FROM locations WHERE business_id = ? ORDER BY created_at DESC").all(b.id),
        db.prepare("SELECT * FROM services WHERE business_id = ? ORDER BY created_at DESC").all(b.id),
        db.prepare("SELECT * FROM staff WHERE business_id = ? ORDER BY created_at DESC").all(b.id),
        db
          .prepare("SELECT * FROM tickets WHERE business_id = ? ORDER BY created_at DESC LIMIT 25")
          .all(b.id),
        db
          .prepare(
            `SELECT a.*, u.email AS actor_email
             FROM audit_logs a
             LEFT JOIN users u ON u.id = a.user_id
             WHERE a.entity_id = ? OR a.details LIKE ?
             ORDER BY a.created_at DESC
             LIMIT 30`
          )
          .all(b.id, `%${b.id}%`)
      ]);

      res.json({
        business: b,
        locations,
        services,
        staff,
        recent_tickets: recentTickets,
        activity
      });
    } catch (e) {
      next(e);
    }
  });

  router.patch("/businesses/:id", async (req, res, next) => {
    try {
      const b = await db.prepare("SELECT * FROM businesses WHERE id = ?").get(req.params.id);
      if (!b) return res.status(404).json({ error: "Business not found" });

      const { status, plan, suspension_reason } = req.body || {};
      let nextStatus = b.status;
      let nextPlan = b.plan || "starter";
      let suspendedAt = b.suspended_at;
      let reason = b.suspension_reason;

      if (status !== undefined) {
        if (!["active", "paused", "suspended"].includes(status)) {
          return res.status(400).json({ error: "Invalid business status" });
        }
        nextStatus = status;
        if (status === "suspended") {
          suspendedAt = b.suspended_at || new Date().toISOString();
          reason =
            suspension_reason !== undefined
              ? String(suspension_reason).trim()
              : b.suspension_reason || "Suspended by Super Admin";
        } else {
          suspendedAt = null;
          reason = null;
        }
      }

      if (plan !== undefined) {
        if (!VALID_PLANS.has(plan)) {
          return res.status(400).json({ error: "Invalid plan" });
        }
        nextPlan = plan;
      }

      await db
        .prepare(
          `UPDATE businesses
           SET status = ?, plan = ?, suspended_at = ?, suspension_reason = ?
           WHERE id = ?`
        )
        .run(nextStatus, nextPlan, suspendedAt, reason, b.id);

      if (nextStatus === "suspended") {
        await evictBusinessSockets(io, db, b.id);
      }

      await audit(
        db,
        req.user.id,
        "super_admin.business_update",
        b.id,
        { status: nextStatus, plan: nextPlan, reason },
        req.ip,
        req.user.role,
        "business",
        req.get("user-agent")
      );

      res.json({
        ok: true,
        business: await db.prepare("SELECT * FROM businesses WHERE id = ?").get(b.id)
      });
    } catch (e) {
      next(e);
    }
  });

  // 10. Security Events & Active Sessions & Audit Logs
  router.get("/security-events", async (req, res, next) => {
    try {
      const { page, limit, offset } = parsePagination(req.query, 25);
      const q = String(req.query.q || "").trim().toLowerCase();
      const type = String(req.query.type || "").trim();
      const success = String(req.query.success || "").trim();

      const where = [];
      const params = [];

      if (q) {
        where.push(
          "(lower(COALESCE(l.email,'')) LIKE ? OR lower(COALESCE(l.ip,'')) LIKE ? OR lower(COALESCE(l.device_info,'')) LIKE ?)"
        );
        const like = `%${q}%`;
        params.push(like, like, like);
      }
      if (type && type !== "all") {
        where.push("l.event_type = ?");
        params.push(type);
      }
      if (success === "1" || success === "0") {
        where.push("l.success = ?");
        params.push(Number(success));
      }

      const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
      const totalRow = await db
        .prepare(`SELECT COUNT(*) AS n FROM login_events l ${whereSql}`)
        .get(...params);
      const total = Number(totalRow?.n || 0);

      const events = await db
        .prepare(
          `SELECT l.*, u.name AS user_name, u.role AS user_role
           FROM login_events l
           LEFT JOIN users u ON u.id = l.user_id
           ${whereSql}
           ORDER BY l.created_at DESC
           LIMIT ? OFFSET ?`
        )
        .all(...params, limit, offset);

      res.json({
        events,
        total,
        page,
        limit,
        totalPages: Math.max(1, Math.ceil(total / limit))
      });
    } catch (e) {
      next(e);
    }
  });

  router.get("/sessions", async (req, res, next) => {
    try {
      const rows = await db
        .prepare(
          `SELECT s.*, u.name AS user_name, u.email AS user_email, u.role AS user_role, u.status AS user_status
           FROM user_sessions s
           JOIN users u ON u.id = s.user_id
           WHERE s.revoked_at IS NULL AND s.logout_at IS NULL
           ORDER BY s.last_seen_at DESC
           LIMIT 200`
        )
        .all();

      const activeSet = await sessionStore.filterActiveSids(rows.map((s) => s.sid));
      res.json({ sessions: rows.filter((s) => activeSet.has(s.sid)) });
    } catch (e) {
      next(e);
    }
  });

  router.get("/audit-logs", async (req, res, next) => {
    try {
      const { page, limit, offset } = parsePagination(req.query, 25);
      const q = String(req.query.q || "").trim().toLowerCase();
      const action = String(req.query.action || "").trim();

      const where = [];
      const params = [];

      if (q) {
        where.push(
          "(lower(COALESCE(a.action,'')) LIKE ? OR lower(COALESCE(a.entity_id,'')) LIKE ? OR lower(COALESCE(a.details,'')) LIKE ? OR lower(COALESCE(u.email,'')) LIKE ?)"
        );
        const like = `%${q}%`;
        params.push(like, like, like, like);
      }
      if (action && action !== "all") {
        where.push("a.action LIKE ?");
        params.push(`${action}%`);
      }

      const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
      const totalRow = await db
        .prepare(
          `SELECT COUNT(*) AS n FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id ${whereSql}`
        )
        .get(...params);
      const total = Number(totalRow?.n || 0);

      const logs = await db
        .prepare(
          `SELECT a.*, u.email AS user_email, u.name AS user_name
           FROM audit_logs a
           LEFT JOIN users u ON u.id = a.user_id
           ${whereSql}
           ORDER BY a.created_at DESC
           LIMIT ? OFFSET ?`
        )
        .all(...params, limit, offset);

      res.json({
        logs,
        total,
        page,
        limit,
        totalPages: Math.max(1, Math.ceil(total / limit))
      });
    } catch (e) {
      next(e);
    }
  });

  return router;
}

module.exports = { createSuperAdminRouter };
