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
  recordUserSession,
  markUserSessionLogout,
  regenerateSession,
  saveSession
} = require("../helpers");
const {
  generateTotpSecret,
  verifyTotp,
  buildOtpAuthUri,
  generateRecoveryCodes,
  consumeRecoveryCode
} = require("../mfa");

const MAX_FAILED_LOGINS = 5;
const LOCKOUT_MINUTES = 15;

function createAuthRouter({ db, middleware, maybeRateLimit }) {
  const router = express.Router();
  const { auth } = middleware;

  router.post(
    "/register",
    maybeRateLimit({ windowMs: 3600000, limit: 10 }),
    async (req, res, next) => {
      try {
        const { name, email, password, phone } = req.body || {};
        const cleanName = String(name || "").trim();
        const cleanEmail = String(email || "").toLowerCase().trim();
        const cleanPass = String(password || "");

        if (!cleanName || !isValidEmail(cleanEmail) || cleanPass.length < 6) {
          return res.status(400).json({
            error: "Name, valid email and password (6+ characters) required"
          });
        }

        const uid = uuid();
        const hash = await bcrypt.hash(cleanPass, 12);
        const nowIso = new Date().toISOString();

        await withTransaction(db, async (tx) => {
          await tx
            .prepare(
              `INSERT INTO users (
                 id, name, email, password_hash, role, phone, status,
                 privacy_notice_accepted_at, last_login_at, last_login_ip, updated_at, created_at
               ) VALUES (?, ?, ?, ?, 'owner', ?, 'active', ?, ?, ?, ?, ?)`
            )
            .run(
              uid,
              cleanName,
              cleanEmail,
              hash,
              String(phone || "").trim(),
              nowIso,
              nowIso,
              req.ip || "",
              nowIso,
              nowIso
            );

          await tx
            .prepare("UPDATE staff SET user_id = ? WHERE lower(email) = ? AND user_id IS NULL")
            .run(uid, cleanEmail);
        });

        await regenerateSession(req, { userId: uid, mfaVerified: true });
        await recordUserSession(db, {
          sid: req.sessionID,
          userId: uid,
          ip: req.ip,
          userAgent: req.get("user-agent")
        });
        await recordSecurityEvent(db, {
          userId: uid,
          email: cleanEmail,
          eventType: "login_success",
          success: true,
          ip: req.ip,
          userAgent: req.get("user-agent"),
          sessionId: req.sessionID,
          details: { via: "register" }
        });
        await audit(
          db,
          uid,
          "auth.register",
          uid,
          { email: cleanEmail },
          req.ip,
          "owner",
          "user",
          req.get("user-agent")
        );

        const createdUser = await db.prepare("SELECT * FROM users WHERE id = ?").get(uid);
        res.json({ user: publicUser(createdUser) });
      } catch (e) {
        if (isUniqueConstraintError(e)) {
          return res.status(400).json({ error: "Email already registered" });
        }
        next(e);
      }
    }
  );

  router.post(
    "/login",
    maybeRateLimit({ windowMs: 900000, limit: 15 }),
    async (req, res, next) => {
      try {
        const cleanEmail = String(req.body?.email || "").toLowerCase().trim();
        const password = String(req.body?.password || "");
        const ua = req.get("user-agent") || "";
        const u = await db.prepare("SELECT * FROM users WHERE email = ?").get(cleanEmail);

        if (!u) {
          await recordSecurityEvent(db, {
            email: cleanEmail,
            eventType: "login_failed",
            success: false,
            ip: req.ip,
            userAgent: ua,
            details: { reason: "unknown_email" }
          });
          return res.status(401).json({ error: "Incorrect email or password" });
        }

        if (u.status === "deleted") {
          await recordSecurityEvent(db, {
            userId: u.id,
            email: cleanEmail,
            eventType: "login_failed",
            success: false,
            ip: req.ip,
            userAgent: ua,
            details: { reason: "account_deleted" }
          });
          return res.status(403).json({ error: "This account has been deactivated" });
        }

        if (u.status === "suspended") {
          await recordSecurityEvent(db, {
            userId: u.id,
            email: cleanEmail,
            eventType: "login_failed",
            success: false,
            ip: req.ip,
            userAgent: ua,
            details: { reason: "account_suspended" }
          });
          return res.status(403).json({
            error: u.suspension_reason
              ? `Account suspended: ${u.suspension_reason}`
              : "Account suspended by platform administrator"
          });
        }

        if (u.locked_until && Date.parse(u.locked_until) > Date.now()) {
          await recordSecurityEvent(db, {
            userId: u.id,
            email: cleanEmail,
            eventType: "login_failed",
            success: false,
            ip: req.ip,
            userAgent: ua,
            details: { reason: "account_locked" }
          });
          return res.status(429).json({
            error: "Too many failed attempts. Account temporarily locked; try again later or contact support."
          });
        }

        const passOk = await bcrypt.compare(password, u.password_hash);
        if (!passOk) {
          const nextFails = Number(u.failed_login_count || 0) + 1;
          const lockUntil =
            nextFails >= MAX_FAILED_LOGINS
              ? new Date(Date.now() + LOCKOUT_MINUTES * 60000).toISOString()
              : null;

          await db
            .prepare("UPDATE users SET failed_login_count = ?, locked_until = ?, updated_at = ? WHERE id = ?")
            .run(nextFails, lockUntil, new Date().toISOString(), u.id);

          await recordSecurityEvent(db, {
            userId: u.id,
            email: cleanEmail,
            eventType: "login_failed",
            success: false,
            ip: req.ip,
            userAgent: ua,
            details: { reason: "bad_password", failed_count: nextFails }
          });

          if (lockUntil) {
            await recordSecurityEvent(db, {
              userId: u.id,
              email: cleanEmail,
              eventType: "suspicious_activity",
              success: false,
              ip: req.ip,
              userAgent: ua,
              details: { reason: "brute_force_lockout", failed_count: nextFails }
            });
          }

          return res.status(401).json({ error: "Incorrect email or password" });
        }

        const nowIso = new Date().toISOString();
        await db
          .prepare(
            `UPDATE users
             SET failed_login_count = 0, locked_until = NULL, updated_at = ?
             WHERE id = ?`
          )
          .run(nowIso, u.id);

        await db
          .prepare("UPDATE staff SET user_id = ? WHERE lower(email) = ? AND user_id IS NULL")
          .run(u.id, cleanEmail);

        if (u.role === "super_admin" && u.mfa_enabled) {
          await regenerateSession(req, {
            pendingMfaUserId: u.id,
            pendingMfaAt: Date.now()
          });
          return res.json({ mfaRequired: true, email: u.email });
        }

        await regenerateSession(req, {
          userId: u.id,
          mfaVerified: !u.mfa_enabled
        });

        await db
          .prepare("UPDATE users SET last_login_at = ?, last_login_ip = ?, updated_at = ? WHERE id = ?")
          .run(nowIso, req.ip || "", nowIso, u.id);

        await recordUserSession(db, {
          sid: req.sessionID,
          userId: u.id,
          ip: req.ip,
          userAgent: ua
        });
        await recordSecurityEvent(db, {
          userId: u.id,
          email: u.email,
          eventType: "login_success",
          success: true,
          ip: req.ip,
          userAgent: ua,
          sessionId: req.sessionID
        });
        await audit(db, u.id, "auth.login", u.id, null, req.ip, u.role, "user", ua);

        const refreshed = await db.prepare("SELECT * FROM users WHERE id = ?").get(u.id);
        res.json({
          user: publicUser(refreshed),
          mustChangePassword: Boolean(refreshed.must_change_password)
        });
      } catch (e) {
        next(e);
      }
    }
  );

  router.post(
    "/mfa/verify",
    maybeRateLimit({ windowMs: 900000, limit: 20 }),
    async (req, res, next) => {
      try {
        const pendingId = req.session?.pendingMfaUserId;
        const pendingAt = Number(req.session?.pendingMfaAt || 0);
        if (!pendingId || Date.now() - pendingAt > 300000) {
          return res.status(401).json({ error: "MFA challenge expired. Sign in again." });
        }

        const u = await db.prepare("SELECT * FROM users WHERE id = ?").get(pendingId);
        if (!u || u.status !== "active" || !u.mfa_enabled || !u.mfa_secret) {
          return res.status(401).json({ error: "MFA verification unavailable" });
        }

        const code = String(req.body?.code || "").trim();
        const ua = req.get("user-agent") || "";
        let verified = verifyTotp(u.mfa_secret, code);
        let usedRecovery = false;

        if (!verified) {
          const rec = consumeRecoveryCode(u.mfa_recovery_hashes, code);
          if (rec.matched) {
            verified = true;
            usedRecovery = true;
            await db
              .prepare("UPDATE users SET mfa_recovery_hashes = ?, updated_at = ? WHERE id = ?")
              .run(rec.remainingJson, new Date().toISOString(), u.id);
          }
        }

        if (!verified) {
          const nextFails = Number(u.failed_login_count || 0) + 1;
          const lockUntil =
            nextFails >= MAX_FAILED_LOGINS
              ? new Date(Date.now() + LOCKOUT_MINUTES * 60000).toISOString()
              : null;
          await db
            .prepare("UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?")
            .run(nextFails, lockUntil, u.id);
          await recordSecurityEvent(db, {
            userId: u.id,
            email: u.email,
            eventType: "mfa_failed",
            success: false,
            ip: req.ip,
            userAgent: ua,
            details: { failed_count: nextFails }
          });
          return res.status(401).json({ error: "Invalid verification code" });
        }

        const nowIso = new Date().toISOString();
        await regenerateSession(req, { userId: u.id, mfaVerified: true });

        await db
          .prepare(
            `UPDATE users
             SET failed_login_count = 0, locked_until = NULL,
                 last_login_at = ?, last_login_ip = ?, updated_at = ?
             WHERE id = ?`
          )
          .run(nowIso, req.ip || "", nowIso, u.id);

        await recordUserSession(db, {
          sid: req.sessionID,
          userId: u.id,
          ip: req.ip,
          userAgent: ua
        });
        await recordSecurityEvent(db, {
          userId: u.id,
          email: u.email,
          eventType: "mfa_verified",
          success: true,
          ip: req.ip,
          userAgent: ua,
          sessionId: req.sessionID,
          details: { used_recovery_code: usedRecovery }
        });
        await recordSecurityEvent(db, {
          userId: u.id,
          email: u.email,
          eventType: "login_success",
          success: true,
          ip: req.ip,
          userAgent: ua,
          sessionId: req.sessionID,
          details: { mfa: true }
        });
        await audit(
          db,
          u.id,
          "auth.mfa_login",
          u.id,
          { used_recovery_code: usedRecovery },
          req.ip,
          u.role,
          "user",
          ua
        );

        const refreshed = await db.prepare("SELECT * FROM users WHERE id = ?").get(u.id);
        res.json({
          user: publicUser(refreshed),
          mustChangePassword: Boolean(refreshed.must_change_password)
        });
      } catch (e) {
        next(e);
      }
    }
  );

  router.post("/mfa/setup", auth, async (req, res, next) => {
    try {
      if (req.user.role !== "super_admin") {
        return res.status(403).json({ error: "MFA setup is reserved for Super Admin accounts" });
      }
      const secret = generateTotpSecret();
      req.session.pendingMfaSecret = secret;
      await saveSession(req);
      const otpauthUri = buildOtpAuthUri({ secret, email: req.user.email });
      res.json({ secret, otpauthUri });
    } catch (e) {
      next(e);
    }
  });

  router.post("/mfa/confirm", auth, async (req, res, next) => {
    try {
      if (req.user.role !== "super_admin") {
        return res.status(403).json({ error: "Forbidden" });
      }
      const pendingSecret = req.session?.pendingMfaSecret;
      if (!pendingSecret) {
        return res.status(400).json({ error: "Start MFA setup first" });
      }
      const code = String(req.body?.code || "").trim();
      if (!verifyTotp(pendingSecret, code)) {
        return res.status(400).json({ error: "Invalid 6-digit authenticator code" });
      }

      const { codes, hashes } = generateRecoveryCodes(8);
      await db
        .prepare(
          `UPDATE users
           SET mfa_enabled = 1, mfa_secret = ?, mfa_recovery_hashes = ?, updated_at = ?
           WHERE id = ?`
        )
        .run(pendingSecret, JSON.stringify(hashes), new Date().toISOString(), req.user.id);

      delete req.session.pendingMfaSecret;
      req.session.mfaVerified = true;
      await saveSession(req);

      await audit(
        db,
        req.user.id,
        "auth.mfa_enabled",
        req.user.id,
        null,
        req.ip,
        req.user.role,
        "user",
        req.get("user-agent")
      );
      await recordSecurityEvent(db, {
        userId: req.user.id,
        email: req.user.email,
        eventType: "mfa_verified",
        success: true,
        ip: req.ip,
        userAgent: req.get("user-agent"),
        sessionId: req.sessionID,
        details: { action: "enrolled" }
      });

      res.json({ ok: true, recoveryCodes: codes });
    } catch (e) {
      next(e);
    }
  });

  router.post("/mfa/disable", auth, async (req, res, next) => {
    try {
      if (req.user.role !== "super_admin") {
        return res.status(403).json({ error: "Forbidden" });
      }
      const { password, code } = req.body || {};
      const passOk = await bcrypt.compare(String(password || ""), req.user.password_hash);
      if (!passOk || !verifyTotp(req.user.mfa_secret, String(code || ""))) {
        return res.status(400).json({ error: "Valid password and current TOTP code required" });
      }

      await db
        .prepare(
          "UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_recovery_hashes = NULL, updated_at = ? WHERE id = ?"
        )
        .run(new Date().toISOString(), req.user.id);

      await audit(
        db,
        req.user.id,
        "auth.mfa_disabled",
        req.user.id,
        null,
        req.ip,
        req.user.role,
        "user",
        req.get("user-agent")
      );
      res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  });

  router.post("/change-password", auth, async (req, res, next) => {
    try {
      const { current_password, new_password } = req.body || {};
      const minLen = 6;
      if (!new_password || String(new_password).length < minLen) {
        return res.status(400).json({
          error: `New password must be at least ${minLen} characters`
        });
      }
      const currentOk = await bcrypt.compare(
        String(current_password || ""),
        req.user.password_hash
      );
      if (!currentOk) {
        return res.status(401).json({ error: "Current password is incorrect" });
      }

      const hash = await bcrypt.hash(String(new_password), 12);
      const nowIso = new Date().toISOString();
      await db
        .prepare(
          `UPDATE users
           SET password_hash = ?, must_change_password = 0, updated_at = ?
           WHERE id = ?`
        )
        .run(hash, nowIso, req.user.id);

      await recordSecurityEvent(db, {
        userId: req.user.id,
        email: req.user.email,
        eventType: "password_changed",
        success: true,
        ip: req.ip,
        userAgent: req.get("user-agent"),
        sessionId: req.sessionID
      });
      await audit(
        db,
        req.user.id,
        "auth.password_changed",
        req.user.id,
        null,
        req.ip,
        req.user.role,
        "user",
        req.get("user-agent")
      );

      const refreshed = await db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
      res.json({ ok: true, user: publicUser(refreshed) });
    } catch (e) {
      next(e);
    }
  });

  router.post(
    "/reset-password",
    maybeRateLimit({ windowMs: 900000, limit: 15 }),
    async (req, res, next) => {
      try {
        const { token, new_password } = req.body || {};
        if (!token || !new_password) {
          return res.status(400).json({ error: "Reset token and new password required" });
        }

        const tokenHash = sha256Hex(String(token).trim());
        const resetRow = await db
          .prepare("SELECT * FROM password_resets WHERE token_hash = ?")
          .get(tokenHash);

        if (
          !resetRow ||
          resetRow.used_at ||
          Date.parse(resetRow.expires_at) <= Date.now()
        ) {
          return res.status(400).json({ error: "Invalid or expired password reset token" });
        }

        const u = await db.prepare("SELECT * FROM users WHERE id = ?").get(resetRow.user_id);
        if (!u || u.status === "deleted") {
          return res.status(400).json({ error: "Account unavailable" });
        }

        const minLen = 6;
        if (String(new_password).length < minLen) {
          return res.status(400).json({
            error: `Password must be at least ${minLen} characters`
          });
        }

        const hash = await bcrypt.hash(String(new_password), 12);
        const nowIso = new Date().toISOString();

        await withTransaction(db, async (tx) => {
          await tx
            .prepare(
              `UPDATE users
               SET password_hash = ?, must_change_password = 0,
                   failed_login_count = 0, locked_until = NULL, updated_at = ?
               WHERE id = ?`
            )
            .run(hash, nowIso, u.id);

          await tx
            .prepare("UPDATE password_resets SET used_at = ? WHERE id = ?")
            .run(nowIso, resetRow.id);
        });

        await recordSecurityEvent(db, {
          userId: u.id,
          email: u.email,
          eventType: "password_reset_completed",
          success: true,
          ip: req.ip,
          userAgent: req.get("user-agent")
        });
        await audit(
          db,
          u.id,
          "auth.password_reset_completed",
          u.id,
          null,
          req.ip,
          u.role,
          "user",
          req.get("user-agent")
        );

        res.json({ ok: true });
      } catch (e) {
        next(e);
      }
    }
  );

  router.post("/logout", async (req, res, next) => {
    try {
      const uid = req.session?.userId || null;
      const sid = req.sessionID;
      const ua = req.get("user-agent") || "";
      const u = uid ? await db.prepare("SELECT id, email, role FROM users WHERE id = ?").get(uid) : null;

      if (sid) await markUserSessionLogout(db, sid);

      req.session.destroy(async () => {
        res.clearCookie("connect.sid", { path: "/" });
        if (u) {
          await recordSecurityEvent(db, {
            userId: u.id,
            email: u.email,
            eventType: "logout",
            success: true,
            ip: req.ip,
            userAgent: ua,
            sessionId: sid
          });
          await audit(db, u.id, "auth.logout", u.id, null, req.ip, u.role, "user", ua);
        }
        res.json({ ok: true });
      });
    } catch (e) {
      next(e);
    }
  });

  router.get("/me", async (req, res, next) => {
    try {
      const uid = req.session?.userId;
      if (!uid) return res.json({ user: null });
      const u = await db.prepare("SELECT * FROM users WHERE id = ?").get(uid);
      if (!u || u.status !== "active") {
        return res.json({ user: null });
      }
      const sessRow = await db
        .prepare("SELECT revoked_at FROM user_sessions WHERE sid = ?")
        .get(req.sessionID);
      if (sessRow?.revoked_at) {
        return res.json({ user: null });
      }
      if (u.role === "super_admin" && u.mfa_enabled && !req.session.mfaVerified) {
        return res.json({ user: null, mfaRequired: true });
      }
      res.json({
        user: publicUser(u),
        mustChangePassword: Boolean(u.must_change_password)
      });
    } catch (e) {
      next(e);
    }
  });

  return router;
}

module.exports = { createAuthRouter };
