const express = require("express");
const { withTransaction } = require("../db");
const { dateStrInTimeZone, audit } = require("../helpers");
const {
  canTransitionStatus,
  getBusinessAccess,
  nextTokenInTx,
  createTicket,
  emitBusinessUpdate
} = require("../queue-service");

const VALID_TICKET_STATUSES = new Set([
  "scheduled",
  "waiting",
  "called",
  "serving",
  "completed",
  "no_show",
  "cancelled"
]);

function assertNotSuspended(business, user) {
  return business.status !== "suspended" || user.role === "super_admin";
}

function createTicketRouter({ db, io, middleware }) {
  const router = express.Router();
  const { auth, businessOperate } = middleware;

  router.post("/businesses/:id/tickets", auth, businessOperate, async (req, res, next) => {
    try {
      if (!assertNotSuspended(req.business, req.user)) {
        return res.status(403).json({ error: "Business is suspended by platform admin" });
      }
      const t = await createTicket(db, req.business, req.body, "walkin", true);
      if (t.error) return res.status(400).json({ error: t.error });
      await audit(db, req.user.id, "ticket.create", t.ticket.id, { business_id: req.business.id }, req.ip);
      await emitBusinessUpdate(io, db, req.business.id);
      res.status(201).json({ ticket: t.ticket });
    } catch (e) {
      next(e);
    }
  });

  router.post("/tickets/:id/status", auth, async (req, res, next) => {
    try {
      const t = await db.prepare("SELECT * FROM tickets WHERE id = ?").get(req.params.id);
      if (!t) return res.sendStatus(404);
      const resolved = await getBusinessAccess(db, t.business_id, req.user);
      if (!resolved?.access?.canOperateQueue) return res.sendStatus(403);
      if (!assertNotSuspended(resolved.business, req.user)) {
        return res.status(403).json({ error: "Business is suspended by platform admin" });
      }

      const nextStatus = req.body?.status;
      if (!VALID_TICKET_STATUSES.has(nextStatus)) {
        return res.status(400).json({ error: "Invalid ticket status" });
      }
      if (!canTransitionStatus(t.status, nextStatus)) {
        return res.status(400).json({
          error: `Cannot change ticket status from "${t.status}" to "${nextStatus}"`
        });
      }

      let nextStaffId = t.staff_id;
      if (req.body?.staff_id !== undefined) {
        if (req.body.staff_id === null || req.body.staff_id === "") {
          nextStaffId = null;
        } else {
          const st = await db
            .prepare("SELECT id FROM staff WHERE id = ? AND business_id = ? AND is_active = 1")
            .get(req.body.staff_id, t.business_id);
          if (!st) return res.status(400).json({ error: "Invalid active staff member" });
          nextStaffId = st.id;
        }
      }

      const tz = resolved.business.timezone || "UTC";
      const now = new Date();
      const nowIso = now.toISOString();
      const today = dateStrInTimeZone(now, tz);

      const statusUpdated = await withTransaction(db, async (tx) => {
        let nextToken = t.token;
        let nextQueueDate = t.queue_date;
        let nextCheckedInAt = t.checked_in_at;
        let nextCalledAt = t.called_at;
        let nextStartedAt = t.started_at;
        let nextCompletedAt = t.completed_at;

        if (t.status === "scheduled" && nextStatus === "waiting") {
          nextCheckedInAt = nowIso;
          if (t.queue_date !== today) {
            nextQueueDate = today;
            nextToken = await nextTokenInTx(tx, t.business_id, today);
          }
        }

        if (nextStatus === "waiting") {
          nextCalledAt = null;
          nextStartedAt = null;
        } else if (nextStatus === "called") {
          nextCalledAt = nowIso;
          nextStartedAt = null;
        } else if (nextStatus === "serving") {
          nextStartedAt = nowIso;
        } else if (
          nextStatus === "completed" ||
          nextStatus === "no_show" ||
          nextStatus === "cancelled"
        ) {
          nextCompletedAt = nowIso;
        }

        const updateResult = await tx
          .prepare(
            `UPDATE tickets
             SET status = ?,
                 staff_id = ?,
                 token = ?,
                 queue_date = ?,
                 checked_in_at = ?,
                 called_at = ?,
                 started_at = ?,
                 completed_at = ?
             WHERE id = ?`
          )
          .run(
            nextStatus,
            nextStaffId,
            nextToken,
            nextQueueDate,
            nextCheckedInAt,
            nextCalledAt,
            nextStartedAt,
            nextCompletedAt,
            t.id,
            t.status
          );
        return Number(updateResult.changes || 0) > 0;
      });

      if (!statusUpdated) {
        return res.status(409).json({
          error: "Ticket status changed by another operation. Refresh and try again."
        });
      }

      await audit(
        db,
        req.user.id,
        "ticket.status",
        t.id,
        { from: t.status, to: nextStatus, staff_id: nextStaffId },
        req.ip
      );
      await emitBusinessUpdate(io, db, t.business_id);
      res.json({
        ok: true,
        ticket: await db.prepare("SELECT * FROM tickets WHERE id = ?").get(t.id)
      });
    } catch (e) {
      next(e);
    }
  });

  router.post("/tickets/:id/check-in", auth, async (req, res, next) => {
    try {
      const t = await db.prepare("SELECT * FROM tickets WHERE id = ?").get(req.params.id);
      if (!t) return res.sendStatus(404);
      const resolved = await getBusinessAccess(db, t.business_id, req.user);
      if (!resolved?.access?.canOperateQueue) return res.sendStatus(403);
      if (!assertNotSuspended(resolved.business, req.user)) {
        return res.status(403).json({ error: "Business is suspended by platform admin" });
      }
      if (t.status !== "scheduled") {
        return res.status(400).json({ error: "Only scheduled appointments can be checked in" });
      }

      const tz = resolved.business.timezone || "UTC";
      const now = new Date();
      const nowIso = now.toISOString();
      const today = dateStrInTimeZone(now, tz);

      const checkedIn = await withTransaction(db, async (tx) => {
        const nextQueueDate = today;
        const nextToken =
          t.queue_date === today ? t.token : await nextTokenInTx(tx, t.business_id, today);
        const result = await tx
          .prepare("UPDATE tickets SET status = 'waiting', queue_date = ?, token = ?, checked_in_at = ? WHERE id = ? AND status = 'scheduled'")
          .run(nextQueueDate, nextToken, nowIso, t.id);
        return Number(result.changes || 0) > 0;
      });
      if (!checkedIn) {
        return res.status(409).json({ error: "Appointment was changed by another operation. Refresh and try again." });
      }

      await audit(db, req.user.id, "ticket.check_in", t.id, null, req.ip);
      await emitBusinessUpdate(io, db, t.business_id);
      res.json({
        ok: true,
        ticket: await db.prepare("SELECT * FROM tickets WHERE id = ?").get(t.id)
      });
    } catch (e) {
      next(e);
    }
  });

  router.post("/businesses/:id/queue/next", auth, businessOperate, async (req, res, next) => {
    try {
      if (!assertNotSuspended(req.business, req.user)) {
        return res.status(403).json({ error: "Business is suspended by platform admin" });
      }

      const { staff_id, location_id } = req.body || {};
      let assignStaffId = null;

      if (staff_id) {
        const member = await db
          .prepare("SELECT id FROM staff WHERE id = ? AND business_id = ? AND is_active = 1")
          .get(staff_id, req.business.id);
        if (!member) return res.status(400).json({ error: "Invalid active team member" });
        assignStaffId = member.id;
      }

      if (location_id) {
        const loc = await db
          .prepare("SELECT id FROM locations WHERE id = ? AND business_id = ?")
          .get(location_id, req.business.id);
        if (!loc) return res.status(400).json({ error: "Invalid location" });
      }

      const now = new Date().toISOString();
      const called = await withTransaction(db, async (tx) => {
        const locationClause = location_id ? "AND location_id = ?" : "";
        const params = location_id ? [req.business.id, location_id] : [req.business.id];
        const nextRow = await tx
          .prepare(
            `SELECT * FROM tickets
             WHERE business_id = ? AND status = 'waiting' ${locationClause}
             ORDER BY COALESCE(checked_in_at, created_at) ASC
             LIMIT 1${tx.kind === "postgres" ? " FOR UPDATE SKIP LOCKED" : ""}`
          )
          .get(...params);

        if (!nextRow) return null;

        const updateResult = await tx
          .prepare(
            "UPDATE tickets SET status = 'called', called_at = ?, staff_id = COALESCE(CAST(? AS TEXT), staff_id) WHERE id = ? AND status = 'waiting'"
          )
          .run(now, assignStaffId, nextRow.id);
        if (Number(updateResult.changes || 0) === 0) return null;

        return tx.prepare("SELECT * FROM tickets WHERE id = ?").get(nextRow.id);
      });

      if (!called) return res.status(404).json({ error: "No waiting customers" });

      await audit(
        db,
        req.user.id,
        "queue.next",
        called.id,
        { business_id: req.business.id, staff_id: assignStaffId, location_id: location_id || null },
        req.ip
      );
      await emitBusinessUpdate(io, db, req.business.id);
      res.json({ ticket: called });
    } catch (e) {
      next(e);
    }
  });

  router.post("/businesses/:id/queue/clear-completed", auth, businessOperate, async (req, res, next) => {
    try {
      if (!assertNotSuspended(req.business, req.user)) {
        return res.status(403).json({ error: "Business is suspended by platform admin" });
      }

      const tz = req.business.timezone || "UTC";
      const today = dateStrInTimeZone(new Date(), tz);
      const nowIso = new Date().toISOString();

      const info = await db
        .prepare(
          `UPDATE tickets
           SET archived_at = ?
           WHERE business_id = ?
             AND status IN ('completed', 'no_show', 'cancelled')
             AND queue_date = ?
             AND archived_at IS NULL`
        )
        .run(nowIso, req.business.id, today);

      await audit(
        db,
        req.user.id,
        "queue.clear_completed",
        req.business.id,
        { archived: Number(info.changes || 0) },
        req.ip
      );
      await emitBusinessUpdate(io, db, req.business.id);
      res.json({ ok: true, archived: Number(info.changes || 0) });
    } catch (e) {
      next(e);
    }
  });

  router.post("/businesses/:id/queue/close-stale", auth, businessOperate, async (req, res, next) => {
    try {
      if (!assertNotSuspended(req.business, req.user)) {
        return res.status(403).json({ error: "Business is suspended by platform admin" });
      }

      const tz = req.business.timezone || "UTC";
      const today = dateStrInTimeZone(new Date(), tz);
      const nowIso = new Date().toISOString();

      const info = await db
        .prepare(
          `UPDATE tickets
           SET status = 'no_show', completed_at = ?
           WHERE business_id = ?
             AND status IN ('waiting', 'called', 'serving')
             AND queue_date < ?`
        )
        .run(nowIso, req.business.id, today);

      await audit(
        db,
        req.user.id,
        "queue.close_stale",
        req.business.id,
        { updated: Number(info.changes || 0) },
        req.ip
      );
      await emitBusinessUpdate(io, db, req.business.id);
      res.json({ ok: true, updated: Number(info.changes || 0) });
    } catch (e) {
      next(e);
    }
  });

  return router;
}

module.exports = { createTicketRouter };
