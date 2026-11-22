const express = require("express");
const { v4: uuid } = require("uuid");
const { isUniqueConstraintError } = require("../db");
const { isValidEmail, isValidTimeZone, publicUser, audit } = require("../helpers");
const {
  getBusinessAccess,
  queue,
  recentFinishedTickets,
  scheduledAppointments,
  stats,
  performance,
  evictBusinessSockets
} = require("../queue-service");

const OWNER_SETTABLE_BUSINESS_STATUSES = new Set(["active", "paused"]);
const STAFF_ROLES = new Set(["staff", "manager", "counter"]);

function createBusinessRouter({ db, io, middleware }) {
  const router = express.Router();
  const { auth, businessOperate, businessManage, businessOwnerOrAdmin } = middleware;

  router.get("/dashboard", auth, async (req, res, next) => {
    try {
      const owned = await db
        .prepare("SELECT *, 'owner' AS access_role FROM businesses WHERE owner_id = ?")
        .all(req.user.id);

      const staffed = await db
        .prepare(
          `SELECT b.*, MIN(st.role) AS access_role
           FROM businesses b
           JOIN staff st ON st.business_id = b.id
           WHERE b.owner_id != ?
             AND st.is_active = 1
             AND (st.user_id = ? OR (st.email IS NOT NULL AND st.email != '' AND lower(st.email) = lower(?)))
           GROUP BY b.id`
        )
        .all(req.user.id, req.user.id, req.user.email || "");

      const combined = [...owned, ...staffed].sort((a, b) =>
        String(b.created_at).localeCompare(String(a.created_at))
      );

      const enriched = await Promise.all(
        combined.map(async (b) => {
          const [bStats, svcRow, locRow] = await Promise.all([
            stats(db, b.id, b.timezone || "UTC"),
            db.prepare("SELECT count(*) AS n FROM services WHERE business_id = ?").get(b.id),
            db.prepare("SELECT count(*) AS n FROM locations WHERE business_id = ?").get(b.id)
          ]);
          return {
            ...b,
            ...bStats,
            services: Number(svcRow?.n || 0),
            locations: Number(locRow?.n || 0)
          };
        })
      );

      res.json({
        businesses: enriched,
        user: publicUser(req.user)
      });
    } catch (e) {
      next(e);
    }
  });

  router.post("/businesses", auth, async (req, res, next) => {
    try {
      const { name, category, description, address, phone, timezone } = req.body || {};
      if (!name || !String(name).trim()) {
        return res.status(400).json({ error: "Business name required" });
      }

      const tz = timezone ? String(timezone).trim() : "UTC";
      if (!isValidTimeZone(tz)) {
        return res.status(400).json({ error: "Invalid IANA timezone" });
      }

      const bid = uuid();
      const nowIso = new Date().toISOString();
      let created = false;

      for (let attempt = 0; attempt < 5; attempt++) {
        const code = uuid().replace(/-/g, "").slice(0, 7).toUpperCase();
        try {
          await db
            .prepare(
              `INSERT INTO businesses (
                 id, owner_id, name, category, description, address, phone, timezone, public_code, created_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
            )
            .run(
              bid,
              req.user.id,
              String(name).trim(),
              String(category || "General").trim(),
              String(description || "").trim(),
              String(address || "").trim(),
              String(phone || "").trim(),
              tz,
              code,
              nowIso
            );
          created = true;
          break;
        } catch (e) {
          if (!isUniqueConstraintError(e)) throw e;
        }
      }

      if (!created) {
        return res.status(500).json({ error: "Could not allocate unique public code" });
      }

      await audit(db, req.user.id, "business.create", bid, { name: String(name).trim() }, req.ip);
      res.status(201).json({
        business: await db.prepare("SELECT * FROM businesses WHERE id = ?").get(bid)
      });
    } catch (e) {
      next(e);
    }
  });

  router.get("/businesses/:id", auth, businessOperate, async (req, res, next) => {
    try {
      const bid = req.business.id;
      const tz = req.business.timezone || "UTC";
      const locationId = req.query.location_id ? String(req.query.location_id).trim() : null;

      if (locationId) {
        const loc = await db
          .prepare("SELECT id FROM locations WHERE id = ? AND business_id = ?")
          .get(locationId, bid);
        if (!loc) return res.status(400).json({ error: "Invalid location filter" });
      }

      const [locations, services, staff, qList, recent, appointments, bStats, bPerf] =
        await Promise.all([
          db.prepare("SELECT * FROM locations WHERE business_id = ? ORDER BY created_at DESC").all(bid),
          db.prepare("SELECT * FROM services WHERE business_id = ? ORDER BY created_at DESC").all(bid),
          db.prepare("SELECT * FROM staff WHERE business_id = ? ORDER BY created_at DESC").all(bid),
          queue(db, bid, locationId),
          recentFinishedTickets(db, bid, tz, locationId),
          scheduledAppointments(db, bid, locationId),
          stats(db, bid, tz, locationId),
          performance(db, bid, tz, locationId)
        ]);

      res.json({
        business: req.business,
        access: req.businessAccess,
        locations,
        services,
        staff,
        queue: qList,
        recent_tickets: recent,
        appointments,
        stats: bStats,
        performance: bPerf
      });
    } catch (e) {
      next(e);
    }
  });

  router.patch("/businesses/:id", auth, businessManage, async (req, res, next) => {
    try {
      const b = req.business;
      if (b.status === "suspended" && req.user.role !== "super_admin") {
        return res.status(403).json({ error: "Business is suspended by Super Admin" });
      }

      const { name, category, description, address, phone, status, timezone } = req.body || {};
      let nextStatus = b.status;

      if (status !== undefined) {
        if (req.user.role === "super_admin" && ["active", "paused", "suspended"].includes(status)) {
          nextStatus = status;
        } else if (OWNER_SETTABLE_BUSINESS_STATUSES.has(status)) {
          nextStatus = status;
        } else {
          return res.status(400).json({ error: "Invalid business status" });
        }
      }

      let nextTz = b.timezone || "UTC";
      if (timezone !== undefined) {
        const candidate = String(timezone).trim();
        if (!isValidTimeZone(candidate)) {
          return res.status(400).json({ error: "Invalid IANA timezone" });
        }
        nextTz = candidate;
      }

      const nextName = name !== undefined ? String(name).trim() : b.name;
      if (!nextName) return res.status(400).json({ error: "Business name required" });

      await db
        .prepare(
          `UPDATE businesses
           SET name = ?, category = ?, description = ?, address = ?, phone = ?, timezone = ?, status = ?
           WHERE id = ?`
        )
        .run(
          nextName,
          category !== undefined ? String(category).trim() || b.category : b.category,
          description !== undefined ? String(description).trim() : b.description,
          address !== undefined ? String(address).trim() : b.address,
          phone !== undefined ? String(phone).trim() : b.phone,
          nextTz,
          nextStatus,
          b.id
        );

      if (nextStatus === "suspended") {
        await evictBusinessSockets(io, db, b.id);
      }

      await audit(db, req.user.id, "business.update", b.id, { status: nextStatus, timezone: nextTz }, req.ip);
      res.json({
        ok: true,
        business: await db.prepare("SELECT * FROM businesses WHERE id = ?").get(b.id)
      });
    } catch (e) {
      next(e);
    }
  });

  router.delete("/businesses/:id", auth, businessOwnerOrAdmin, async (req, res, next) => {
    try {
      await evictBusinessSockets(io, db, req.business.id);
      await db.prepare("DELETE FROM businesses WHERE id = ?").run(req.business.id);
      await audit(
        db,
        req.user.id,
        "business.delete",
        req.business.id,
        { name: req.business.name },
        req.ip
      );
      res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  });

  // Locations / Branches
  router.post("/businesses/:id/locations", auth, businessManage, async (req, res, next) => {
    try {
      if (req.business.status === "suspended" && req.user.role !== "super_admin") {
        return res.status(403).json({ error: "Business is suspended by Super Admin" });
      }
      const { name, address, phone } = req.body || {};
      if (!name || !String(name).trim()) {
        return res.status(400).json({ error: "Location name required" });
      }
      const lid = uuid();
      await db
        .prepare(
          "INSERT INTO locations (id, business_id, name, address, phone, created_at) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .run(
          lid,
          req.business.id,
          String(name).trim(),
          String(address || "").trim(),
          String(phone || "").trim(),
          new Date().toISOString()
        );
      await audit(db, req.user.id, "location.create", lid, { business_id: req.business.id }, req.ip);
      res.status(201).json({
        location: await db.prepare("SELECT * FROM locations WHERE id = ?").get(lid)
      });
    } catch (e) {
      next(e);
    }
  });

  router.patch("/locations/:id", auth, async (req, res, next) => {
    try {
      const loc = await db.prepare("SELECT * FROM locations WHERE id = ?").get(req.params.id);
      if (!loc) return res.sendStatus(404);
      const resolved = await getBusinessAccess(db, loc.business_id, req.user);
      if (!resolved?.access?.canManageBusiness) return res.sendStatus(403);

      const x = req.body || {};
      const nextName = x.name !== undefined ? String(x.name).trim() : loc.name;
      if (!nextName) return res.status(400).json({ error: "Location name required" });

      await db
        .prepare("UPDATE locations SET name = ?, address = ?, phone = ?, is_active = ? WHERE id = ?")
        .run(
          nextName,
          x.address !== undefined ? String(x.address).trim() : loc.address,
          x.phone !== undefined ? String(x.phone).trim() : loc.phone,
          x.is_active === undefined ? loc.is_active : x.is_active ? 1 : 0,
          loc.id
        );
      await audit(db, req.user.id, "location.update", loc.id, null, req.ip);
      res.json({
        ok: true,
        location: await db.prepare("SELECT * FROM locations WHERE id = ?").get(loc.id)
      });
    } catch (e) {
      next(e);
    }
  });

  router.delete("/locations/:id", auth, async (req, res, next) => {
    try {
      const loc = await db.prepare("SELECT * FROM locations WHERE id = ?").get(req.params.id);
      if (!loc) return res.sendStatus(404);
      const resolved = await getBusinessAccess(db, loc.business_id, req.user);
      if (!resolved?.access?.canManageBusiness) return res.sendStatus(403);

      await db.prepare("DELETE FROM locations WHERE id = ?").run(loc.id);
      await audit(db, req.user.id, "location.delete", loc.id, null, req.ip);
      res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  });

  // Services
  router.post("/businesses/:id/services", auth, businessManage, async (req, res, next) => {
    try {
      if (req.business.status === "suspended" && req.user.role !== "super_admin") {
        return res.status(403).json({ error: "Business is suspended by Super Admin" });
      }
      const { name, description, duration_minutes, price } = req.body || {};
      if (!name || !String(name).trim()) {
        return res.status(400).json({ error: "Service name required" });
      }
      const parsedDuration = duration_minutes === undefined ? 15 : Number(duration_minutes);
      if (!Number.isFinite(parsedDuration) || parsedDuration < 5 || parsedDuration > 1440) {
        return res.status(400).json({ error: "Duration must be between 5 and 1440 minutes" });
      }
      const parsedPrice = price === undefined ? 0 : Number(price);
      if (!Number.isFinite(parsedPrice) || parsedPrice < 0) {
        return res.status(400).json({ error: "Price must be a valid non-negative number" });
      }
      const cleanServiceName = String(name).trim();
      const cleanDescription = String(description || "").trim();
      if (cleanServiceName.length > 100 || cleanDescription.length > 1000) {
        return res.status(400).json({ error: "Service name or description is too long" });
      }
      const duration = Math.round(parsedDuration);
      const sid = uuid();

      await db
        .prepare(
          `INSERT INTO services (id, business_id, name, description, duration_minutes, price, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          sid,
          req.business.id,
          cleanServiceName,
          cleanDescription,
          duration,
          parsedPrice,
          new Date().toISOString()
        );
      await audit(db, req.user.id, "service.create", sid, { business_id: req.business.id }, req.ip);
      res.status(201).json({
        service: await db.prepare("SELECT * FROM services WHERE id = ?").get(sid)
      });
    } catch (e) {
      next(e);
    }
  });

  router.patch("/services/:id", auth, async (req, res, next) => {
    try {
      const s = await db.prepare("SELECT * FROM services WHERE id = ?").get(req.params.id);
      if (!s) return res.sendStatus(404);
      const resolved = await getBusinessAccess(db, s.business_id, req.user);
      if (!resolved?.access?.canManageBusiness) return res.sendStatus(403);

      const x = req.body || {};
      const nextName = x.name !== undefined ? String(x.name).trim() : s.name;
      if (!nextName) return res.status(400).json({ error: "Service name required" });
      if (nextName.length > 100) return res.status(400).json({ error: "Service name must be 100 characters or fewer" });

      let nextDuration = s.duration_minutes;
      if (x.duration_minutes !== undefined) {
        const parsed = Number(x.duration_minutes);
        if (!Number.isFinite(parsed) || parsed < 5 || parsed > 1440) {
          return res.status(400).json({ error: "Duration must be between 5 and 1440 minutes" });
        }
        nextDuration = Math.round(parsed);
      }

      let nextPrice = s.price;
      if (x.price !== undefined) {
        const parsed = Number(x.price);
        if (!Number.isFinite(parsed) || parsed < 0) {
          return res.status(400).json({ error: "Price cannot be negative" });
        }
        nextPrice = parsed;
      }

      await db
        .prepare(
          `UPDATE services
           SET name = ?, description = ?, duration_minutes = ?, price = ?, is_active = ?
           WHERE id = ?`
        )
        .run(
          nextName,
          x.description !== undefined ? String(x.description).trim().slice(0, 1000) : s.description,
          nextDuration,
          nextPrice,
          x.is_active === undefined ? s.is_active : x.is_active ? 1 : 0,
          s.id
        );
      await audit(db, req.user.id, "service.update", s.id, null, req.ip);
      res.json({
        ok: true,
        service: await db.prepare("SELECT * FROM services WHERE id = ?").get(s.id)
      });
    } catch (e) {
      next(e);
    }
  });

  router.delete("/services/:id", auth, async (req, res, next) => {
    try {
      const s = await db.prepare("SELECT * FROM services WHERE id = ?").get(req.params.id);
      if (!s) return res.sendStatus(404);
      const resolved = await getBusinessAccess(db, s.business_id, req.user);
      if (!resolved?.access?.canManageBusiness) return res.sendStatus(403);

      await db.prepare("DELETE FROM services WHERE id = ?").run(s.id);
      await audit(db, req.user.id, "service.delete", s.id, null, req.ip);
      res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  });

  // Staff
  router.post("/businesses/:id/staff", auth, businessManage, async (req, res, next) => {
    try {
      if (req.business.status === "suspended" && req.user.role !== "super_admin") {
        return res.status(403).json({ error: "Business is suspended by Super Admin" });
      }
      const { name, email, role, counter_label } = req.body || {};
      const cleanName = String(name || "").trim();
      if (!cleanName) {
        return res.status(400).json({ error: "Staff name required" });
      }
      if (cleanName.length > 100) {
        return res.status(400).json({ error: "Staff name must be 100 characters or fewer" });
      }
      const cleanEmail = String(email || "").toLowerCase().trim();
      if (cleanEmail.length > 254 || (cleanEmail && !isValidEmail(cleanEmail))) {
        return res.status(400).json({ error: "Invalid staff email" });
      }
      if (role !== undefined && !STAFF_ROLES.has(role)) {
        return res.status(400).json({ error: "Invalid staff role" });
      }
      const cleanCounter = String(counter_label || "").trim();
      if (cleanCounter.length > 50) {
        return res.status(400).json({ error: "Counter label must be 50 characters or fewer" });
      }
      const cleanRole = role || "staff";
      const linkedUser = cleanEmail
        ? await db.prepare("SELECT id FROM users WHERE email = ?").get(cleanEmail)
        : null;

      const sid = uuid();
      try {
        await db
          .prepare(
            `INSERT INTO staff (id, business_id, user_id, name, email, role, counter_label, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .run(
            sid,
            req.business.id,
            linkedUser ? linkedUser.id : null,
            cleanName,
            cleanEmail,
            cleanRole,
            cleanCounter,
            new Date().toISOString()
          );
      } catch (e) {
        if (isUniqueConstraintError(e)) {
          return res.status(400).json({ error: "Team member with this email already exists" });
        }
        throw e;
      }

      await audit(
        db,
        req.user.id,
        "staff.create",
        sid,
        { business_id: req.business.id, role: cleanRole },
        req.ip
      );
      res.status(201).json({
        staff: await db.prepare("SELECT * FROM staff WHERE id = ?").get(sid)
      });
    } catch (e) {
      next(e);
    }
  });

  router.patch("/staff/:id", auth, async (req, res, next) => {
    try {
      const s = await db.prepare("SELECT * FROM staff WHERE id = ?").get(req.params.id);
      if (!s) return res.sendStatus(404);
      const resolved = await getBusinessAccess(db, s.business_id, req.user);
      if (!resolved?.access?.canManageBusiness) return res.sendStatus(403);

      const x = req.body || {};
      const nextName = x.name !== undefined ? String(x.name).trim() : s.name;
      if (!nextName) return res.status(400).json({ error: "Staff name required" });
      if (nextName.length > 100) return res.status(400).json({ error: "Staff name must be 100 characters or fewer" });

      const nextEmail = x.email !== undefined ? String(x.email).toLowerCase().trim() : s.email;
      if (nextEmail.length > 254 || (nextEmail && !isValidEmail(nextEmail))) {
        return res.status(400).json({ error: "Invalid staff email" });
      }
      if (x.role !== undefined && !STAFF_ROLES.has(x.role)) {
        return res.status(400).json({ error: "Invalid staff role" });
      }
      const nextRole = x.role !== undefined ? x.role : s.role;
      const nextCounter = x.counter_label !== undefined ? String(x.counter_label).trim() : s.counter_label;
      if (nextCounter.length > 50) {
        return res.status(400).json({ error: "Counter label must be 50 characters or fewer" });
      }
      const nextActive = x.is_active === undefined ? s.is_active : x.is_active ? 1 : 0;
      const linkedUser = nextEmail
        ? await db.prepare("SELECT id FROM users WHERE email = ?").get(nextEmail)
        : null;

      try {
        await db
          .prepare(
            `UPDATE staff
             SET name = ?, email = ?, user_id = ?, role = ?, counter_label = ?, is_active = ?
             WHERE id = ?`
          )
          .run(
            nextName,
            nextEmail,
            linkedUser ? linkedUser.id : nextEmail === "" ? null : s.user_id,
            nextRole,
            nextCounter,
            nextActive,
            s.id
          );
      } catch (e) {
        if (isUniqueConstraintError(e)) {
          return res.status(400).json({ error: "Team member with this email already exists" });
        }
        throw e;
      }

      if (!nextActive || (s.user_id && nextEmail !== s.email)) {
        await evictBusinessSockets(io, db, s.business_id, s.user_id || null);
      }

      await audit(db, req.user.id, "staff.update", s.id, { is_active: nextActive }, req.ip);
      res.json({
        ok: true,
        staff: await db.prepare("SELECT * FROM staff WHERE id = ?").get(s.id)
      });
    } catch (e) {
      next(e);
    }
  });

  router.delete("/staff/:id", auth, async (req, res, next) => {
    try {
      const s = await db.prepare("SELECT * FROM staff WHERE id = ?").get(req.params.id);
      if (!s) return res.sendStatus(404);
      const resolved = await getBusinessAccess(db, s.business_id, req.user);
      if (!resolved?.access?.canManageBusiness) return res.sendStatus(403);

      await db.prepare("DELETE FROM staff WHERE id = ?").run(s.id);
      await evictBusinessSockets(io, db, s.business_id, s.user_id || null);
      await audit(db, req.user.id, "staff.delete", s.id, { business_id: s.business_id }, req.ip);
      res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  });

  return router;
}

module.exports = { createBusinessRouter };
