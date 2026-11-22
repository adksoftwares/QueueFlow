const express = require("express");
const QRCode = require("qrcode");
const { dateStrInTimeZone, sha256Hex } = require("../helpers");
const { queue, stats, createTicket, emitBusinessUpdate } = require("../queue-service");

function buildPublicShortUrl(req, code, locationId = "") {
  const host = req.get("host");
  const basePath = `/q/${encodeURIComponent(code)}`;
  const pathWithLoc = locationId
    ? `${basePath}?location_id=${encodeURIComponent(locationId)}`
    : basePath;
  return host ? `${req.protocol}://${host}${pathWithLoc}` : pathWithLoc;
}

function createPublicRouter({ db, io, middleware, maybeRateLimit }) {
  const router = express.Router();
  const { byCode } = middleware;

  async function serveQr(req, res, format) {
    const code = req.business.public_code;
    const locationId = req.query.location_id ? String(req.query.location_id).trim() : "";
    if (locationId) {
      const loc = await db
        .prepare("SELECT id FROM locations WHERE id = ? AND business_id = ? AND is_active = 1")
        .get(locationId, req.business.id);
      if (!loc) return res.status(400).json({ error: "Invalid location" });
    }

    const targetUrl = buildPublicShortUrl(req, code, locationId);
    const qrOpts = {
      margin: 2,
      errorCorrectionLevel: "M",
      color: { dark: "#132328", light: "#ffffff" }
    };
    const isDownload = req.query.download === "1";

    if (format === "png") {
      const buf = await QRCode.toBuffer(targetUrl, { ...qrOpts, type: "png", width: 800 });
      res.setHeader("Content-Type", "image/png");
      if (isDownload) {
        res.setHeader(
          "Content-Disposition",
          `attachment; filename="queueflow-${code.toLowerCase()}-qr.png"`
        );
      }
      return res.send(buf);
    }

    const svg = await QRCode.toString(targetUrl, { ...qrOpts, type: "svg", width: 320 });
    res.setHeader("Content-Type", "image/svg+xml; charset=utf-8");
    if (isDownload) {
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="queueflow-${code.toLowerCase()}-qr.svg"`
      );
    }
    return res.send(svg);
  }

  router.get("/:code/qr.svg", byCode, async (req, res, next) => {
    try {
      await serveQr(req, res, "svg");
    } catch (e) {
      next(e);
    }
  });

  router.get("/:code/qr.png", byCode, async (req, res, next) => {
    try {
      await serveQr(req, res, "png");
    } catch (e) {
      next(e);
    }
  });

  router.get("/:code", byCode, async (req, res, next) => {
    try {
      const bid = req.business.id;
      const tz = req.business.timezone || "UTC";
      const locationId = req.query.location_id ? String(req.query.location_id).trim() : null;

      if (locationId) {
        const loc = await db
          .prepare("SELECT id FROM locations WHERE id = ? AND business_id = ? AND is_active = 1")
          .get(locationId, bid);
        if (!loc) return res.status(400).json({ error: "Invalid location" });
      }

      const [locations, services, qList, bStats] = await Promise.all([
        db
          .prepare("SELECT id, name, address, phone FROM locations WHERE business_id = ? AND is_active = 1")
          .all(bid),
        db
          .prepare(
            "SELECT id, name, description, duration_minutes, price FROM services WHERE business_id = ? AND is_active = 1"
          )
          .all(bid),
        queue(db, bid, locationId),
        stats(db, bid, tz, locationId)
      ]);

      res.json({
        business: {
          name: req.business.name,
          category: req.business.category,
          description: req.business.description,
          address: req.business.address,
          phone: req.business.phone,
          timezone: tz,
          public_code: req.business.public_code
        },
        locations,
        services,
        queue: qList.map((t) => ({
          token: t.token,
          status: t.status,
          service_name: t.service_name,
          staff_name: t.staff_name,
          counter_label: t.counter_label,
          location_id: t.location_id,
          location_name: t.location_name
        })),
        stats: bStats
      });
    } catch (e) {
      next(e);
    }
  });

  router.post(
    "/:code/tickets",
    maybeRateLimit({ windowMs: 60000, limit: 10 }),
    byCode,
    async (req, res, next) => {
      try {
        const t = await createTicket(db, req.business, req.body, "online", false);
        if (t.error) return res.status(400).json({ error: t.error });
        await emitBusinessUpdate(io, db, req.business.id);
        res.status(201).json({
          ticket: {
            token: t.ticket.token,
            lookup_key: t.lookupKey,
            status: t.ticket.status,
            queue_date: t.ticket.queue_date,
            location_id: t.ticket.location_id,
            appointment_at: t.ticket.appointment_at,
            created_at: t.ticket.created_at
          }
        });
      } catch (e) {
        next(e);
      }
    }
  );

  router.get(
    "/:code/tickets/:token",
    maybeRateLimit({ windowMs: 60000, limit: 60 }),
    byCode,
    async (req, res, next) => {
      try {
        const token = String(req.params.token || "").trim().toUpperCase();
        const lookupKey = String(req.get("x-ticket-lookup-key") || "").trim();
        // Ticket tracking keys are generated as 32 random bytes encoded in base64url (43 chars).
        // Keep the validation strict to avoid unnecessary hash/database work on malformed input.
        if (!/^[A-Z0-9_-]{3,24}$/.test(token) || !/^[A-Za-z0-9_-]{43}$/.test(lookupKey)) {
          res.setHeader("Cache-Control", "no-store");
          res.setHeader("Referrer-Policy", "no-referrer");
          return res.status(404).json({ error: "Token not found" });
        }
        res.setHeader("Cache-Control", "no-store");
        res.setHeader("Referrer-Policy", "no-referrer");
        const lookupKeyHash = sha256Hex(lookupKey);
        const tz = req.business.timezone || "UTC";
        const today = dateStrInTimeZone(new Date(), tz);

        const t = await db
          .prepare(
            `SELECT t.id, t.token, t.status, t.queue_date, t.location_id, t.created_at, t.appointment_at,
                    s.name AS service_name,
                    st.name AS staff_name,
                    st.counter_label AS counter_label,
                    l.name AS location_name
             FROM tickets t
             LEFT JOIN services s ON s.id = t.service_id
             LEFT JOIN staff st ON st.id = t.staff_id
             LEFT JOIN locations l ON l.id = t.location_id
             WHERE t.business_id = ? AND UPPER(t.token) = ? AND t.lookup_key_hash = ?
             ORDER BY CASE WHEN t.queue_date = ? THEN 0 ELSE 1 END, t.created_at DESC
             LIMIT 1`
          )
          .get(req.business.id, token, lookupKeyHash, today);

        if (!t) return res.status(404).json({ error: "Token not found" });

        const queueSnapshot = await queue(db, req.business.id, t.location_id || null);
        const scopedQueue = queueSnapshot.filter(
          (q) => (q.location_id || null) === (t.location_id || null)
        );

        let positionAhead = null;
        let ticketsAhead = null;
        let estimatedWaitMinutes = null;
        if (t.status === "waiting") {
          const idx = scopedQueue.findIndex((q) => q.id === t.id);
          if (idx >= 0) {
            const ahead = scopedQueue.slice(0, idx);
            ticketsAhead = ahead.length;
            positionAhead = ahead.filter((q) => q.status === "waiting").length;
            estimatedWaitMinutes = ahead.reduce(
              (sum, q) => sum + Number(q.service_duration || 15),
              0
            );
          }
        }

        const activeTicket = scopedQueue.find(
          (q) => q.id !== t.id && (q.status === "serving" || q.status === "called")
        );

        res.json({
          ticket: {
            token: t.token,
            status: t.status,
            queue_date: t.queue_date,
            service_name: t.service_name,
            staff_name: t.staff_name,
            counter_label: t.counter_label,
            location_id: t.location_id,
            location_name: t.location_name,
            position_ahead: positionAhead,
            tickets_ahead: ticketsAhead,
            estimated_wait_minutes: estimatedWaitMinutes,
            alert_30m:
              t.status === "waiting" &&
              ticketsAhead !== null &&
              ticketsAhead > 0 &&
              estimatedWaitMinutes <= 30,
            is_next: t.status === "waiting" && positionAhead === 0,
            current_active: activeTicket
              ? {
                  token: activeTicket.token,
                  status: activeTicket.status,
                  counter_label: activeTicket.counter_label || null,
                  staff_name: activeTicket.staff_name || null
                }
              : null,
            appointment_at: t.appointment_at,
            created_at: t.created_at
          }
        });
      } catch (e) {
        next(e);
      }
    }
  );

  return router;
}

module.exports = { createPublicRouter };
