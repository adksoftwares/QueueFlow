const { v4: uuid } = require("uuid");
const crypto = require("crypto");
const { withTransaction } = require("./db");
const {
  dateStrInTimeZone,
  addDaysToDateStr,
  parseAppointmentInTimeZone
} = require("./helpers");

const ALLOWED_TRANSITIONS = {
  scheduled: new Set(["waiting", "cancelled", "no_show"]),
  waiting: new Set(["called", "serving", "completed", "no_show", "cancelled"]),
  called: new Set(["waiting", "serving", "completed", "no_show", "cancelled"]),
  serving: new Set(["waiting", "called", "completed", "no_show", "cancelled"]),
  completed: new Set(),
  no_show: new Set(),
  cancelled: new Set()
};

function canTransitionStatus(fromStatus, toStatus) {
  if (fromStatus === toStatus) return true;
  const allowed = ALLOWED_TRANSITIONS[fromStatus];
  return Boolean(allowed && allowed.has(toStatus));
}

async function getBusinessAccess(db, businessId, user) {
  const b = await db.prepare("SELECT * FROM businesses WHERE id = ?").get(businessId);
  if (!b) return null;
  if (!user || user.status !== "active") return { business: b, access: null };

  if (user.role === "super_admin") {
    return {
      business: b,
      access: {
        role: "super_admin",
        canManageBusiness: true,
        canDeleteBusiness: true,
        canOperateQueue: true
      }
    };
  }

  if (b.owner_id === user.id) {
    return {
      business: b,
      access: {
        role: "owner",
        canManageBusiness: true,
        canDeleteBusiness: true,
        canOperateQueue: true
      }
    };
  }

  const staffRow = await db
    .prepare(
      `SELECT * FROM staff
       WHERE business_id = ? AND is_active = 1
         AND (user_id = ? OR (email IS NOT NULL AND email != '' AND lower(email) = lower(?)))
       LIMIT 1`
    )
    .get(b.id, user.id, user.email || "");

  if (staffRow) {
    const isManager = staffRow.role === "manager";
    return {
      business: b,
      access: {
        role: staffRow.role || "staff",
        staffId: staffRow.id,
        canManageBusiness: isManager,
        canDeleteBusiness: false,
        canOperateQueue: true
      }
    };
  }

  return { business: b, access: null };
}

async function queue(db, businessId, locationId = null) {
  const locationClause = locationId ? "AND t.location_id = ?" : "";
  const params = locationId ? [businessId, locationId] : [businessId];

  return db
    .prepare(
      `SELECT t.*,
              s.name AS service_name,
              COALESCE(s.duration_minutes, 15) AS service_duration,
              st.name AS staff_name,
              st.counter_label AS counter_label,
              l.name AS location_name
       FROM tickets t
       LEFT JOIN services s ON s.id = t.service_id
       LEFT JOIN staff st ON st.id = t.staff_id
       LEFT JOIN locations l ON l.id = t.location_id
       WHERE t.business_id = ?
         AND t.status IN ('waiting', 'called', 'serving')
         ${locationClause}
       ORDER BY CASE t.status
                  WHEN 'serving' THEN 0
                  WHEN 'called' THEN 1
                  ELSE 2
                END,
                COALESCE(t.checked_in_at, t.created_at) ASC`
    )
    .all(...params);
}

async function recentFinishedTickets(db, businessId, timeZone = "UTC", locationId = null) {
  const today = dateStrInTimeZone(new Date(), timeZone);
  const locationClause = locationId ? "AND t.location_id = ?" : "";
  const params = locationId ? [businessId, today, locationId] : [businessId, today];

  return db
    .prepare(
      `SELECT t.*,
              s.name AS service_name,
              COALESCE(s.duration_minutes, 15) AS service_duration,
              st.name AS staff_name,
              st.counter_label AS counter_label,
              l.name AS location_name
       FROM tickets t
       LEFT JOIN services s ON s.id = t.service_id
       LEFT JOIN staff st ON st.id = t.staff_id
       LEFT JOIN locations l ON l.id = t.location_id
       WHERE t.business_id = ?
         AND t.queue_date = ?
         AND t.status IN ('completed', 'no_show', 'cancelled')
         AND t.archived_at IS NULL
         ${locationClause}
       ORDER BY COALESCE(t.completed_at, t.created_at) DESC
       LIMIT 50`
    )
    .all(...params);
}

async function scheduledAppointments(db, businessId, locationId = null) {
  const locationClause = locationId ? "AND t.location_id = ?" : "";
  const params = locationId ? [businessId, locationId] : [businessId];

  return db
    .prepare(
      `SELECT t.*,
              s.name AS service_name,
              l.name AS location_name
       FROM tickets t
       LEFT JOIN services s ON s.id = t.service_id
       LEFT JOIN locations l ON l.id = t.location_id
       WHERE t.business_id = ? AND t.status = 'scheduled' ${locationClause}
       ORDER BY t.appointment_at ASC, t.created_at ASC`
    )
    .all(...params);
}

async function stats(db, businessId, timeZone = "UTC", locationId = null) {
  const today = dateStrInTimeZone(new Date(), timeZone);
  const locationClause = locationId ? "AND location_id = ?" : "";
  const params = locationId ? [today, businessId, locationId] : [today, businessId];

  const row = await db
    .prepare(
      `SELECT
         SUM(CASE WHEN status = 'waiting' THEN 1 ELSE 0 END) AS waiting,
         SUM(CASE WHEN status = 'called' THEN 1 ELSE 0 END) AS called,
         SUM(CASE WHEN status = 'serving' THEN 1 ELSE 0 END) AS serving,
         SUM(CASE WHEN status = 'scheduled' THEN 1 ELSE 0 END) AS scheduled,
         SUM(CASE WHEN status = 'completed' AND queue_date = ? THEN 1 ELSE 0 END) AS completed
       FROM tickets
       WHERE business_id = ? ${locationClause}`
    )
    .get(...params);

  return {
    waiting: Number(row?.waiting || 0),
    called: Number(row?.called || 0),
    serving: Number(row?.serving || 0),
    scheduled: Number(row?.scheduled || 0),
    completed: Number(row?.completed || 0)
  };
}

async function performance(db, businessId, timeZone = "UTC", locationId = null) {
  const today = dateStrInTimeZone(new Date(), timeZone);
  const thirtyDaysAgo = addDaysToDateStr(today, -30);
  const locationClause = locationId ? "AND location_id = ?" : "";
  const joinLocationClause = locationId ? "AND t.location_id = ?" : "";

  const todayParams = locationId ? [businessId, today, locationId] : [businessId, today];
  const todayRow = await db
    .prepare(
      `SELECT
         SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed_today,
         SUM(CASE WHEN status = 'no_show' THEN 1 ELSE 0 END) AS no_show_today,
         SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled_today
       FROM tickets
       WHERE business_id = ? AND queue_date = ? ${locationClause}`
    )
    .get(...todayParams);

  const histParams = locationId
    ? [businessId, thirtyDaysAgo, locationId]
    : [businessId, thirtyDaysAgo];
  const completedRows = await db
    .prepare(
      `SELECT created_at, checked_in_at, called_at, started_at, completed_at
       FROM tickets
       WHERE business_id = ?
         AND status IN ('serving', 'completed')
         AND queue_date >= ?
         ${locationClause}`
    )
    .all(...histParams);

  let waitSum = 0;
  let waitCount = 0;
  let serviceSum = 0;
  let serviceCount = 0;

  for (const r of completedRows) {
    const queueEntryMs = Date.parse(r.checked_in_at || r.created_at);
    const waitEndMs = Date.parse(r.started_at || r.called_at || "");
    if (!Number.isNaN(queueEntryMs) && !Number.isNaN(waitEndMs) && waitEndMs >= queueEntryMs) {
      waitSum += (waitEndMs - queueEntryMs) / 60000;
      waitCount += 1;
    }
    const startMs = Date.parse(r.started_at || "");
    const endMs = Date.parse(r.completed_at || "");
    if (!Number.isNaN(startMs) && !Number.isNaN(endMs) && endMs >= startMs) {
      serviceSum += (endMs - startMs) / 60000;
      serviceCount += 1;
    }
  }

  const byServiceParams = locationId ? [businessId, today, locationId] : [businessId, today];
  const rawByService = await db
    .prepare(
      `SELECT
         COALESCE(s.name, 'General') AS service_name,
         COUNT(*) AS total,
         SUM(CASE WHEN t.status = 'completed' THEN 1 ELSE 0 END) AS completed,
         SUM(CASE WHEN t.status = 'waiting' THEN 1 ELSE 0 END) AS waiting
       FROM tickets t
       LEFT JOIN services s ON s.id = t.service_id
       WHERE t.business_id = ? AND t.queue_date = ? ${joinLocationClause}
       GROUP BY COALESCE(s.name, 'General')
       ORDER BY total DESC`
    )
    .all(...byServiceParams);

  const byService = rawByService.map((r) => ({
    service_name: r.service_name,
    total: Number(r.total || 0),
    completed: Number(r.completed || 0),
    waiting: Number(r.waiting || 0)
  }));

  return {
    completed_today: Number(todayRow?.completed_today || 0),
    no_show_today: Number(todayRow?.no_show_today || 0),
    cancelled_today: Number(todayRow?.cancelled_today || 0),
    avg_wait_minutes: waitCount ? Number((waitSum / waitCount).toFixed(1)) : 0,
    avg_service_minutes: serviceCount ? Number((serviceSum / serviceCount).toFixed(1)) : 0,
    by_service: byService
  };
}

async function nextTokenInTx(tx, businessId, queueDate) {
  await tx
    .prepare(
      `INSERT INTO token_counters (business_id, queue_date, last_seq)
       VALUES (?, ?, 1)
       ON CONFLICT(business_id, queue_date) DO UPDATE SET last_seq = token_counters.last_seq + 1`
    )
    .run(businessId, queueDate);

  const row = await tx
    .prepare("SELECT last_seq FROM token_counters WHERE business_id = ? AND queue_date = ?")
    .get(businessId, queueDate);

  return `Q${String(row.last_seq).padStart(3, "0")}`;
}

async function createTicket(db, b, body, source, allowStaffAssign = false) {
  const {
    service_id,
    location_id,
    staff_id,
    customer_name,
    customer_phone,
    notes,
    appointment_at
  } = body || {};

  const cleanCustomerName = String(customer_name || "").trim();
  const cleanCustomerPhone = String(customer_phone || "").trim();
  const cleanNotes = String(notes || "").trim();

  if (!cleanCustomerName) {
    return { error: "Customer name required" };
  }
  if (cleanCustomerName.length > 100) {
    return { error: "Customer name must be 100 characters or fewer" };
  }
  if (cleanCustomerPhone.length > 30) {
    return { error: "Customer phone must be 30 characters or fewer" };
  }
  if (cleanNotes.length > 500) {
    return { error: "Notes must be 500 characters or fewer" };
  }

  if (service_id) {
    const svc = await db
      .prepare("SELECT id FROM services WHERE id = ? AND business_id = ? AND is_active = 1")
      .get(service_id, b.id);
    if (!svc) return { error: "Choose a valid active service" };
  }

  if (location_id) {
    const loc = await db
      .prepare("SELECT id FROM locations WHERE id = ? AND business_id = ? AND is_active = 1")
      .get(location_id, b.id);
    if (!loc) return { error: "Choose a valid active location" };
  }

  let resolvedStaffId = null;
  if (allowStaffAssign && staff_id) {
    const member = await db
      .prepare("SELECT id FROM staff WHERE id = ? AND business_id = ? AND is_active = 1")
      .get(staff_id, b.id);
    if (!member) return { error: "Choose a valid active team member" };
    resolvedStaffId = member.id;
  }

  const tz = b.timezone || "UTC";
  const now = new Date();
  const nowIso = now.toISOString();
  let ticketStatus = "waiting";
  let ticketSource = source;
  let queueDate = dateStrInTimeZone(now, tz);
  let normalizedAppointmentAt = null;

  if (appointment_at && String(appointment_at).trim()) {
    const parsed = parseAppointmentInTimeZone(appointment_at, tz);
    if (!parsed) {
      return { error: "Invalid appointment date/time" };
    }
    normalizedAppointmentAt = parsed.toISOString();
    if (parsed.getTime() > now.getTime() + 15 * 60000) {
      ticketStatus = "scheduled";
      ticketSource = "appointment";
      queueDate = dateStrInTimeZone(parsed, tz);
    }
  }

  const tid = uuid();
  const lookupKey = crypto.randomBytes(32).toString("base64url");
  const lookupKeyHash = crypto.createHash("sha256").update(lookupKey).digest("hex");
  const ticket = await withTransaction(db, async (tx) => {
    const token = await nextTokenInTx(tx, b.id, queueDate);
    await tx
      .prepare(
        `INSERT INTO tickets (
           id, business_id, location_id, service_id, staff_id,
           token, lookup_key_hash, queue_date, customer_name, customer_phone, notes,
           status, source, appointment_at, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        tid,
        b.id,
        location_id || null,
        service_id || null,
        resolvedStaffId,
        token,
        lookupKeyHash,
        queueDate,
        cleanCustomerName,
        cleanCustomerPhone,
        cleanNotes,
        ticketStatus,
        ticketSource,
        normalizedAppointmentAt,
        nowIso
      );
    return tx.prepare("SELECT * FROM tickets WHERE id = ?").get(tid);
  });

  return { ticket, lookupKey };
}

async function emitBusinessUpdate(io, db, businessId) {
  const b = await db.prepare("SELECT id, timezone FROM businesses WHERE id = ?").get(businessId);
  if (!b) return;
  const tz = b.timezone || "UTC";
  const [full, currentStats, appointments, recent, perf] = await Promise.all([
    queue(db, businessId),
    stats(db, businessId, tz),
    scheduledAppointments(db, businessId),
    recentFinishedTickets(db, businessId, tz),
    performance(db, businessId, tz)
  ]);

  io.to(`business:${businessId}`).emit("queue:update", {
    business_id: businessId,
    tickets: full,
    appointments,
    recent_tickets: recent,
    stats: currentStats,
    performance: perf
  });

  io.to(`public:${businessId}`).emit("queue:update", {
    business_id: businessId,
    tickets: full.map((t) => ({
      token: t.token,
      status: t.status,
      service_name: t.service_name,
      staff_name: t.staff_name,
      counter_label: t.counter_label,
      location_id: t.location_id,
      location_name: t.location_name
    })),
    stats: currentStats
  });
}

async function evictBusinessSockets(io, db, businessId, onlyUserId = null) {
  const roomName = `business:${businessId}`;
  const room = io.sockets.adapter.rooms.get(roomName);
  if (!room) return;

  for (const socketId of Array.from(room)) {
    const sock = io.sockets.sockets.get(socketId);
    if (!sock) continue;

    const uid = sock.data?.userId;
    if (onlyUserId && uid !== onlyUserId) continue;

    const u = uid ? await db.prepare("SELECT * FROM users WHERE id = ?").get(uid) : null;
    const resolved = await getBusinessAccess(db, businessId, u);
    const allowed =
      resolved &&
      resolved.access?.canOperateQueue &&
      (resolved.business.status !== "suspended" || u?.role === "super_admin");

    if (!allowed) {
      sock.emit("business:revoked", { business_id: businessId });
      sock.leave(roomName);
    }
  }
}

function evictUserSockets(io, userId) {
  if (!io || !userId) return;
  for (const [, sock] of io.sockets.sockets) {
    if (sock.data?.userId === userId) {
      sock.emit("session:revoked", { reason: "Session revoked by administrator" });
      for (const room of Array.from(sock.rooms)) {
        if (room.startsWith("business:")) {
          sock.leave(room);
        }
      }
      sock.disconnect(true);
    }
  }
}

module.exports = {
  ALLOWED_TRANSITIONS,
  canTransitionStatus,
  getBusinessAccess,
  queue,
  recentFinishedTickets,
  scheduledAppointments,
  stats,
  performance,
  nextTokenInTx,
  createTicket,
  emitBusinessUpdate,
  evictBusinessSockets,
  evictUserSockets
};
