const path = require("path");
const express = require("express");
const http = require("http");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const { v4: uuid } = require("uuid");
const { Server } = require("socket.io");

const { initDatabase } = require("./db");
const { SQLiteSessionStore, PGSessionStore } = require("./session-store");
const {
  resolveSessionSecret,
  parseTrustProxy,
  dateStrInTimeZone,
  touchUserSession,
  isValidEmail,
  audit
} = require("./helpers");
const { getBusinessAccess } = require("./queue-service");
const { createAuthRouter } = require("./routes/auth");
const { createBusinessRouter } = require("./routes/businesses");
const { createTicketRouter } = require("./routes/tickets");
const { createPublicRouter } = require("./routes/public");
const { createSuperAdminRouter } = require("./routes/super-admin");

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

function createOriginGuard() {
  return (req, res, next) => {
    if (SAFE_METHODS.has(req.method)) return next();

    const host = req.get("host");
    const origin = req.get("origin");
    if (origin) {
      try {
        if (new URL(origin).host !== host) {
          return res.status(403).json({ error: "Cross-origin request blocked" });
        }
      } catch {
        return res.status(403).json({ error: "Invalid Origin header" });
      }
      return next();
    }

    const referer = req.get("referer");
    if (referer) {
      try {
        if (new URL(referer).host !== host) {
          return res.status(403).json({ error: "Cross-origin referer blocked" });
        }
      } catch {
        return res.status(403).json({ error: "Invalid Referer header" });
      }
    }

    next();
  };
}

async function bootstrapInitialSuperAdmin(db, envConfig = {}) {
  const email = String(envConfig.email ?? process.env.SUPER_ADMIN_EMAIL ?? "")
    .toLowerCase()
    .trim();
  const password = String(envConfig.password ?? process.env.SUPER_ADMIN_PASSWORD ?? "");
  const name =
    String(envConfig.name ?? process.env.SUPER_ADMIN_NAME ?? "Platform Owner").trim() ||
    "Platform Owner";

  if (!email || !password) return false;
  if (!isValidEmail(email) || password.length < 6) return false;

  const existingRow = await db
    .prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'super_admin'")
    .get();
  if (Number(existingRow?.n || 0) > 0) return false;

  const conflict = await db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (conflict) return false;

  const uid = uuid();
  const nowIso = new Date().toISOString();
  const hash = await bcrypt.hash(password, 12);

  await db
    .prepare(
      `INSERT INTO users (
         id, name, email, password_hash, role, status,
         privacy_notice_accepted_at, updated_at, created_at
       ) VALUES (?, ?, ?, ?, 'super_admin', 'active', ?, ?, ?)`
    )
    .run(uid, name, email, hash, nowIso, nowIso, nowIso);

  await audit(
    db,
    uid,
    "super_admin.env_bootstrap",
    uid,
    { email },
    "system",
    "super_admin",
    "user",
    "env-bootstrap"
  );
  return true;
}

function createApp(options = {}) {
  const rootDir = options.rootDir || path.resolve(__dirname, "..");
  const storageDir = options.storageDir || path.join(rootDir, "storage");
  const publicDir = options.publicDir || path.join(rootDir, "public");

  const sessionSecret = resolveSessionSecret(options.sessionSecret, storageDir);

  const db = initDatabase({
    storageDir,
    connectionString: options.connectionString,
    sqliteOnly: options.sqliteOnly
  });

  const defaultPruneMs = process.env.VERCEL ? 0 : 900000;
  const sessionStore =
    db.kind === "postgres"
      ? new PGSessionStore({
          pool: db.pool,
          ensureReady: () => db.ensureReady(),
          pruneIntervalMs: options.pruneIntervalMs ?? defaultPruneMs
        })
      : new SQLiteSessionStore({
          dir: storageDir,
          db: "sessions.sqlite",
          pruneIntervalMs: options.pruneIntervalMs ?? defaultPruneMs
        });

  let bootDone = false;
  let bootInFlight = null;
  function ensureAppReady() {
    if (bootDone) return Promise.resolve();
    if (bootInFlight) return bootInFlight;
    bootInFlight = (async () => {
      await db.ensureReady();
      if (!options.skipEnvSuperAdminBootstrap) {
        await bootstrapInitialSuperAdmin(db, options.bootstrapSuperAdmin);
      }
      bootDone = true;
    })().finally(() => {
      bootInFlight = null;
    });
    return bootInFlight;
  }

  const app = express();
  const server = http.createServer(app);
  const io = new Server(server);

  const defaultTrustProxy =
    process.env.TRUST_PROXY !== undefined
      ? process.env.TRUST_PROXY
      : process.env.VERCEL
      ? "1"
      : undefined;

  app.set(
    "trust proxy",
    parseTrustProxy(options.trustProxy !== undefined ? options.trustProxy : defaultTrustProxy)
  );

  const isProd = process.env.NODE_ENV === "production";
  const cspDirectives = {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "https://fonts.googleapis.com"],
    fontSrc: ["'self'", "https://fonts.gstatic.com"],
    connectSrc: ["'self'", "ws:", "wss:"],
    imgSrc: ["'self'", "data:"],
    objectSrc: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    frameAncestors: ["'none'"]
  };
  if (!isProd) {
    cspDirectives.upgradeInsecureRequests = null;
  }

  app.use(
    helmet({
      strictTransportSecurity: isProd,
      contentSecurityPolicy: {
        directives: cspDirectives
      }
    })
  );
  app.use(compression());
  app.use(express.json({ limit: "1mb" }));
  app.use(express.urlencoded({ extended: false }));
  app.use(express.static(publicDir));

  app.use(async (req, res, next) => {
    try {
      await ensureAppReady();
      next();
    } catch (e) {
      next(e);
    }
  });

  const sessionMiddleware = session({
    name: "connect.sid",
    store: sessionStore,
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: isProd ? "auto" : false,
      maxAge: 7 * 86400000
    }
  });

  app.use(sessionMiddleware);
  io.engine.use(sessionMiddleware);

  const maybeRateLimit = (cfg) =>
    options.disableRateLimit ? (req, res, next) => next() : rateLimit(cfg);

  app.use("/api/", (req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    next();
  });

  app.use(
    "/api/",
    maybeRateLimit({
      windowMs: 900000,
      limit: 500,
      standardHeaders: true,
      legacyHeaders: false
    })
  );
  app.use("/api/", createOriginGuard());

  // Shared auth & access middleware
  const getSessionUser = async (req) => {
    if (!req.session?.userId) return null;
    const u = (await db.prepare("SELECT * FROM users WHERE id = ?").get(req.session.userId)) || null;
    if (!u || u.status !== "active") return null;

    const sessRow = await db
      .prepare("SELECT revoked_at FROM user_sessions WHERE sid = ?")
      .get(req.sessionID);
    if (sessRow?.revoked_at) return null;

    if (u.role === "super_admin" && u.mfa_enabled && !req.session.mfaVerified) {
      return null;
    }
    return u;
  };

  const authBasic = async (req, res, next) => {
    try {
      const u = await getSessionUser(req);
      if (!u) {
        return res.status(401).json({ error: "Sign in required" });
      }
      await touchUserSession(db, req.sessionID);
      req.user = u;
      next();
    } catch (e) {
      next(e);
    }
  };

  const auth = async (req, res, next) => {
    try {
      const u = await getSessionUser(req);
      if (!u) {
        return res.status(401).json({ error: "Sign in required" });
      }
      await touchUserSession(db, req.sessionID);
      if (u.must_change_password) {
        return res.status(403).json({
          error: "Password change required before continuing",
          code: "PASSWORD_CHANGE_REQUIRED"
        });
      }
      req.user = u;
      next();
    } catch (e) {
      next(e);
    }
  };

  const superAdmin = (req, res, next) =>
    req.user.role === "super_admin"
      ? next()
      : res.status(403).json({ error: "Super Admin access required" });

  const businessOperate = async (req, res, next) => {
    try {
      const resolved = await getBusinessAccess(db, req.params.id, req.user);
      if (!resolved) return res.sendStatus(404);
      if (!resolved.access?.canOperateQueue) return res.sendStatus(403);
      req.business = resolved.business;
      req.businessAccess = resolved.access;
      next();
    } catch (e) {
      next(e);
    }
  };

  const businessManage = async (req, res, next) => {
    try {
      const resolved = await getBusinessAccess(db, req.params.id, req.user);
      if (!resolved) return res.sendStatus(404);
      if (!resolved.access?.canManageBusiness) return res.sendStatus(403);
      req.business = resolved.business;
      req.businessAccess = resolved.access;
      next();
    } catch (e) {
      next(e);
    }
  };

  const businessOwnerOrAdmin = async (req, res, next) => {
    try {
      const resolved = await getBusinessAccess(db, req.params.id, req.user);
      if (!resolved) return res.sendStatus(404);
      if (!resolved.access?.canDeleteBusiness) return res.sendStatus(403);
      req.business = resolved.business;
      req.businessAccess = resolved.access;
      next();
    } catch (e) {
      next(e);
    }
  };

  const byCode = async (req, res, next) => {
    try {
      const code = String(req.params.code || "").trim().toUpperCase();
      const b = await db
        .prepare("SELECT * FROM businesses WHERE public_code = ? AND status = 'active'")
        .get(code);
      if (!b) return res.status(404).json({ error: "Business unavailable" });
      req.business = b;
      next();
    } catch (e) {
      next(e);
    }
  };

  const allowAdditionalSuperAdmins =
    options.allowAdditionalSuperAdmins !== undefined
      ? Boolean(options.allowAdditionalSuperAdmins)
      : process.env.ALLOW_ADDITIONAL_SUPER_ADMINS === "true";

  const middleware = {
    auth,
    authBasic,
    superAdmin,
    businessOperate,
    businessManage,
    businessOwnerOrAdmin,
    byCode
  };

  app.get("/", (req, res) => {
    res.sendFile(path.join(publicDir, "index.html"));
  });

  app.get("/q/:code", (req, res) => {
    const code = String(req.params.code || "").trim().toUpperCase();
    if (!/^[A-Z0-9_-]{3,24}$/.test(code)) {
      return res.redirect("/");
    }
    const qs = new URLSearchParams({ code });
    const loc = req.query.location_id ? String(req.query.location_id).trim() : "";
    if (loc) qs.set("location_id", loc);
    res.redirect(302, `/queue.html?${qs.toString()}`);
  });

  app.get("/api/health", (req, res) =>
    res.json({ ok: true, service: "QueueFlow", version: "2.0.0", database: db.kind })
  );

  app.use("/api/auth", createAuthRouter({ db, middleware: { auth: authBasic }, maybeRateLimit }));
  app.use("/api", createBusinessRouter({ db, io, middleware }));
  app.use("/api", createTicketRouter({ db, io, middleware }));
  app.use("/api/public", createPublicRouter({ db, io, middleware, maybeRateLimit }));
  app.use(
    "/api/super-admin",
    createSuperAdminRouter({
      db,
      io,
      sessionStore,
      middleware,
      allowAdditionalSuperAdmins
    })
  );

  io.on("connection", (socket) => {
    socket.on("join-business", async (bid) => {
      try {
        await ensureAppReady();
        const uid = socket.request.session?.userId;
        const sid = socket.request.sessionID;
        const u = uid ? await db.prepare("SELECT * FROM users WHERE id = ?").get(uid) : null;
        if (!u || u.status !== "active") return;
        if (u.role === "super_admin" && u.mfa_enabled && !socket.request.session?.mfaVerified) {
          return;
        }
        const sessRow = sid
          ? await db.prepare("SELECT revoked_at FROM user_sessions WHERE sid = ?").get(sid)
          : null;
        if (sessRow?.revoked_at) return;

        const resolved = await getBusinessAccess(db, bid, u);
        const allowed =
          resolved &&
          resolved.access?.canOperateQueue &&
          (resolved.business.status !== "suspended" || u.role === "super_admin");

        if (allowed) {
          socket.data.userId = u.id;
          socket.join(`business:${resolved.business.id}`);
        }
      } catch {
        // Ignore socket auth errors
      }
    });

    socket.on("leave-business", (bid) => {
      if (bid) socket.leave(`business:${bid}`);
    });

    socket.on("join-public", async (code) => {
      try {
        await ensureAppReady();
        const b = await db
          .prepare("SELECT id FROM businesses WHERE public_code = ? AND status = 'active'")
          .get(String(code || "").trim().toUpperCase());
        if (b) socket.join(`public:${b.id}`);
      } catch {
        // ignore
      }
    });
  });

  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: "Unexpected server error" });
  });

  async function close() {
    if (bootInFlight) await bootInFlight.catch(() => {});
    await new Promise((resolve) => {
      io.close(() => {
        server.close(() => resolve());
      });
    });
    await sessionStore.close();
    await db.close();
  }

  return {
    app,
    server,
    io,
    db,
    sessionStore,
    ensureReady: ensureAppReady,
    get ready() {
      return ensureAppReady();
    },
    close
  };
}

module.exports = { createApp, todayDateStr: dateStrInTimeZone };
