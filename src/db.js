const fs = require("fs");
const path = require("path");
const { DatabaseSync } = require("node:sqlite");

function isUniqueConstraintError(err) {
  return err?.code === "23505" || /UNIQUE/i.test(String(err?.message || ""));
}

function isTransientPgError(err) {
  const code = String(err?.code || "");
  const msg = String(err?.message || "");
  return (
    code === "08P01" ||
    code === "08006" ||
    code === "08003" ||
    code === "57P01" ||
    code === "57P03" ||
    code === "ETIMEDOUT" ||
    code === "ECONNRESET" ||
    code === "ECONNREFUSED" ||
    /Authentication timed out|Connection terminated|timeout expired/i.test(msg)
  );
}

async function pgRetry(fn, attempts = 3) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (i >= attempts - 1 || !isTransientPgError(err)) throw err;
      await new Promise((r) => setTimeout(r, 350 * (i + 1)));
    }
  }
  throw lastErr;
}

function translateSqlPlaceholders(sql) {
  let out = "";
  let idx = 0;
  let inSingleQuote = false;
  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    if (ch === "'") {
      out += ch;
      if (inSingleQuote && sql[i + 1] === "'") {
        out += "'";
        i++;
      } else {
        inSingleQuote = !inSingleQuote;
      }
      continue;
    }
    if (ch === "?" && !inSingleQuote) {
      idx += 1;
      out += `$${idx}`;
      continue;
    }
    out += ch;
  }
  return out;
}

const CORE_SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'owner',
    phone TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    suspended_at TEXT,
    suspension_reason TEXT,
    deleted_at TEXT,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    mfa_secret TEXT,
    mfa_recovery_hashes TEXT,
    last_login_at TEXT,
    last_login_ip TEXT,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    privacy_notice_accepted_at TEXT,
    updated_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS businesses (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    category TEXT,
    description TEXT,
    address TEXT,
    phone TEXT,
    timezone TEXT DEFAULT 'UTC',
    public_code TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'active',
    plan TEXT DEFAULT 'starter',
    suspended_at TEXT,
    suspension_reason TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS locations (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    address TEXT,
    phone TEXT,
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    duration_minutes INTEGER DEFAULT 15,
    price REAL DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS staff (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'staff',
    counter_label TEXT,
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS token_counters (
    business_id TEXT NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
    queue_date TEXT NOT NULL,
    last_seq INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (business_id, queue_date)
  );

  CREATE TABLE IF NOT EXISTS tickets (
    id TEXT PRIMARY KEY,
    business_id TEXT NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
    location_id TEXT REFERENCES locations(id) ON DELETE SET NULL,
    service_id TEXT REFERENCES services(id) ON DELETE SET NULL,
    staff_id TEXT REFERENCES staff(id) ON DELETE SET NULL,
    token TEXT NOT NULL,
    lookup_key_hash TEXT NOT NULL DEFAULT '',
    queue_date TEXT NOT NULL DEFAULT '',
    customer_name TEXT NOT NULL,
    customer_phone TEXT,
    notes TEXT,
    status TEXT DEFAULT 'waiting',
    source TEXT DEFAULT 'walkin',
    appointment_at TEXT,
    checked_in_at TEXT,
    called_at TEXT,
    started_at TEXT,
    completed_at TEXT,
    archived_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS user_sessions (
    sid TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip TEXT,
    user_agent TEXT,
    device_info TEXT,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    logout_at TEXT,
    revoked_at TEXT,
    revoked_by TEXT
  );

  CREATE TABLE IF NOT EXISTS login_events (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    email TEXT,
    event_type TEXT NOT NULL,
    success INTEGER NOT NULL DEFAULT 0,
    ip TEXT,
    user_agent TEXT,
    device_info TEXT,
    session_id TEXT,
    details TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS password_resets (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE NOT NULL,
    created_by_user_id TEXT,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    actor_role TEXT,
    action TEXT,
    target_type TEXT,
    entity_id TEXT,
    details TEXT,
    ip TEXT,
    user_agent TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_ticket_queue ON tickets(business_id, status, created_at);
  CREATE INDEX IF NOT EXISTS idx_business_owner ON businesses(owner_id);
`;

const POST_MIGRATION_SQL = `
  UPDATE users SET role = 'super_admin' WHERE role = 'admin';
  UPDATE tickets
  SET queue_date = substr(created_at, 1, 10)
  WHERE queue_date = '' AND created_at IS NOT NULL AND length(created_at) >= 10;

  CREATE UNIQUE INDEX IF NOT EXISTS idx_ticket_daily_token ON tickets(business_id, queue_date, token);
  CREATE INDEX IF NOT EXISTS idx_ticket_lookup_hash ON tickets(business_id, lookup_key_hash);
  CREATE INDEX IF NOT EXISTS idx_ticket_date ON tickets(business_id, queue_date, status);
  CREATE INDEX IF NOT EXISTS idx_ticket_location ON tickets(business_id, location_id, status);
  CREATE INDEX IF NOT EXISTS idx_staff_email ON staff(email);
  CREATE UNIQUE INDEX IF NOT EXISTS idx_staff_business_email
    ON staff(business_id, lower(email))
    WHERE email IS NOT NULL AND email != '';
  CREATE UNIQUE INDEX IF NOT EXISTS idx_staff_business_user
    ON staff(business_id, user_id)
    WHERE user_id IS NOT NULL;
  CREATE INDEX IF NOT EXISTS idx_locations_business ON locations(business_id);
  CREATE INDEX IF NOT EXISTS idx_users_role_status ON users(role, status);
  CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id, revoked_at, logout_at);
  CREATE INDEX IF NOT EXISTS idx_login_events_created ON login_events(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_login_events_user ON login_events(user_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);
`;

const MIGRATIONS = [
  ["users", "status", "TEXT NOT NULL DEFAULT 'active'"],
  ["users", "suspended_at", "TEXT"],
  ["users", "suspension_reason", "TEXT"],
  ["users", "deleted_at", "TEXT"],
  ["users", "must_change_password", "INTEGER NOT NULL DEFAULT 0"],
  ["users", "mfa_enabled", "INTEGER NOT NULL DEFAULT 0"],
  ["users", "mfa_secret", "TEXT"],
  ["users", "mfa_recovery_hashes", "TEXT"],
  ["users", "last_login_at", "TEXT"],
  ["users", "last_login_ip", "TEXT"],
  ["users", "failed_login_count", "INTEGER NOT NULL DEFAULT 0"],
  ["users", "locked_until", "TEXT"],
  ["users", "privacy_notice_accepted_at", "TEXT"],
  ["users", "updated_at", "TEXT"],
  ["businesses", "timezone", "TEXT DEFAULT 'UTC'"],
  ["businesses", "plan", "TEXT DEFAULT 'starter'"],
  ["businesses", "suspended_at", "TEXT"],
  ["businesses", "suspension_reason", "TEXT"],
  ["staff", "user_id", "TEXT REFERENCES users(id) ON DELETE SET NULL"],
  ["staff", "counter_label", "TEXT"],
  ["tickets", "location_id", "TEXT REFERENCES locations(id) ON DELETE SET NULL"],
  ["tickets", "lookup_key_hash", "TEXT NOT NULL DEFAULT ''"],
  ["tickets", "queue_date", "TEXT NOT NULL DEFAULT ''"],
  ["tickets", "checked_in_at", "TEXT"],
  ["tickets", "archived_at", "TEXT"],
  ["audit_logs", "actor_role", "TEXT"],
  ["audit_logs", "target_type", "TEXT"],
  ["audit_logs", "details", "TEXT"],
  ["audit_logs", "user_agent", "TEXT"]
];

function hasSqliteColumn(sqliteDb, table, column) {
  const cols = sqliteDb.prepare(`PRAGMA table_info(${table})`).all();
  return cols.some((c) => c.name === column);
}

function createSqliteAdapter(storageDir) {
  fs.mkdirSync(storageDir, { recursive: true });
  const dbPath = path.join(storageDir, "queueflow.sqlite");
  const sqliteDb = new DatabaseSync(dbPath);
  sqliteDb.exec("PRAGMA journal_mode = WAL;");
  sqliteDb.exec("PRAGMA foreign_keys = ON;");
  sqliteDb.exec("PRAGMA busy_timeout = 5000;");
  sqliteDb.exec(CORE_SCHEMA_SQL);

  for (const [table, column, definition] of MIGRATIONS) {
    if (!hasSqliteColumn(sqliteDb, table, column)) {
      sqliteDb.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
    }
  }
  sqliteDb.exec(POST_MIGRATION_SQL);

  let txQueue = Promise.resolve();

  const adapter = {
    kind: "sqlite",
    ready: Promise.resolve(),
    ensureReady: () => Promise.resolve(),
    prepare(sql) {
      const stmt = sqliteDb.prepare(sql);
      return {
        get: async (...params) => stmt.get(...params),
        all: async (...params) => stmt.all(...params),
        run: async (...params) => stmt.run(...params)
      };
    },
    async exec(sql) {
      sqliteDb.exec(sql);
    },
    transaction(fn) {
      const run = async () => {
        sqliteDb.exec("BEGIN IMMEDIATE");
        try {
          const result = await fn(adapter);
          sqliteDb.exec("COMMIT");
          return result;
        } catch (err) {
          try {
            sqliteDb.exec("ROLLBACK");
          } catch {
            // Ignore rollback errors if transaction already aborted
          }
          throw err;
        }
      };
      const next = txQueue.then(run, run);
      txQueue = next.catch(() => {});
      return next;
    },
    async close() {
      sqliteDb.close();
    }
  };

  return adapter;
}

function wrapPgQueryable(queryable, sql, allowRetry = false) {
  const pgSql = translateSqlPlaceholders(sql);
  const execQuery = (params) =>
    allowRetry
      ? pgRetry(() => queryable.query(pgSql, params), 2)
      : queryable.query(pgSql, params);
  return {
    get: async (...params) => {
      const r = await execQuery(params);
      return r.rows[0];
    },
    all: async (...params) => {
      const r = await execQuery(params);
      return r.rows;
    },
    run: async (...params) => {
      const r = await execQuery(params);
      return { changes: r.rowCount || 0 };
    }
  };
}

const PG_SCHEMA_VERSION = 3;

const PG_SESSION_DDL = `
  CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    sess TEXT NOT NULL,
    expired BIGINT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_expired ON sessions(expired);
  CREATE TABLE IF NOT EXISTS schema_meta (
    id INTEGER PRIMARY KEY,
    version INTEGER NOT NULL
  );
`;

function createPostgresAdapter(connectionString) {
  const { Pool } = require("pg");
  const pool = new Pool({
    connectionString,
    max: 5,
    idleTimeoutMillis: 10000,
    connectionTimeoutMillis: 15000,
    keepAlive: true
  });
  pool.on("error", (err) => {
    console.error("PG pool idle client error:", err.message);
  });

  const alterSql = MIGRATIONS.map(
    ([table, column, definition]) =>
      `ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS ${column} ${definition};`
  ).join("\n");

  let readyDone = false;
  let readyInFlight = null;

  function ensureReady() {
    if (readyDone) return Promise.resolve();
    if (readyInFlight) return readyInFlight;
    readyInFlight = (async () => {
      await pgRetry(async () => {
        const reg = await pool.query(
          "SELECT to_regclass('public.schema_meta') AS m, to_regclass('public.sessions') AS s, to_regclass('public.users') AS u"
        );
        const row = reg.rows[0] || {};
        if (row.m && row.s && row.u) {
          const verRes = await pool.query("SELECT version FROM schema_meta WHERE id = 1");
          if (Number(verRes.rows[0]?.version || 0) >= PG_SCHEMA_VERSION) {
            return;
          }
        }
        await pool.query(CORE_SCHEMA_SQL);
        await pool.query(PG_SESSION_DDL);
        await pool.query(alterSql);
        await pool.query(POST_MIGRATION_SQL);
        await pool.query(
          "INSERT INTO schema_meta (id, version) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET version = EXCLUDED.version",
          [PG_SCHEMA_VERSION]
        );
      }, 3);
      readyDone = true;
    })().finally(() => {
      readyInFlight = null;
    });
    return readyInFlight;
  }

  return {
    kind: "postgres",
    pool,
    ensureReady,
    get ready() {
      return ensureReady();
    },
    prepare(sql) {
      return wrapPgQueryable(pool, sql, true);
    },
    async exec(sql) {
      await ensureReady();
      await pool.query(sql);
    },
    async transaction(fn) {
      await ensureReady();
      const client = await pgRetry(() => pool.connect(), 2);
      const tx = {
        kind: "postgres",
        prepare: (sql) => wrapPgQueryable(client, sql, false),
        exec: async (sql) => {
          await client.query(sql);
        }
      };
      try {
        await client.query("BEGIN");
        const result = await fn(tx);
        await client.query("COMMIT");
        return result;
      } catch (err) {
        try {
          await client.query("ROLLBACK");
        } catch {
          // Ignore rollback errors if transaction already aborted
        }
        throw err;
      } finally {
        client.release();
      }
    },
    async close() {
      await pool.end();
    }
  };
}

function initDatabase(optionsOrStorageDir) {
  if (typeof optionsOrStorageDir === "string") {
    return createSqliteAdapter(optionsOrStorageDir);
  }
  const opts = optionsOrStorageDir || {};
  const conn =
    opts.connectionString !== undefined
      ? opts.connectionString
      : !opts.sqliteOnly
      ? process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.POSTGRES_PRISMA_URL || ""
      : "";

  if (conn) {
    return createPostgresAdapter(conn);
  }
  return createSqliteAdapter(opts.storageDir);
}

function withTransaction(db, fn) {
  return db.transaction(fn);
}

module.exports = {
  initDatabase,
  withTransaction,
  isUniqueConstraintError,
  pgRetry
};
