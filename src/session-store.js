const fs = require("fs");
const path = require("path");
const session = require("express-session");
const { DatabaseSync } = require("node:sqlite");
const { pgRetry } = require("./db");

function getExpiry(sess) {
  const maxAge = sess?.cookie?.originalMaxAge ?? sess?.cookie?.maxAge ?? 86400000;
  if (sess?.cookie?.expires) {
    const ts = new Date(sess.cookie.expires).getTime();
    if (!Number.isNaN(ts)) return ts;
  }
  return Date.now() + Number(maxAge);
}

class SQLiteSessionStore extends session.Store {
  constructor(options = {}) {
    super();
    const dir = options.dir || path.join(process.cwd(), "storage");
    const dbName = options.db || "sessions.sqlite";
    fs.mkdirSync(dir, { recursive: true });

    this.db = new DatabaseSync(path.join(dir, dbName));
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec("PRAGMA busy_timeout = 5000;");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        sid TEXT PRIMARY KEY,
        sess TEXT NOT NULL,
        expired INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_sessions_expired ON sessions(expired);
    `);

    const pruneMs = options.pruneIntervalMs ?? 900000;
    if (pruneMs > 0) {
      this._timer = setInterval(() => this.pruneExpired(), pruneMs);
      this._timer.unref();
    }
  }

  async pruneExpired() {
    try {
      this.db.prepare("DELETE FROM sessions WHERE expired <= ?").run(Date.now());
    } catch {
      // Ignore cleanup errors on closed db
    }
  }

  get(sid, callback) {
    try {
      const row = this.db
        .prepare("SELECT sess, expired FROM sessions WHERE sid = ?")
        .get(sid);
      if (!row) return callback(null, null);
      if (Number(row.expired) <= Date.now()) {
        this.destroy(sid, () => callback(null, null));
        return;
      }
      callback(null, JSON.parse(row.sess));
    } catch (err) {
      callback(err);
    }
  }

  set(sid, sess, callback) {
    try {
      const expired = getExpiry(sess);
      const data = JSON.stringify(sess);
      this.db
        .prepare(
          `INSERT INTO sessions (sid, sess, expired)
           VALUES (?, ?, ?)
           ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expired = excluded.expired`
        )
        .run(sid, data, expired);
      if (callback) callback(null);
    } catch (err) {
      if (callback) callback(err);
    }
  }

  touch(sid, sess, callback) {
    try {
      const expired = getExpiry(sess);
      this.db
        .prepare("UPDATE sessions SET expired = ? WHERE sid = ?")
        .run(expired, sid);
      if (callback) callback(null);
    } catch (err) {
      if (callback) callback(err);
    }
  }

  destroy(sid, callback) {
    try {
      this.db.prepare("DELETE FROM sessions WHERE sid = ?").run(sid);
      if (callback) callback(null);
    } catch (err) {
      if (callback) callback(err);
    }
  }

  async destroyMany(sids = []) {
    if (!sids.length) return;
    const stmt = this.db.prepare("DELETE FROM sessions WHERE sid = ?");
    for (const sid of sids) {
      stmt.run(sid);
    }
  }

  async hasActiveSid(sid) {
    const row = this.db
      .prepare("SELECT expired FROM sessions WHERE sid = ?")
      .get(sid);
    return Boolean(row && Number(row.expired) > Date.now());
  }

  async filterActiveSids(sids = []) {
    if (!sids.length) return new Set();
    const placeholders = sids.map(() => "?").join(",");
    const rows = this.db
      .prepare(`SELECT sid FROM sessions WHERE sid IN (${placeholders}) AND expired > ?`)
      .all(...sids, Date.now());
    return new Set(rows.map((r) => r.sid));
  }

  async close() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
    this.db.close();
  }
}

class PGSessionStore extends session.Store {
  constructor(options = {}) {
    super();
    this.pool = options.pool;
    if (!this.pool) {
      const { Pool } = require("pg");
      this.pool = new Pool({
        connectionString: options.connectionString,
        max: 5,
        idleTimeoutMillis: 10000,
        connectionTimeoutMillis: 15000,
        keepAlive: true
      });
      this.pool.on("error", (err) => {
        console.error("PG session pool idle error:", err.message);
      });
      this._ownsPool = true;
    }

    if (typeof options.ensureReady === "function") {
      this._ensureReady = options.ensureReady;
    } else {
      let readyDone = false;
      let inFlight = null;
      this._ensureReady = () => {
        if (readyDone) return Promise.resolve();
        if (inFlight) return inFlight;
        inFlight = pgRetry(
          () =>
            this.pool.query(`
              CREATE TABLE IF NOT EXISTS sessions (
                sid TEXT PRIMARY KEY,
                sess TEXT NOT NULL,
                expired BIGINT NOT NULL
              );
              CREATE INDEX IF NOT EXISTS idx_sessions_expired ON sessions(expired);
            `),
          3
        )
          .then(() => {
            readyDone = true;
          })
          .finally(() => {
            inFlight = null;
          });
        return inFlight;
      };
    }

    const pruneMs = options.pruneIntervalMs ?? 900000;
    if (pruneMs > 0) {
      this._timer = setInterval(() => this.pruneExpired(), pruneMs);
      this._timer.unref();
    }
  }

  async _query(sql, params = [], retry = true) {
    await this._ensureReady();
    return retry
      ? pgRetry(() => this.pool.query(sql, params), 2)
      : this.pool.query(sql, params);
  }

  async pruneExpired() {
    try {
      await this._query("DELETE FROM sessions WHERE expired <= $1", [Date.now()], false);
    } catch {
      // Ignore cleanup errors
    }
  }

  get(sid, callback) {
    this._query("SELECT sess, expired FROM sessions WHERE sid = $1", [sid])
      .then((res) => {
        const row = res.rows[0];
        if (!row) return callback(null, null);
        if (Number(row.expired) <= Date.now()) {
          return this.destroy(sid, () => callback(null, null));
        }
        callback(null, JSON.parse(row.sess));
      })
      .catch((err) => callback(err));
  }

  set(sid, sess, callback) {
    const expired = getExpiry(sess);
    const data = JSON.stringify(sess);
    this._query(
      `INSERT INTO sessions (sid, sess, expired)
       VALUES ($1, $2, $3)
       ON CONFLICT (sid) DO UPDATE SET sess = EXCLUDED.sess, expired = EXCLUDED.expired`,
      [sid, data, expired]
    )
      .then(() => {
        if (callback) callback(null);
      })
      .catch((err) => {
        if (callback) callback(err);
      });
  }

  touch(sid, sess, callback) {
    const expired = getExpiry(sess);
    this._query("UPDATE sessions SET expired = $1 WHERE sid = $2", [expired, sid])
      .then(() => {
        if (callback) callback(null);
      })
      .catch((err) => {
        if (callback) callback(err);
      });
  }

  destroy(sid, callback) {
    this._query("DELETE FROM sessions WHERE sid = $1", [sid])
      .then(() => {
        if (callback) callback(null);
      })
      .catch((err) => {
        if (callback) callback(err);
      });
  }

  async destroyMany(sids = []) {
    if (!sids.length) return;
    await this._query("DELETE FROM sessions WHERE sid = ANY($1::text[])", [sids]);
  }

  async hasActiveSid(sid) {
    const res = await this._query(
      "SELECT expired FROM sessions WHERE sid = $1",
      [sid]
    );
    const row = res.rows[0];
    return Boolean(row && Number(row.expired) > Date.now());
  }

  async filterActiveSids(sids = []) {
    if (!sids.length) return new Set();
    const res = await this._query(
      "SELECT sid FROM sessions WHERE sid = ANY($1::text[]) AND expired > $2",
      [sids, Date.now()]
    );
    return new Set(res.rows.map((r) => r.sid));
  }

  async close() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
    if (this._ownsPool) {
      await this.pool.end();
    }
  }
}

module.exports = { SQLiteSessionStore, PGSessionStore };
