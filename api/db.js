"use strict";

const { neon } = require("@neondatabase/serverless");

let sqlClient = null;
let initPromise = null;

function getDatabaseUrl() {
  return process.env.DATABASE_URL || process.env.NEON_DATABASE_URL || process.env.POSTGRES_URL || "";
}

function getSql() {
  const url = getDatabaseUrl();
  if (!url) throw new Error("DATABASE_URL is not configured");
  if (!sqlClient) sqlClient = neon(url);
  return sqlClient;
}

async function initDb() {
  if (initPromise) return initPromise;
  initPromise = (async () => {
    const sql = getSql();
    await sql`
      CREATE TABLE IF NOT EXISTS users (
        discord_id   TEXT PRIMARY KEY,
        email        TEXT NOT NULL DEFAULT '',
        username     TEXT NOT NULL DEFAULT '',
        handle       TEXT NOT NULL DEFAULT '',
        avatar       TEXT NOT NULL DEFAULT '',
        ip           TEXT NOT NULL DEFAULT '',
        first_login_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_login_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        login_count  INTEGER NOT NULL DEFAULT 1
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS login_logs (
        id          BIGSERIAL PRIMARY KEY,
        discord_id  TEXT NOT NULL,
        email       TEXT NOT NULL DEFAULT '',
        username    TEXT NOT NULL DEFAULT '',
        ip          TEXT NOT NULL DEFAULT '',
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;
    await sql`CREATE INDEX IF NOT EXISTS idx_login_logs_discord_id ON login_logs(discord_id)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_login_logs_created_at ON login_logs(created_at DESC)`;
    await sql`
      CREATE TABLE IF NOT EXISTS scan_logs (
        id              BIGSERIAL PRIMARY KEY,
        target_username TEXT NOT NULL DEFAULT '',
        requester_id    TEXT NOT NULL DEFAULT '',
        requester_name  TEXT NOT NULL DEFAULT '',
        requester_ip    TEXT NOT NULL DEFAULT '',
        country         TEXT NOT NULL DEFAULT '',
        city            TEXT NOT NULL DEFAULT '',
        browser         TEXT NOT NULL DEFAULT '',
        os              TEXT NOT NULL DEFAULT '',
        device          TEXT NOT NULL DEFAULT '',
        email_count     INTEGER NOT NULL DEFAULT 0,
        repo_count      INTEGER NOT NULL DEFAULT 0,
        scan_depth      TEXT NOT NULL DEFAULT 'normal',
        from_cache      BOOLEAN NOT NULL DEFAULT FALSE,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;
    await sql`CREATE INDEX IF NOT EXISTS idx_scan_logs_created_at ON scan_logs(created_at DESC)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_scan_logs_target ON scan_logs(target_username)`;
  })().catch((err) => {
    initPromise = null;
    throw err;
  });
  return initPromise;
}

async function upsertUserLogin({ discordId, email, username, handle, avatar, ip }) {
  const sql = getSql();
  await initDb();
  await sql`
    INSERT INTO users (discord_id, email, username, handle, avatar, ip, first_login_at, last_login_at, login_count)
    VALUES (${discordId}, ${email}, ${username}, ${handle}, ${avatar}, ${ip}, NOW(), NOW(), 1)
    ON CONFLICT (discord_id) DO UPDATE SET
      email = EXCLUDED.email,
      username = EXCLUDED.username,
      handle = EXCLUDED.handle,
      avatar = EXCLUDED.avatar,
      ip = EXCLUDED.ip,
      last_login_at = NOW(),
      login_count = users.login_count + 1
  `;
  await sql`
    INSERT INTO login_logs (discord_id, email, username, ip)
    VALUES (${discordId}, ${email}, ${username}, ${ip})
  `;
}

async function getUserByDiscordId(discordId) {
  const sql = getSql();
  await initDb();
  const rows = await sql`SELECT discord_id, email, username, handle, avatar, ip, first_login_at, last_login_at, login_count FROM users WHERE discord_id = ${discordId} LIMIT 1`;
  return rows[0] || null;
}


async function listUsers({ search = "", limit = 50, offset = 0 } = {}) {
  const sql = getSql();
  await initDb();
  const lim = Math.min(Math.max(Number(limit) || 50, 1), 200);
  const off = Math.max(Number(offset) || 0, 0);
  const q = String(search || "").trim().slice(0, 100);
  if (q) {
    const like = `%${q}%`;
    const rows = await sql`
      SELECT discord_id, email, username, handle, avatar, ip, first_login_at, last_login_at, login_count
      FROM users
      WHERE discord_id ILIKE ${like} OR email ILIKE ${like} OR username ILIKE ${like} OR handle ILIKE ${like} OR ip ILIKE ${like}
      ORDER BY last_login_at DESC
      LIMIT ${lim} OFFSET ${off}
    `;
    const countRows = await sql`
      SELECT COUNT(*)::int AS total FROM users
      WHERE discord_id ILIKE ${like} OR email ILIKE ${like} OR username ILIKE ${like} OR handle ILIKE ${like} OR ip ILIKE ${like}
    `;
    return { rows, total: countRows[0]?.total || 0 };
  }
  const rows = await sql`
    SELECT discord_id, email, username, handle, avatar, ip, first_login_at, last_login_at, login_count
    FROM users
    ORDER BY last_login_at DESC
    LIMIT ${lim} OFFSET ${off}
  `;
  const countRows = await sql`SELECT COUNT(*)::int AS total FROM users`;
  return { rows, total: countRows[0]?.total || 0 };
}

async function listLoginLogs({ limit = 50, offset = 0, discordId = "" } = {}) {
  const sql = getSql();
  await initDb();
  const lim = Math.min(Math.max(Number(limit) || 50, 1), 200);
  const off = Math.max(Number(offset) || 0, 0);
  const id = String(discordId || "").trim();
  if (id) {
    const rows = await sql`
      SELECT id, discord_id, email, username, ip, created_at
      FROM login_logs WHERE discord_id = ${id}
      ORDER BY created_at DESC LIMIT ${lim} OFFSET ${off}
    `;
    const countRows = await sql`SELECT COUNT(*)::int AS total FROM login_logs WHERE discord_id = ${id}`;
    return { rows, total: countRows[0]?.total || 0 };
  }
  const rows = await sql`
    SELECT id, discord_id, email, username, ip, created_at
    FROM login_logs
    ORDER BY created_at DESC LIMIT ${lim} OFFSET ${off}
  `;
  const countRows = await sql`SELECT COUNT(*)::int AS total FROM login_logs`;
  return { rows, total: countRows[0]?.total || 0 };
}

async function getDbStats() {
  const sql = getSql();
  await initDb();
  const [u, l, s] = await Promise.all([
    sql`SELECT COUNT(*)::int AS total FROM users`,
    sql`SELECT COUNT(*)::int AS total FROM login_logs`,
    sql`SELECT COUNT(*)::int AS total FROM scan_logs`,
  ]);
  return { users: u[0]?.total || 0, loginLogs: l[0]?.total || 0, scanLogs: s[0]?.total || 0 };
}

async function insertScanLog({ targetUsername, requesterId, requesterName, requesterIp, country, city, browser, os, device, emailCount, repoCount, scanDepth, fromCache }) {
  const sql = getSql();
  await initDb();
  await sql`
    INSERT INTO scan_logs (target_username, requester_id, requester_name, requester_ip, country, city, browser, os, device, email_count, repo_count, scan_depth, from_cache)
    VALUES (${targetUsername}, ${requesterId}, ${requesterName}, ${requesterIp}, ${country}, ${city}, ${browser}, ${os}, ${device}, ${emailCount}, ${repoCount}, ${scanDepth}, ${fromCache})
  `;
}

async function listScanLogs({ limit = 50, offset = 0, search = "" } = {}) {
  const sql = getSql();
  await initDb();
  const lim = Math.min(Math.max(Number(limit) || 50, 1), 200);
  const off = Math.max(Number(offset) || 0, 0);
  const q = String(search || "").trim().slice(0, 100);
  if (q) {
    const like = `%${q}%`;
    const rows = await sql`
      SELECT id, target_username, requester_id, requester_name, requester_ip, country, city, browser, os, device, email_count, repo_count, scan_depth, from_cache, created_at
      FROM scan_logs
      WHERE target_username ILIKE ${like} OR requester_id ILIKE ${like} OR requester_name ILIKE ${like} OR requester_ip ILIKE ${like}
      ORDER BY created_at DESC
      LIMIT ${lim} OFFSET ${off}
    `;
    const countRows = await sql`
      SELECT COUNT(*)::int AS total FROM scan_logs
      WHERE target_username ILIKE ${like} OR requester_id ILIKE ${like} OR requester_name ILIKE ${like} OR requester_ip ILIKE ${like}
    `;
    return { rows, total: countRows[0]?.total || 0 };
  }
  const rows = await sql`
    SELECT id, target_username, requester_id, requester_name, requester_ip, country, city, browser, os, device, email_count, repo_count, scan_depth, from_cache, created_at
    FROM scan_logs
    ORDER BY created_at DESC
    LIMIT ${lim} OFFSET ${off}
  `;
  const countRows = await sql`SELECT COUNT(*)::int AS total FROM scan_logs`;
  return { rows, total: countRows[0]?.total || 0 };
}

async function getScanStats({ days = 14 } = {}) {
  const sql = getSql();
  await initDb();
  const d = Math.min(Math.max(Number(days) || 14, 1), 90);
  const daily = await sql`
    SELECT to_char(date_trunc('day', created_at), 'YYYY-MM-DD') AS day, COUNT(*)::int AS scans, COALESCE(SUM(email_count),0)::int AS emails
    FROM scan_logs
    WHERE created_at >= NOW() - (${d} || ' days')::interval
    GROUP BY 1 ORDER BY 1 ASC
  `;
  const topTargets = await sql`
    SELECT target_username, COUNT(*)::int AS scans, MAX(created_at) AS last_scan
    FROM scan_logs
    GROUP BY target_username
    ORDER BY scans DESC, last_scan DESC
    LIMIT 8
  `;
  const totals = await sql`
    SELECT COUNT(*)::int AS total_scans, COALESCE(SUM(email_count),0)::int AS total_emails, COUNT(DISTINCT target_username)::int AS unique_targets, COUNT(DISTINCT requester_id)::int AS unique_requesters
    FROM scan_logs
  `;
  return {
    daily: daily.map(r => ({ day: r.day, scans: r.scans, emails: r.emails })),
    topTargets: topTargets.map(r => ({ target: r.target_username, scans: r.scans, lastScan: r.last_scan })),
    totals: totals[0] || { total_scans: 0, total_emails: 0, unique_targets: 0, unique_requesters: 0 },
  };
}

module.exports = { getSql, initDb, upsertUserLogin, getUserByDiscordId, listUsers, listLoginLogs, getDbStats, insertScanLog, listScanLogs, getScanStats, getDatabaseUrl };

