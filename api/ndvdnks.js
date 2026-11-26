"use strict";

const crypto = require("crypto");
const kv     = require("../lib/kv");
const { getCorsHeaders } = require("../lib/middleware");
const { listUsers, listLoginLogs, getDbStats, getDatabaseUrl, listScanLogs, getScanStats } = require("../lib/db");

const CTRL_RE = /[^\x20-\x7E]/g;

function s(str, max) {
  return String(str || "").replace(CTRL_RE, "").slice(0, max || 512);
}

function esc(str) {
  return String(str || "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;").replace(/\//g, "&#x2F;");
}

function getAdminPassword() {
  const p = process.env.ADMIN_PASSWORD;
  if (!p || p.length < 8) return null;
  return p;
}

function timingSafeCompare(a, b) {
  const ba = Buffer.from(String(a), "utf8");
  const bb = Buffer.from(String(b), "utf8");
  if (ba.length !== bb.length) { crypto.timingSafeEqual(ba, Buffer.alloc(ba.length)); return false; }
  return crypto.timingSafeEqual(ba, bb);
}

function verifyAdminToken(token) {
  if (!token || typeof token !== "string") return false;
  const secret = process.env.ADMIN_PASSWORD;
  if (!secret) return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [dataB64, sig] = parts;
  try {
    const data     = JSON.parse(Buffer.from(dataB64, "base64url").toString());
    const expected = crypto.createHmac("sha256", secret).update(dataB64).digest("hex");
    const b1 = Buffer.from(sig, "utf8"), b2 = Buffer.from(expected, "utf8");
    if (b1.length !== b2.length || !crypto.timingSafeEqual(b1, b2)) return false;
    if (Date.now() > data.exp) return false;
    return true;
  } catch { return false; }
}

function createAdminToken() {
  const secret = process.env.ADMIN_PASSWORD;
  const data   = Buffer.from(JSON.stringify({ exp: Date.now() + 4 * 60 * 60 * 1000 })).toString("base64url");
  const sig    = crypto.createHmac("sha256", secret).update(data).digest("hex");
  return `${data}.${sig}`;
}

function getBlacklist() {
  const map = new Map();
  for (let i = 1; i <= 50; i++) {
    const id     = (process.env[`BLACKLISTED_USER${i}`] || "").trim();
    const reason = (process.env[`BLACKLISTED_USER${i}_REASON`] || "No reason").trim();
    if (id && /^\d{17,19}$/.test(id)) map.set(id, reason);
  }
  return map;
}

function getSpecialUsers() {
  const map = new Map();
  for (let i = 1; i <= 50; i++) {
    const id = (process.env[`SPECIAL_USER${i}`] || "").trim();
    if (id && /^\d{17,19}$/.test(id)) map.set(id, `SPECIAL_USER${i}`);
  }
  return map;
}

async function getKvKeys(prefix) {
  try {
    const r    = await fetch(`${process.env.KV_REST_API_URL}/keys/${encodeURIComponent(prefix + "*")}`,
      { headers: { Authorization: `Bearer ${process.env.KV_REST_API_TOKEN}` } });
    const data = await r.json().catch(() => ({}));
    return Array.isArray(data.result) ? data.result : [];
  } catch { return []; }
}

async function addActivityLog(type, detail) {
  try {
    const entry = { type: s(type, 32), detail: s(detail, 200), ts: Date.now() };
    const existing = await kv.get("mono:admin:activity").catch(() => null);
    const log = Array.isArray(existing) ? existing : [];
    log.unshift(entry);
    await kv.set("mono:admin:activity", log.slice(0, 50), 7 * 24 * 60 * 60);
  } catch (_) {}
}

module.exports = async function handler(req, res) {
  Object.entries(getCorsHeaders(req)).forEach(([k, v]) => res.setHeader(k, v));
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Robots-Tag", "noindex, nofollow");

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST")    return res.status(405).json({ error: "Method Not Allowed" });

  if (!getAdminPassword()) return res.status(503).json({ error: "Admin not configured. Set ADMIN_PASSWORD env var (min 8 chars)." });

  let body;
  try {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString();
    if (raw.length > 4096) return res.status(400).json({ error: "Request too large" });
    body = JSON.parse(raw || "{}");
  } catch { return res.status(400).json({ error: "Invalid JSON" }); }

  if (typeof body !== "object" || body === null || Array.isArray(body))
    return res.status(400).json({ error: "Invalid request" });

  const action = s(body.action, 32);

  if (action === "login") {
    const pw = typeof body.password === "string" ? body.password : "";
    if (pw.length > 256) return res.status(400).json({ error: "Password too long" });
    if (!timingSafeCompare(pw, getAdminPassword())) {
      await new Promise(r => setTimeout(r, 500 + Math.random() * 300));
      return res.status(401).json({ error: "Invalid admin password" });
    }
    return res.status(200).json({ ok: true, token: createAdminToken() });
  }

  const token = typeof body.token === "string" ? body.token : "";
  if (!verifyAdminToken(token)) return res.status(401).json({ error: "Unauthorized" });

  if (action === "stats") {
    const [sessionKeys, blacklistKeys, failKeys, scanKeys, ratelimitKeys, dbStats] = await Promise.all([
      getKvKeys("mono:token_ip:"),
      getKvKeys("mono:blacklist:"),
      getKvKeys("mono:fails:"),
      getKvKeys("mono:scan:"),
      getKvKeys("rl:"),
      getDatabaseUrl() ? getDbStats().catch(() => ({ users: 0, loginLogs: 0 })) : Promise.resolve({ users: 0, loginLogs: 0 }),
    ]);
    const blacklist = getBlacklist();
    const special   = getSpecialUsers();
    return res.status(200).json({
      ok: true,
      activeSessions:    sessionKeys.length,
      blacklistedTokens: blacklistKeys.length,
      activeFails:       failKeys.length,
      cachedScans:       scanKeys.length,
      rateLimitKeys:     ratelimitKeys.length,
      dbUsers:           dbStats.users || 0,
      dbLoginLogs:       dbStats.loginLogs || 0,
      dbScanLogs:        dbStats.scanLogs || 0,
      blacklist: [...blacklist].map(([id, reason]) => ({ id: esc(id), reason: esc(reason) })),
      special:   [...special].map(([id, envKey])   => ({ id: esc(id), envKey: esc(envKey) })),
      env: {
        hasGithubToken: !!process.env.GITHUB_TOKEN,
        hasWebhook:     !!process.env.WEBHOOK_URL,
        hasDiscordBot:  !!process.env.DISCORD_BOT_TOKEN,
        hasKv:          !!(process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN),
        guildId:        esc(process.env.DISCORD_GUILD_ID || "not set"),
        roleId:         esc(process.env.DISCORD_ROLE_ID  || "not set"),
      },
    });
  }

  if (action === "activity_log") {
    const log = await kv.get("mono:admin:activity").catch(() => []);
    return res.status(200).json({ ok: true, log: Array.isArray(log) ? log : [] });
  }

  if (action === "user_lookup") {
    const uid = s(body.userId, 20).replace(/[^\d]/g, "");
    if (!uid || !/^\d{17,19}$/.test(uid)) return res.status(400).json({ error: "Invalid user ID" });
    const [sessionKey, failCount, scanIpKey, kvBlacklistEntry] = await Promise.all([
      kv.get(`mono:token_ip:${uid}`).catch(() => null),
      kv.get(`mono:fails:${uid}`).catch(() => null),
      kv.get(`mono:confirmed:${uid}`).catch(() => null),
      kv.get(`mono:kv_blacklist:${uid}`).catch(() => null),
    ]);
    const blacklist = getBlacklist();
    const special   = getSpecialUsers();
    const envBl = blacklist.has(uid);
    const kvBl  = !!kvBlacklistEntry;
    const blReason = envBl ? blacklist.get(uid) : (kvBlacklistEntry?.reason || "");
    return res.status(200).json({
      ok: true,
      userId:        esc(uid),
      hasActiveSession: !!sessionKey,
      sessionIp:     sessionKey ? esc(s(sessionKey, 45)) : null,
      failCount:     Number(failCount) || 0,
      isConfirmed:   !!scanIpKey,
      confirmedUntil: scanIpKey?.confirmedUntil || null,
      isBlacklisted: envBl || kvBl,
      blacklistReason: (envBl || kvBl) ? esc(blReason) : null,
      blacklistSource: envBl && kvBl ? "env+kv" : (envBl ? "env" : (kvBl ? "kv" : null)),
      isSpecial:     special.has(uid),
      specialKey:    special.has(uid) ? esc(special.get(uid)) : null,
    });
  }

  if (action === "revoke_session") {
    const uid = s(body.userId, 20).replace(/[^\d]/g, "");
    if (!uid || !/^\d{17,19}$/.test(uid)) return res.status(400).json({ error: "Invalid user ID" });
    const keys = await getKvKeys("mono:token_ip:");
    let revoked = 0;
    await Promise.all(keys.filter(k => k.includes(uid)).map(async k => {
      await kv.del(k.replace("mono:token_ip:", "")).catch(() => {});
      revoked++;
    }));
    await addActivityLog("session_revoked", `Admin revoked session for ${uid}`);
    return res.status(200).json({ ok: true, message: `Session revoked for ${uid}` });
  }

  if (action === "kv_blacklist_add") {
    const uid    = s(body.userId, 20).replace(/[^\d]/g, "");
    const reason = s(body.reason, 100) || "Admin blacklisted";
    if (!uid || !/^\d{17,19}$/.test(uid)) return res.status(400).json({ error: "Invalid user ID" });
    await kv.set(`mono:kv_blacklist:${uid}`, { reason, addedAt: Date.now() }, 365 * 24 * 60 * 60);
    await addActivityLog("kv_blacklist_add", `Admin blacklisted ${uid}: ${reason}`);
    return res.status(200).json({ ok: true, message: `User ${uid} blacklisted in KV` });
  }

  if (action === "kv_blacklist_remove") {
    const uid = s(body.userId, 20).replace(/[^\d]/g, "");
    if (!uid || !/^\d{17,19}$/.test(uid)) return res.status(400).json({ error: "Invalid user ID" });
    await kv.del(`mono:kv_blacklist:${uid}`);
    await addActivityLog("kv_blacklist_remove", `Admin removed KV blacklist for ${uid}`);
    return res.status(200).json({ ok: true, message: `User ${uid} removed from KV blacklist` });
  }

  if (action === "kv_blacklist_list") {
    const keys    = await getKvKeys("mono:kv_blacklist:");
    const entries = await Promise.all(keys.slice(0, 100).map(async k => {
      const uid  = esc(k.replace("mono:kv_blacklist:", ""));
      const data = await kv.get(`mono:kv_blacklist:${uid}`).catch(() => null);
      return { uid, reason: esc(data?.reason || ""), addedAt: data?.addedAt || 0 };
    }));
    return res.status(200).json({ ok: true, entries });
  }

  if (action === "recent_scans") {
    const keys  = await getKvKeys("mono:scan:");
    const scans = await Promise.all(keys.slice(0, 30).map(async k => {
      const username = esc(k.replace("mono:scan:", ""));
      const raw      = await kv.get(`mono:scan:${username}`).catch(() => null);
      return {
        username,
        emailCount: raw && typeof raw === "object" ? (Array.isArray(raw.emails) ? raw.emails.length : 0) : 0,
        repoCount:  raw && typeof raw === "object" ? (Number(raw.repoCount) || 0) : 0,
        cachedAt:   raw && typeof raw === "object" ? (raw.cachedAt || 0) : 0,
      };
    }));
    return res.status(200).json({ ok: true, scans });
  }

  if (action === "clear_scan_cache") {
    const username = s(body.username, 39).replace(/[^a-zA-Z0-9\-]/g, "");
    if (!username) return res.status(400).json({ error: "Invalid username" });
    await kv.del(`mono:scan:${username}`);
    await addActivityLog("cache_cleared", `Cache cleared for @${username}`);
    return res.status(200).json({ ok: true, message: `Cache cleared for @${username}` });
  }

  if (action === "clear_all_scan_cache") {
    const keys = await getKvKeys("mono:scan:");
    await Promise.all(keys.map(k => kv.del(k.replace("mono:scan:", "")).catch(() => {})));
    await addActivityLog("cache_cleared_all", `All ${keys.length} scan caches cleared`);
    return res.status(200).json({ ok: true, message: `${keys.length} entries cleared` });
  }

  if (action === "revoke_fails") {
    const uid = s(body.userId, 20).replace(/[^\d]/g, "");
    if (!uid || !/^\d{17,19}$/.test(uid)) return res.status(400).json({ error: "Invalid user ID" });
    await kv.del(`mono:fails:${uid}`);
    await addActivityLog("fails_reset", `Fail counter reset for ${uid}`);
    return res.status(200).json({ ok: true, message: `Fail counter reset for ${uid}` });
  }

  if (action === "list_fails") {
    const keys  = await getKvKeys("mono:fails:");
    const fails = await Promise.all(keys.slice(0, 50).map(async k => {
      const uid   = esc(k.replace("mono:fails:", ""));
      const count = await kv.get(`mono:fails:${uid}`).catch(() => 0);
      return { uid, count: Number(count) || 0 };
    }));
    return res.status(200).json({ ok: true, fails: fails.sort((a, b) => b.count - a.count) });
  }

  if (action === "service_status") {
    const checks = await Promise.allSettled([
      fetch("https://api.github.com/zen", { signal: AbortSignal.timeout(4000) }).then(r => ({ name: "GitHub API", ok: r.ok, status: r.status })),
      fetch("https://discord.com/api/v10/gateway", { signal: AbortSignal.timeout(4000) }).then(r => ({ name: "Discord API", ok: r.ok, status: r.status })),
    ]);
    const results = checks.map(c => c.status === "fulfilled" ? c.value : { name: "Unknown", ok: false, status: 0 });
    return res.status(200).json({ ok: true, services: results, checkedAt: Date.now() });
  }

  if (action === "export") {
    const [stats, fails, scans, activity, kvBl] = await Promise.all([
      (async () => {
        const [s1, s2, s3, s4, s5] = await Promise.all([
          getKvKeys("mono:token_ip:"), getKvKeys("mono:blacklist:"),
          getKvKeys("mono:fails:"),    getKvKeys("mono:scan:"), getKvKeys("rl:"),
        ]);
        return { activeSessions: s1.length, blacklistedTokens: s2.length, activeFails: s3.length, cachedScans: s4.length, rateLimitKeys: s5.length };
      })(),
      (async () => {
        const keys = await getKvKeys("mono:fails:");
        return Promise.all(keys.slice(0, 50).map(async k => {
          const uid = k.replace("mono:fails:", ""); const c = await kv.get(`mono:fails:${uid}`).catch(() => 0); return { uid, count: Number(c) || 0 };
        }));
      })(),
      (async () => {
        const keys = await getKvKeys("mono:scan:");
        return Promise.all(keys.slice(0, 30).map(async k => {
          const u = k.replace("mono:scan:", ""); const r = await kv.get(`mono:scan:${u}`).catch(() => null);
          return { username: u, emailCount: r?.emails?.length || 0, repoCount: r?.repoCount || 0 };
        }));
      })(),
      kv.get("mono:admin:activity").catch(() => []),
      (async () => {
        const keys = await getKvKeys("mono:kv_blacklist:"); return Promise.all(keys.slice(0, 100).map(async k => { const u = k.replace("mono:kv_blacklist:", ""); const d = await kv.get(`mono:kv_blacklist:${u}`).catch(() => null); return { uid: u, reason: d?.reason || "", addedAt: d?.addedAt || 0 }; }));
      })(),
    ]);
    const exportData = { exportedAt: new Date().toISOString(), stats, fails, scans, activity: Array.isArray(activity) ? activity : [], kvBlacklist: kvBl, envBlacklist: [...getBlacklist()].map(([id, r]) => ({ id, reason: r })), specialUsers: [...getSpecialUsers()].map(([id, k]) => ({ id, envKey: k })) };
    return res.status(200).json({ ok: true, data: exportData });
  }

  if (action === "db_users") {
    if (!getDatabaseUrl()) return res.status(503).json({ error: "DATABASE_URL not configured" });
    const search = s(body.search, 100);
    const limit  = Math.min(Math.max(Number(body.limit) || 50, 1), 200);
    const offset = Math.max(Number(body.offset) || 0, 0);
    const { rows, total } = await listUsers({ search, limit, offset });
    return res.status(200).json({
      ok: true,
      total,
      users: rows.map(u => ({
        discordId: esc(u.discord_id),
        email: esc(u.email),
        username: esc(u.username),
        handle: esc(u.handle),
        avatar: esc(u.avatar),
        ip: esc(u.ip),
        firstLoginAt: u.first_login_at,
        lastLoginAt: u.last_login_at,
        loginCount: Number(u.login_count) || 0,
      })),
    });
  }

  if (action === "db_login_logs") {
    if (!getDatabaseUrl()) return res.status(503).json({ error: "DATABASE_URL not configured" });
    const limit = Math.min(Math.max(Number(body.limit) || 50, 1), 200);
    const offset = Math.max(Number(body.offset) || 0, 0);
    const discordId = s(body.discordId, 20).replace(/[^\d]/g, "");
    const { rows, total } = await listLoginLogs({ limit, offset, discordId });
    return res.status(200).json({
      ok: true,
      total,
      logs: rows.map(l => ({
        id: Number(l.id),
        discordId: esc(l.discord_id),
        email: esc(l.email),
        username: esc(l.username),
        ip: esc(l.ip),
        createdAt: l.created_at,
      })),
    });
  }

  if (action === "scan_logs") {
    if (!getDatabaseUrl()) return res.status(503).json({ error: "DATABASE_URL not configured" });
    const search = s(body.search, 100);
    const limit  = Math.min(Math.max(Number(body.limit) || 50, 1), 200);
    const offset = Math.max(Number(body.offset) || 0, 0);
    const { rows, total } = await listScanLogs({ search, limit, offset });
    return res.status(200).json({
      ok: true,
      total,
      logs: rows.map(r => ({
        id: Number(r.id),
        target: esc(r.target_username),
        requesterId: esc(r.requester_id),
        requesterName: esc(r.requester_name),
        requesterIp: esc(r.requester_ip),
        country: esc(r.country),
        city: esc(r.city),
        browser: esc(r.browser),
        os: esc(r.os),
        device: esc(r.device),
        emailCount: Number(r.email_count) || 0,
        repoCount: Number(r.repo_count) || 0,
        scanDepth: esc(r.scan_depth),
        fromCache: !!r.from_cache,
        createdAt: r.created_at,
      })),
    });
  }

  if (action === "scan_stats") {
    if (!getDatabaseUrl()) return res.status(503).json({ error: "DATABASE_URL not configured" });
    const days = Math.min(Math.max(Number(body.days) || 14, 1), 90);
    try {
      const stats = await getScanStats({ days });
      return res.status(200).json({ ok: true, ...stats });
    } catch (e) {
      return res.status(500).json({ error: "scan_stats_failed", detail: String(e?.message || e).slice(0, 200) });
    }
  }

  return res.status(400).json({ error: "Unknown action" });
};
