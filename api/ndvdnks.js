"use strict";

const crypto = require("crypto");
const kv     = require("./kv");
const { getCorsHeaders } = require("./middleware");

const CTRL_RE = /[^\x20-\x7E]/g;

function s(str, max) {
  return String(str || "").replace(CTRL_RE, "").slice(0, max || 512);
}

function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\//g, "&#x2F;");
}

function safeKey(str) {
  return String(str || "").replace(/[^a-zA-Z0-9_:\-]/g, "").slice(0, 200);
}

function getAdminPassword() {
  const p = process.env.ADMIN_PASSWORD;
  if (!p || p.length < 8) return null;
  return p;
}

function timingSafeCompare(a, b) {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
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
    const data    = JSON.parse(Buffer.from(dataB64, "base64url").toString());
    const expected = crypto.createHmac("sha256", secret).update(dataB64).digest("hex");
    const buf1    = Buffer.from(sig, "utf8");
    const buf2    = Buffer.from(expected, "utf8");
    if (buf1.length !== buf2.length || !crypto.timingSafeEqual(buf1, buf2)) return false;
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
    const result = await fetch(`${process.env.KV_REST_API_URL}/keys/${encodeURIComponent(prefix + "*")}`, {
      headers: { Authorization: `Bearer ${process.env.KV_REST_API_TOKEN}` }
    });
    const data = await result.json().catch(() => ({}));
    return Array.isArray(data.result) ? data.result : [];
  } catch { return []; }
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
    if (raw.length > 2048) return res.status(400).json({ error: "Request too large" });
    body = JSON.parse(raw || "{}");
  } catch { return res.status(400).json({ error: "Invalid JSON" }); }

  if (typeof body !== "object" || body === null || Array.isArray(body))
    return res.status(400).json({ error: "Invalid request" });

  const action = s(body.action, 32);

  if (action === "login") {
    const pw = typeof body.password === "string" ? body.password : "";
    if (pw.length > 256) return res.status(400).json({ error: "Password too long" });
    const expected = getAdminPassword();
    if (!timingSafeCompare(pw, expected)) {
      await new Promise(r => setTimeout(r, 500 + Math.random() * 300));
      return res.status(401).json({ error: "Invalid admin password" });
    }
    return res.status(200).json({ ok: true, token: createAdminToken() });
  }

  const token = typeof body.token === "string" ? body.token : "";
  if (!verifyAdminToken(token)) return res.status(401).json({ error: "Unauthorized" });

  if (action === "stats") {
    const [sessionKeys, blacklistKeys, failKeys, scanKeys, ratelimitKeys] = await Promise.all([
      getKvKeys("antisec:token_ip:"),
      getKvKeys("antisec:blacklist:"),
      getKvKeys("antisec:fails:"),
      getKvKeys("antisec:scan:"),
      getKvKeys("rl:"),
    ]);

    const blacklist   = getBlacklist();
    const special     = getSpecialUsers();

    const blacklistArr = [];
    for (const [id, reason] of blacklist) {
      blacklistArr.push({ id: escapeHtml(id), reason: escapeHtml(reason), envKey: escapeHtml(special.get(id) || "") });
    }

    const specialArr = [];
    for (const [id, envKey] of special) {
      specialArr.push({ id: escapeHtml(id), envKey: escapeHtml(envKey) });
    }

    return res.status(200).json({
      ok: true,
      activeSessions:  sessionKeys.length,
      blacklistedTokens: blacklistKeys.length,
      activeFails:     failKeys.length,
      cachedScans:     scanKeys.length,
      rateLimitKeys:   ratelimitKeys.length,
      blacklist:       blacklistArr,
      special:         specialArr,
      env: {
        hasGithubToken:   !!process.env.GITHUB_TOKEN,
        hasWebhook:       !!process.env.WEBHOOK_URL,
        hasDiscordBot:    !!process.env.DISCORD_BOT_TOKEN,
        hasKv:            !!(process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN),
        guildId:          escapeHtml(process.env.DISCORD_GUILD_ID || "not set"),
        roleId:           escapeHtml(process.env.DISCORD_ROLE_ID  || "not set"),
      }
    });
  }

  if (action === "recent_scans") {
    const keys = await getKvKeys("antisec:scan:");
    const scans = [];
    await Promise.all(keys.slice(0, 20).map(async (k) => {
      const raw = await kv.get(k.replace("antisec:scan:", "").replace(/^antisec:scan:/, "")).catch(() => null);
      const username = escapeHtml(k.replace("antisec:scan:", ""));
      scans.push({
        username,
        emailCount: raw && typeof raw === "object" ? (Array.isArray(raw.emails) ? raw.emails.length : 0) : 0,
        repoCount:  raw && typeof raw === "object" ? (Number(raw.repoCount) || 0) : 0,
      });
    }));
    return res.status(200).json({ ok: true, scans });
  }

  if (action === "clear_scan_cache") {
    const username = s(body.username, 39).replace(/[^a-zA-Z0-9\-]/g, "");
    if (!username) return res.status(400).json({ error: "Invalid username" });
    await kv.del(`antisec:scan:${username}`);
    return res.status(200).json({ ok: true, message: `Cache cleared for @${username}` });
  }

  if (action === "clear_all_scan_cache") {
    const keys = await getKvKeys("antisec:scan:");
    await Promise.all(keys.map(k => {
      const username = k.replace("antisec:scan:", "");
      return kv.del(`antisec:scan:${username}`).catch(() => {});
    }));
    return res.status(200).json({ ok: true, message: `${keys.length} scan cache entries cleared` });
  }

  if (action === "revoke_fails") {
    const uid = s(body.userId, 20).replace(/[^\d]/g, "");
    if (!uid || !/^\d{17,19}$/.test(uid)) return res.status(400).json({ error: "Invalid user ID" });
    await kv.del(`antisec:fails:${uid}`);
    return res.status(200).json({ ok: true, message: `Fail counter reset for ${uid}` });
  }

  if (action === "list_fails") {
    const keys = await getKvKeys("antisec:fails:");
    const fails = await Promise.all(keys.slice(0, 50).map(async (k) => {
      const uid   = escapeHtml(k.replace("antisec:fails:", ""));
      const count = await kv.get(`antisec:fails:${uid}`).catch(() => 0);
      return { uid, count: Number(count) || 0 };
    }));
    return res.status(200).json({ ok: true, fails: fails.sort((a, b) => b.count - a.count) });
  }

  return res.status(400).json({ error: "Unknown action" });
};
