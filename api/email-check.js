"use strict";

const crypto = require("crypto");
const kv     = require("./kv");
const { kvRateLimit, getCorsHeaders } = require("./middleware");
const { verifySessionToken, isTokenBlacklisted } = require("./session");
const { getUserByDiscordId, getDatabaseUrl } = require("./db");

const EMAIL_RE = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

function json(res, status, body) {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.status(status).send(JSON.stringify(body));
}

function parseCookies(req) {
  const raw = String(req.headers["cookie"] || "");
  const out = {};
  raw.split(/;\s*/).forEach(part => {
    const idx = part.indexOf("=");
    if (idx > 0) out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  });
  return out;
}

function sanitizeEmail(e) {
  const email = String(e || "").trim().toLowerCase().slice(0, 254);
  if (!EMAIL_RE.test(email)) return "";
  return email;
}

async function fetchWithTimeout(url, opts = {}, ms = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    const r = await fetch(url, { ...opts, signal: ctrl.signal, redirect: opts.redirect || "follow" });
    return r;
  } finally { clearTimeout(t); }
}

function md5(s) { return crypto.createHash("md5").update(String(s).trim().toLowerCase()).digest("hex"); }

// ---- Modules ----
// Each returns { name, category, status: 'found'|'not_found'|'error'|'rate_limit', detail }

async function checkGravatar(email) {
  const hash = md5(email);
  try {
    const r = await fetchWithTimeout(`https://en.gravatar.com/${hash}.json`, { headers: { "User-Agent": "mono-osint/1.0" } }, 7000);
    if (r.status === 200) {
      const data = await r.json().catch(() => null);
      const entry = data?.entry?.[0];
      const name = entry?.displayName || entry?.preferredUsername || "Profile exists";
      return { name: "Gravatar", category: "profile", status: "found", detail: String(name).slice(0, 80) };
    }
    if (r.status === 404) return { name: "Gravatar", category: "profile", status: "not_found", detail: "No public profile" };
    return { name: "Gravatar", category: "profile", status: "error", detail: `HTTP ${r.status}` };
  } catch (e) { return { name: "Gravatar", category: "profile", status: "error", detail: "Request failed" }; }
}

async function checkAdobe(email) {
  try {
    const r = await fetchWithTimeout("https://auth.services.adobe.com/signin/v2/users/accounts", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Ims-ClientId": "adobedotcom2", "User-Agent": "Mozilla/5.0" },
      body: JSON.stringify({ username: email }),
    }, 8000);
    if (r.status === 200) {
      const data = await r.json().catch(() => ({}));
      if (Array.isArray(data) && data.length > 0) return { name: "Adobe", category: "creative", status: "found", detail: "Account exists" };
      if (data?.length > 0) return { name: "Adobe", category: "creative", status: "found", detail: "Account exists" };
      return { name: "Adobe", category: "creative", status: "not_found", detail: "No account found" };
    }
    if (r.status === 404) return { name: "Adobe", category: "creative", status: "not_found", detail: "No account found" };
    if (r.status === 429) return { name: "Adobe", category: "creative", status: "rate_limit", detail: "Rate limited" };
    return { name: "Adobe", category: "creative", status: "error", detail: `HTTP ${r.status}` };
  } catch { return { name: "Adobe", category: "creative", status: "error", detail: "Request failed" }; }
}

async function checkSpotify(email) {
  try {
    const r = await fetchWithTimeout(`https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email=${encodeURIComponent(email)}`, {
      headers: { "User-Agent": "Mozilla/5.0" },
    }, 8000);
    if (r.status === 200) {
      const data = await r.json().catch(() => ({}));
      if (data?.status === 20) return { name: "Spotify", category: "music", status: "found", detail: "Account exists" };
      if (data?.status === 1) return { name: "Spotify", category: "music", status: "not_found", detail: "No account found" };
      return { name: "Spotify", category: "music", status: "error", detail: "Unexpected response" };
    }
    if (r.status === 429) return { name: "Spotify", category: "music", status: "rate_limit", detail: "Rate limited" };
    return { name: "Spotify", category: "music", status: "error", detail: `HTTP ${r.status}` };
  } catch { return { name: "Spotify", category: "music", status: "error", detail: "Request failed" }; }
}

async function checkWordpress(email) {
  try {
    const r = await fetchWithTimeout("https://public-api.wordpress.com/rest/v1.1/users/" + encodeURIComponent(email) + "/auth-options", {
      headers: { "User-Agent": "Mozilla/5.0" },
    }, 8000);
    if (r.status === 200) {
      const data = await r.json().catch(() => ({}));
      if (data?.email) return { name: "WordPress", category: "web", status: "found", detail: "Account exists" };
      return { name: "WordPress", category: "web", status: "found", detail: "Account exists" };
    }
    if (r.status === 404) return { name: "WordPress", category: "web", status: "not_found", detail: "No account found" };
    if (r.status === 429) return { name: "WordPress", category: "web", status: "rate_limit", detail: "Rate limited" };
    return { name: "WordPress", category: "web", status: "error", detail: `HTTP ${r.status}` };
  } catch { return { name: "WordPress", category: "web", status: "error", detail: "Request failed" }; }
}

async function checkFirefox(email) {
  try {
    const r = await fetchWithTimeout("https://api.accounts.firefox.com/v1/account/status?email=" + encodeURIComponent(email), {
      headers: { "User-Agent": "Mozilla/5.0" },
    }, 8000);
    if (r.status === 200) {
      const data = await r.json().catch(() => ({}));
      if (data?.exists === true) return { name: "Firefox", category: "tech", status: "found", detail: "Account exists" };
      return { name: "Firefox", category: "tech", status: "not_found", detail: "No account found" };
    }
    if (r.status === 429) return { name: "Firefox", category: "tech", status: "rate_limit", detail: "Rate limited" };
    return { name: "Firefox", category: "tech", status: "error", detail: `HTTP ${r.status}` };
  } catch { return { name: "Firefox", category: "tech", status: "error", detail: "Request failed" }; }
}

async function checkArchiveOrg(email) {
  try {
    const r = await fetchWithTimeout("https://archive.org/account/signup", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0" },
      body: `input=${encodeURIComponent(email)}&checkval=true`,
    }, 8000);
    if (r.status === 200) {
      const data = await r.json().catch(() => ({}));
      if (data?.success === false && String(data?.error || "").toLowerCase().includes("email")) return { name: "Archive.org", category: "archive", status: "found", detail: "Account exists" };
      return { name: "Archive.org", category: "archive", status: "not_found", detail: "No account found" };
    }
    if (r.status === 429) return { name: "Archive.org", category: "archive", status: "rate_limit", detail: "Rate limited" };
    return { name: "Archive.org", category: "archive", status: "error", detail: `HTTP ${r.status}` };
  } catch { return { name: "Archive.org", category: "archive", status: "error", detail: "Request failed" }; }
}

async function checkStrava(email) {
  try {
    const r = await fetchWithTimeout("https://www.strava.com/frontend/athletes/email_unique?email=" + encodeURIComponent(email), {
      headers: { "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/javascript, */*; q=0.01", "X-Requested-With": "XMLHttpRequest" },
    }, 8000);
    if (r.status === 200) {
      const txt = await r.text().catch(() => "");
      if (txt.includes("false")) return { name: "Strava", category: "fitness", status: "found", detail: "Account exists" };
      if (txt.includes("true")) return { name: "Strava", category: "fitness", status: "not_found", detail: "No account found" };
      return { name: "Strava", category: "fitness", status: "error", detail: "Unexpected response" };
    }
    if (r.status === 429) return { name: "Strava", category: "fitness", status: "rate_limit", detail: "Rate limited" };
    return { name: "Strava", category: "fitness", status: "error", detail: `HTTP ${r.status}` };
  } catch { return { name: "Strava", category: "fitness", status: "error", detail: "Request failed" }; }
}

async function checkDuolingo(email) {
  try {
    const r = await fetchWithTimeout(`https://www.duolingo.com/2017-06-30/users?email=${encodeURIComponent(email)}`, {
      headers: { "User-Agent": "Mozilla/5.0" },
    }, 8000);
    if (r.status === 200) {
      const data = await r.json().catch(() => ({}));
      const users = data?.users || [];
      if (Array.isArray(users) && users.length > 0) return { name: "Duolingo", category: "learning", status: "found", detail: "Account exists" };
      return { name: "Duolingo", category: "learning", status: "not_found", detail: "No account found" };
    }
    if (r.status === 404) return { name: "Duolingo", category: "learning", status: "not_found", detail: "No account found" };
    if (r.status === 429) return { name: "Duolingo", category: "learning", status: "rate_limit", detail: "Rate limited" };
    return { name: "Duolingo", category: "learning", status: "error", detail: `HTTP ${r.status}` };
  } catch { return { name: "Duolingo", category: "learning", status: "error", detail: "Request failed" }; }
}

async function checkPornhub(email) {
  // Skip - inappropriate for this context
  return null;
}

const MODULES = [
  checkGravatar,
  checkAdobe,
  checkSpotify,
  checkWordpress,
  checkFirefox,
  checkArchiveOrg,
  checkStrava,
  checkDuolingo,
];

async function runModules(email) {
  const results = await Promise.all(MODULES.map(fn => fn(email).catch(() => ({ name: fn.name.replace(/^check/,''), category: 'unknown', status: 'error', detail: 'Check failed' }))));
  return results.filter(Boolean);
}

module.exports = async function handler(req, res) {
  Object.entries(getCorsHeaders(req)).forEach(([k, v]) => res.setHeader(k, v));
  res.setHeader("Cache-Control", "no-store");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return json(res, 405, { error: "Method not allowed" });

  const cookies = parseCookies(req);
  const rawToken = cookies["mono_session"] || String(req.headers["x-session-token"] || "").trim();
  const session = verifySessionToken(rawToken);
  if (!session.ok) return json(res, 401, { error: session.error || "Login required" });
  if (await isTokenBlacklisted(rawToken)) return json(res, 401, { error: "Session revoked — please log in again" });

  // user blacklist enforcement
  let userBlocked = false;
  for (let i = 1; i <= 50; i++) { const id = String(process.env[`BLACKLISTED_USER${i}`] || "").trim(); if (id === session.userId) { userBlocked = true; break; } }
  if (!userBlocked) { try { const bl = await kv.get(`mono:kv_blacklist:${session.userId}`); if (bl) userBlocked = true; } catch (_) {} }
  if (userBlocked) return json(res, 403, { error: "Your account is not allowed to use this service." });

  let body;
  try {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString();
    if (raw.length > 1024) return json(res, 413, { error: "Request body too large" });
    body = JSON.parse(raw || "{}");
  } catch (_) { return json(res, 400, { error: "Invalid JSON" }); }

  const email = sanitizeEmail(body.email);
  if (!email) return json(res, 400, { error: "Invalid email address" });

  const limited = await kvRateLimit(`rl:emailcheck:${session.userId}`, 8, 60);
  if (limited) return json(res, 429, { error: "Rate limit reached. Wait a moment." });

  const started = Date.now();
  const results = await runModules(email);
  const found = results.filter(r => r.status === "found").length;

  return json(res, 200, {
    email,
    checked: results.length,
    found,
    durationMs: Date.now() - started,
    results,
  });
};
