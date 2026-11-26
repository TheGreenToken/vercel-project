"use strict";

// Email Breach Check (key-free, server-side, read-only):
//   - Email mode  -> breach names for an address via XposedOrNot
//   - Password mode -> breach count for a password via HaveIBeenPwned
//                      Pwned Passwords (k-anonymity, full password never sent)
//
// Defensive OSINT exposure lookup over publicly indexed breach data.

const crypto = require("crypto");
const kv     = require("./kv");
const { kvRateLimit, getCorsHeaders } = require("./middleware");
const { verifySessionToken, isTokenBlacklisted } = require("./session");

const EMAIL_RE = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
const XON_URL = "https://api.xposedornot.com/v1/check-email/";
const HIBP_URL = "https://api.pwnedpasswords.com/range/";

function json(res, status, body) {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.status(status).send(JSON.stringify(body));
}
function parseCookies(req) {
  const raw = String(req.headers["cookie"] || "");
  const out = {};
  raw.split(/;\s*/).forEach(part => { const idx = part.indexOf("="); if (idx > 0) out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim()); });
  return out;
}
function sanitizeEmail(e) { const email = String(e || "").trim().toLowerCase().slice(0, 254); return EMAIL_RE.test(email) ? email : ""; }
function sanitizePassword(p) { const v = String(p || "").replace(/[\r\n\t]/g, "").slice(0, 128); return v; }

async function fetchWithTimeout(url, opts = {}, ms = 15000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, {
      ...opts,
      signal: ctrl.signal,
      redirect: opts.redirect || "follow",
      headers: {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Accept": "application/json,text/plain,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        ...(opts.headers || {}),
      },
    });
  } finally { clearTimeout(t); }
}

function xonError(status, body) {
  const snippet = String(body || "").replace(/\s+/g, " ").slice(0, 120);
  if (status === 429) return { ok: false, status: "rate_limit", detail: "XposedOrNot rate limit reached." };
  return { ok: false, status: "error", detail: `XposedOrNot returned HTTP ${status}${snippet ? ": " + snippet : ""}` };
}

// ---- Email breach lookup ----
async function queryEmailBreaches(email) {
  const url = XON_URL + encodeURIComponent(email);
  try {
    const r = await fetchWithTimeout(url, {}, 15000);
    const text = await r.text().catch(() => "");
    if (r.status !== 200) return xonError(r.status, text);
    let data;
    try { data = JSON.parse(text); } catch { return { ok: false, status: "error", detail: "XposedOrNot returned invalid JSON." }; }
    const breaches = Array.isArray(data.breaches) ? data.breaches : [];
    const names = [];
    for (const group of breaches) {
      if (Array.isArray(group)) group.forEach(n => { if (typeof n === "string" && n) names.push(n); });
      else if (typeof group === "string" && group) names.push(group);
    }
    return { ok: true, status: names.length ? "found" : "not_found", breaches: names, count: names.length };
  } catch (e) {
    return { ok: false, status: "error", detail: "XposedOrNot request failed: " + (e && e.name === "AbortError" ? "timeout" : "network") };
  }
}

// ---- Password breach lookup (HIBP k-anonymity) ----
async function queryPasswordBreach(password) {
  const sha1 = crypto.createHash("sha1").update(password, "utf8").digest("hex").toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);
  try {
    const r = await fetchWithTimeout(HIBP_URL + prefix, {}, 15000);
    const text = await r.text().catch(() => "");
    if (r.status !== 200) {
      const snippet = String(text || "").replace(/\s+/g, " ").slice(0, 120);
      return { ok: false, status: "error", detail: `HaveIBeenPwned returned HTTP ${r.status}${snippet ? ": " + snippet : ""}` };
    }
    const lines = String(text || "").split(/\r?\n/);
    for (const line of lines) {
      const idx = line.indexOf(":");
      if (idx <= 0) continue;
      if (line.slice(0, idx).trim() === suffix) {
        const count = parseInt(line.slice(idx + 1).trim(), 10) || 0;
        return { ok: true, status: "found", count, sha1Prefix: prefix };
      }
    }
    return { ok: true, status: "not_found", count: 0, sha1Prefix: prefix };
  } catch (e) {
    return { ok: false, status: "error", detail: "HaveIBeenPwned request failed: " + (e && e.name === "AbortError" ? "timeout" : "network") };
  }
}

async function handler(req, res) {
  Object.entries(getCorsHeaders(req)).forEach(([k, v]) => res.setHeader(k, v));
  res.setHeader("Cache-Control", "no-store");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return json(res, 405, { error: "Method not allowed" });

  const cookies = parseCookies(req);
  const rawToken = cookies["mono_session"] || String(req.headers["x-session-token"] || "").trim();
  const session = verifySessionToken(rawToken);
  if (!session.ok) return json(res, 401, { error: session.error || "Login required" });
  if (await isTokenBlacklisted(rawToken)) return json(res, 401, { error: "Session revoked — please log in again" });

  let userBlocked = false;
  for (let i = 1; i <= 50; i++) { const id = String(process.env[`BLACKLISTED_USER${i}`] || "").trim(); if (id === session.userId) { userBlocked = true; break; } }
  if (!userBlocked) { try { const bl = await kv.get(`mono:kv_blacklist:${session.userId}`); if (bl) userBlocked = true; } catch (_) {} }
  if (userBlocked) return json(res, 403, { error: "Your account is not allowed to use this service." });

  let body;
  try {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString();
    if (raw.length > 4096) return json(res, 413, { error: "Request body too large" });
    body = JSON.parse(raw || "{}");
  } catch (_) { return json(res, 400, { error: "Invalid JSON" }); }

  const started = Date.now();

  // ---- Password breach mode ----
  if (body.password !== undefined && body.password !== null && String(body.password).trim() !== "") {
    const password = sanitizePassword(body.password);
    if (!password) return json(res, 400, { error: "Invalid password" });
    const limited = await kvRateLimit(`rl:breachpw:${session.userId}`, 10, 60);
    if (limited) return json(res, 429, { error: "Rate limit reached. Wait a moment." });
    const result = await queryPasswordBreach(password).catch(() => ({ ok: false, status: "error", detail: "Network request failed" }));
    const durationMs = Date.now() - started;
    if (!result.ok) return json(res, 502, { status: result.status, detail: result.detail, durationMs });
    return json(res, 200, {
      mode: "password",
      status: result.status,
      found: result.status === "found",
      count: result.count,
      detail: result.status === "found" ? `This password has appeared in ${result.count} breach records.` : "This password was not found in the breach corpus.",
      durationMs,
    });
  }

  // ---- Email breach mode ----
  const email = sanitizeEmail(body.email);
  if (!email) return json(res, 400, { error: "Invalid email address" });

  const limited = await kvRateLimit(`rl:breachcheck:${session.userId}`, 8, 60);
  if (limited) return json(res, 429, { error: "Rate limit reached. Wait a moment." });

  const result = await queryEmailBreaches(email).catch(() => ({ ok: false, status: "error", detail: "Network request failed" }));
  const durationMs = Date.now() - started;
  if (!result.ok) return json(res, 502, { email, status: result.status, detail: result.detail, breaches: [], count: 0, durationMs });

  return json(res, 200, {
    email,
    mode: "email",
    status: result.status,
    breaches: result.breaches,
    count: result.count,
    detail: result.status === "found" ? `Found in ${result.count} breach record(s).` : "No breach records found for this address.",
    durationMs,
  });
}

module.exports = handler;
module.exports.config = { maxDuration: 30 };
