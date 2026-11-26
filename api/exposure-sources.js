"use strict";

// Additional exposure sources (all key-free, server-side, read-only):
//   - ProxyNova COMB      -> leaked email:password pairs (3.2B records)
//   - XposedOrNot         -> breach names for an email address
//   - Weakpass            -> hash reverse-lookup (MD5/NTLM/SHA1/SHA256 -> plaintext)
//
// Defensive OSINT exposure lookup over publicly indexed breach data.
// Same category as HIBP / Intel X. We only query public read-only APIs and
// never attempt to bypass auth, paywalls, or anti-scraping.

const kv     = require("./kv");
const { kvRateLimit, getCorsHeaders } = require("./middleware");
const { verifySessionToken, isTokenBlacklisted } = require("./session");

const EMAIL_RE = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
const COMB_URL = "https://api.proxynova.com/comb";
const XON_URL = "https://api.xposedornot.com/v1/check-email/";
const WEAK_URL = "https://weakpass.com/api/v1/search/";

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

// hash: strip a leading {TYPE} prefix (e.g. {MD5}, {SHA}), keep hex/base64, lowercase
function sanitizeHash(h) {
  let v = String(h || "").trim().toLowerCase();
  if (v.startsWith("{")) { const end = v.indexOf("}"); if (end > 0) v = v.slice(end + 1); }
  v = v.replace(/[^a-z0-9+/=]/g, "");
  return v.length >= 8 && v.length <= 200 ? v : "";
}

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

function combSourceError(status, body) {
  const snippet = String(body || "").replace(/\s+/g, " ").slice(0, 120);
  if (status === 429) return { ok: false, status: "rate_limit", detail: "ProxyNova COMB rate limit reached." };
  return { ok: false, status: "error", detail: `ProxyNova COMB returned HTTP ${status}${snippet ? ": " + snippet : ""}` };
}
function xonSourceError(status, body) {
  const snippet = String(body || "").replace(/\s+/g, " ").slice(0, 120);
  if (status === 429) return { ok: false, status: "rate_limit", detail: "XposedOrNot rate limit reached." };
  return { ok: false, status: "error", detail: `XposedOrNot returned HTTP ${status}${snippet ? ": " + snippet : ""}` };
}
function weakSourceError(status, body) {
  const snippet = String(body || "").replace(/\s+/g, " ").slice(0, 120);
  if (status === 404) return { ok: false, status: "not_found", detail: "Weakpass has no entry for this hash." };
  if (status === 429) return { ok: false, status: "rate_limit", detail: "Weakpass rate limit reached." };
  return { ok: false, status: "error", detail: `Weakpass returned HTTP ${status}${snippet ? ": " + snippet : ""}` };
}

// ---- ProxyNova COMB: leaked email:password pairs ----
async function queryComb(email) {
  const url = `${COMB_URL}?query=${encodeURIComponent(email)}&start=0&limit=100`;
  try {
    const r = await fetchWithTimeout(url, {}, 15000);
    const text = await r.text().catch(() => "");
    if (r.status !== 200) return combSourceError(r.status, text);
    let data;
    try { data = JSON.parse(text); } catch { return { ok: false, status: "error", detail: "ProxyNova COMB returned invalid JSON." }; }
    const lines = Array.isArray(data.lines) ? data.lines : [];
    const hits = [];
    for (const line of lines) {
      const s = String(line || "");
      const idx = s.indexOf(":");
      if (idx <= 0) continue;
      const login = s.slice(0, idx).trim().slice(0, 254);
      const password = s.slice(idx + 1).trim().slice(0, 254);
      if (!login || !password) continue;
      hits.push({ origin: "ProxyNova COMB", login, password, posted: "—", source: "COMB" });
    }
    return { ok: true, status: hits.length ? "found" : "not_found", detail: "", hitCount: hits.length, total: Number(data.count) || 0, hits };
  } catch (e) {
    return { ok: false, status: "error", detail: "ProxyNova COMB request failed: " + (e && e.name === "AbortError" ? "timeout" : "network") };
  }
}

// ---- XposedOrNot: breach names for an email ----
async function queryXposedOrNot(email) {
  const url = XON_URL + encodeURIComponent(email);
  try {
    const r = await fetchWithTimeout(url, {}, 15000);
    const text = await r.text().catch(() => "");
    if (r.status !== 200) return xonSourceError(r.status, text);
    let data;
    try { data = JSON.parse(text); } catch { return { ok: false, status: "error", detail: "XposedOrNot returned invalid JSON." }; }
    const breaches = Array.isArray(data.breaches) ? data.breaches : [];
    const names = [];
    for (const group of breaches) {
      if (Array.isArray(group)) group.forEach(n => { if (typeof n === "string" && n) names.push(n); });
      else if (typeof group === "string" && group) names.push(group);
    }
    const count = names.length;
    const hit = {
      origin: "XposedOrNot",
      login: email,
      password: "—",
      posted: "—",
      source: `${count} breach${count === 1 ? "" : "es"}`,
      breaches: names.slice(0, 200),
    };
    return { ok: true, status: count ? "found" : "not_found", detail: "", hitCount: 1, total: count, hits: count ? [hit] : [] };
  } catch (e) {
    return { ok: false, status: "error", detail: "XposedOrNot request failed: " + (e && e.name === "AbortError" ? "timeout" : "network") };
  }
}

// ---- Weakpass: hash reverse-lookup ----
async function queryWeakpass(hash) {
  const url = WEAK_URL + encodeURIComponent(hash);
  try {
    const r = await fetchWithTimeout(url, {}, 15000);
    const text = await r.text().catch(() => "");
    if (r.status !== 200) return weakSourceError(r.status, text);
    let data;
    try { data = JSON.parse(text); } catch { return { ok: false, status: "error", detail: "Weakpass returned invalid JSON." }; }
    const pass = typeof data.pass === "string" ? data.pass : "";
    if (!pass) return { ok: true, status: "not_found", detail: "No plaintext found for this hash.", type: data.type || "" };
    return { ok: true, status: "found", detail: "", type: data.type || "", hash: String(data.hash || hash), pass };
  } catch (e) {
    return { ok: false, status: "error", detail: "Weakpass request failed: " + (e && e.name === "AbortError" ? "timeout" : "network") };
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

  // ---- Weakpass hash-lookup mode ----
  if (body.hash !== undefined && body.hash !== null && String(body.hash).trim() !== "") {
    const hash = sanitizeHash(body.hash);
    if (!hash) return json(res, 400, { error: "Invalid hash" });
    const limited = await kvRateLimit(`rl:weakpass:${session.userId}`, 10, 60);
    if (limited) return json(res, 429, { error: "Rate limit reached. Wait a moment." });
    const result = await queryWeakpass(hash).catch(() => ({ ok: false, status: "error", detail: "Network request failed" }));
    const durationMs = Date.now() - started;
    if (!result.ok) return json(res, 502, { hash, status: result.status, detail: result.detail, durationMs });
    return json(res, 200, {
      hash, type: result.type, found: result.status === "found", pass: result.pass || null,
      status: result.status, detail: result.detail, durationMs,
    });
  }

  // ---- Email mode: COMB + XposedOrNot ----
  const email = sanitizeEmail(body.email);
  if (!email) return json(res, 400, { error: "Invalid email address" });

  const sources = Array.isArray(body.sources) ? body.sources.filter(s => ["comb", "xposedornot"].includes(s)) : ["comb", "xposedornot"];
  if (!sources.length) return json(res, 400, { error: "No valid sources selected" });

  const limited = await kvRateLimit(`rl:exposuresrc:${session.userId}`, 6, 60);
  if (limited) return json(res, 429, { error: "Rate limit reached. Wait a moment." });

  const results = {};
  const hits = [];
  for (const src of sources) {
    try {
      if (src === "comb") results.comb = await queryComb(email);
      else if (src === "xposedornot") results.xposedornot = await queryXposedOrNot(email);
    } catch (_) { results[src] = { ok: false, status: "error", detail: "Request failed" }; }
    const r = results[src];
    if (r && r.ok && Array.isArray(r.hits)) hits.push(...r.hits);
  }

  const durationMs = Date.now() - started;
  const anyError = Object.values(results).some(r => r && !r.ok);
  return json(res, anyError ? 502 : 200, {
    email,
    sources,
    status: hits.length ? "found" : (anyError ? "error" : "not_found"),
    detail: "",
    hitCount: hits.length,
    total: hits.reduce((a, h) => a + (Number(h._total) || 0), 0),
    hits,
    results,
    durationMs,
  });
}

module.exports = handler;
module.exports.config = { maxDuration: 40 };
