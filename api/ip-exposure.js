"use strict";

// IP Exposure Lookup (free web search, no API token). Uses the same
// stealerlogs.com method as the email Exposure Search, but queries with
// type=ip. Scrapes the rendered result table for an IP identifier and returns
// normalized hits. Session-gated, rate-limited, defensive.
//
// Scope: read-only exposure lookup over publicly indexed stealer-log hits.
// The free web search only exposes partial logins/passwords; we pass those
// through as-is and never attempt to bypass any paywall, auth, or
// anti-scraping.

const kv     = require("../lib/kv");
const { kvRateLimit, getCorsHeaders } = require("../lib/middleware");
const { verifySessionToken, isTokenBlacklisted } = require("../lib/session");
const { appendLookup, makeEntry } = require("../lib/lookuplog");
const { searchStealthlogs } = require("../lib/stealerlogs");

const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;

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
function sanitizeIp(v) {
  const s = String(v || "").trim().slice(0, 64);
  if (IPV4_RE.test(s)) return s;
  // loose IPv6 literal check (colons + hex)
  if (/^[0-9a-fA-F:]+$/.test(s) && s.indexOf(":") >= 0) return s.toLowerCase();
  return "";
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

  const ip = sanitizeIp(body.ip);
  if (!ip) return json(res, 400, { error: "Enter a valid IPv4 or IPv6 address" });

  const limited = await kvRateLimit(`rl:ipexposure:${session.userId}`, 6, 60);
  if (limited) return json(res, 429, { error: "Rate limit reached. Wait a moment." });

  const started = Date.now();
  const result = await searchStealthlogs(ip, "ip").catch(() => ({ ok: false, status: "error", detail: "Network request failed" }));
  const durationMs = Date.now() - started;

  if (!result.ok) {
    await appendLookup(session.userId, makeEntry("ip_exposure", ip, "error", durationMs)).catch(() => {});
    return json(res, 502, { ip, status: result.status, detail: result.detail, hits: [], total: 0, durationMs });
  }

  const hits = result.parsed.hits;
  await appendLookup(session.userId, makeEntry("ip_exposure", ip, result.status, durationMs)).catch(() => {});
  return json(res, 200, {
    ip,
    status: result.status,
    detail: result.detail,
    total: result.parsed.total,
    page: result.parsed.page,
    totalPages: result.parsed.totalPages,
    hitCount: hits.length,
    hits,
    durationMs,
  });
}

module.exports = handler;
module.exports.config = { maxDuration: 60 };
