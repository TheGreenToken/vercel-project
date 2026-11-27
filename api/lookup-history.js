"use strict";

// Lookup activity history. Returns the authenticated user's recent lookups
// across all tools (github, email, exposure, ip, domain, username), recorded
// server-side by each tool endpoint. Session-gated, read/clear only.

const kv = require("../lib/kv");
const { getCorsHeaders } = require("../lib/middleware");
const { verifySessionToken, isTokenBlacklisted } = require("../lib/session");
const { getLookups, clearLookups } = require("../lib/lookuplog");

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

async function handler(req, res) {
  Object.entries(getCorsHeaders(req)).forEach(([k, v]) => res.setHeader(k, v));
  res.setHeader("Cache-Control", "no-store");
  if (req.method === "OPTIONS") return res.status(204).end();

  const cookies = parseCookies(req);
  const rawToken = cookies["mono_session"] || String(req.headers["x-session-token"] || "").trim();
  const session = verifySessionToken(rawToken);
  if (!session.ok) return json(res, 401, { error: session.error || "Login required" });
  if (await isTokenBlacklisted(rawToken)) return json(res, 401, { error: "Session revoked — please log in again" });

  let userBlocked = false;
  for (let i = 1; i <= 50; i++) { const id = String(process.env[`BLACKLISTED_USER${i}`] || "").trim(); if (id === session.userId) { userBlocked = true; break; } }
  if (!userBlocked) { try { const bl = await kv.get(`mono:kv_blacklist:${session.userId}`); if (bl) userBlocked = true; } catch (_) {} }
  if (userBlocked) return json(res, 403, { error: "Your account is not allowed to use this service." });

  // POST { action: "clear" } clears the log; GET returns it.
  if (req.method === "POST") {
    let body = {};
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const raw = Buffer.concat(chunks).toString();
      if (raw.length > 4096) return json(res, 413, { error: "Request body too large" });
      body = JSON.parse(raw || "{}");
    } catch (_) { return json(res, 400, { error: "Invalid JSON" }); }
    if (body.action === "clear") {
      await clearLookups(session.userId).catch(() => {});
      return json(res, 200, { cleared: true });
    }
    return json(res, 200, { entries: await getLookups(session.userId) });
  }

  if (req.method !== "GET") return json(res, 405, { error: "Method not allowed" });

  const entries = await getLookups(session.userId);
  return json(res, 200, { entries });
}

module.exports = handler;
module.exports.config = { maxDuration: 15 };
