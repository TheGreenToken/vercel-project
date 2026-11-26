"use strict";

// IP / Host Lookup (key-free). Resolves a hostname to an IP, geolocates the
// address via ip-api.com (free web tier, no token), and runs a reverse-DNS
// lookup. Session-gated, rate-limited, defensive.
//
// Scope: read-only infrastructure intelligence over public DNS and a public
// geolocation service (same category as ipinfo / ip-api free endpoints). We
// never attempt to bypass any rate limit, paywall, or auth.

const dns = require("dns").promises;
const kv = require("./kv");
const { kvRateLimit, getCorsHeaders } = require("./middleware");
const { verifySessionToken, isTokenBlacklisted } = require("./session");

const IPAPI_BASE = "http://ip-api.com/json/";
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/;

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

// A query is a valid IPv4/IPv6 literal or a hostname.
function sanitizeQuery(q) {
  const v = String(q || "").trim().slice(0, 253);
  if (!v) return "";
  if (IPV4_RE.test(v)) return v;
  // loose IPv6 literal check (contains colons and only hex/colons)
  if (/^[0-9a-fA-F:]+$/.test(v) && v.indexOf(":") >= 0) return v;
  // hostname: labels of [a-zA-Z0-9-], total length sane, not a path/url
  if (/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/.test(v)) return v;
  return "";
}

async function fetchWithTimeout(url, opts = {}, ms = 12000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, {
      ...opts,
      signal: ctrl.signal,
      redirect: opts.redirect || "follow",
      headers: {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9",
        ...(opts.headers || {}),
      },
    });
  } finally { clearTimeout(t); }
}

// Forward resolution: if the query is a hostname, resolve it to an IP.
async function resolveTarget(query) {
  if (IPV4_RE.test(query) || (/^[0-9a-fA-F:]+$/.test(query) && query.indexOf(":") >= 0)) {
    return { query, ip: query, type: query.indexOf(":") >= 0 ? "ipv6" : "ipv4", source: "literal" };
  }
  try {
    const { address, family } = await dns.lookup(query, { all: false });
    return { query, ip: address, type: family === 6 ? "ipv6" : "ipv4", source: "dns" };
  } catch (_) {
    return { query, ip: "", type: "", source: "unresolved", error: "Hostname could not be resolved (NXDOMAIN or no DNS record)" };
  }
}

// Reverse DNS for an IP (best-effort, returns [] on failure).
async function reverseLookup(ip) {
  if (!ip) return [];
  try {
    const names = await dns.reverse(ip);
    return (names || []).filter(Boolean).slice(0, 5);
  } catch (_) {
    return [];
  }
}

// Geolocation + ASN/ISP via ip-api.com free endpoint.
async function geoLookup(ip) {
  if (!ip) return { ok: false, detail: "No IP to geolocate" };
  try {
    const r = await fetchWithTimeout(IPAPI_BASE + encodeURIComponent(ip), {}, 10000);
    const text = await r.text().catch(() => "");
    if (r.status !== 200) {
      return { ok: false, detail: `Geolocation service responded HTTP ${r.status}` };
    }
    let data;
    try { data = JSON.parse(text); } catch { return { ok: false, detail: "Invalid geolocation response" }; }
    if (data.status && data.status !== "success") {
      return { ok: false, detail: `Geolocation: ${data.message || "lookup failed"}` };
    }
    return {
      ok: true,
      geo: {
        country: data.country || "",
        countryCode: data.countryCode || "",
        region: data.regionName || data.region || "",
        city: data.city || "",
        zip: data.zip || "",
        lat: data.lat != null ? data.lat : null,
        lon: data.lon != null ? data.lon : null,
        timezone: data.timezone || "",
        isp: data.isp || "",
        org: data.org || "",
        as: data.as || "",
        asname: data.asname || "",
        reverse: data.reverse || "",
        mobile: !!data.mobile,
        proxy: !!data.proxy,
        hosting: !!data.hosting,
      },
    };
  } catch (e) {
    return { ok: false, detail: "Geolocation service timed out or failed: " + (e && e.name === "AbortError" ? "timeout" : "network") };
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

  const query = sanitizeQuery(body.query);
  if (!query) return json(res, 400, { error: "Enter a valid IP address or hostname" });

  const limited = await kvRateLimit(`rl:iplookup:${session.userId}`, 10, 60);
  if (limited) return json(res, 429, { error: "Rate limit reached. Wait a moment." });

  const started = Date.now();
  const target = await resolveTarget(query);
  if (target.error) {
    return json(res, 200, { query, status: "not_found", detail: target.error, ip: "", type: "", geo: null, reverse: [], durationMs: Date.now() - started });
  }

  const [geoRes, reverse] = await Promise.all([
    geoLookup(target.ip),
    reverseLookup(target.ip),
  ]);

  const durationMs = Date.now() - started;

  if (!geoRes.ok) {
    // reverse DNS may still be useful even if geo failed
    return json(res, 502, { query, status: "error", detail: geoRes.detail, ip: target.ip, type: target.type, geo: null, reverse, durationMs });
  }

  return json(res, 200, {
    query,
    status: "found",
    ip: target.ip,
    type: target.type,
    source: target.source,
    geo: geoRes.geo,
    reverse,
    durationMs,
  });
}

module.exports = handler;
module.exports.config = { maxDuration: 30 };
