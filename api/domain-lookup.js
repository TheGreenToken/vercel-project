"use strict";

// Domain Lookup (key-free). Resolves a domain's registration data via RDAP
// (the modern WHOIS replacement), its DNS records, and certificate-transparency
// data from crt.sh. Session-gated, rate-limited, defensive OSINT.
//
// Scope: read-only infrastructure intelligence over public RDAP/DNS/CT data.
// We never attempt to bypass any rate limit, paywall, or auth.

const dns = require("dns").promises;
const kv = require("../lib/kv");
const { kvRateLimit, getCorsHeaders } = require("../lib/middleware");
const { verifySessionToken, isTokenBlacklisted } = require("../lib/session");

const DOMAIN_RE = /^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;

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
function sanitizeDomain(q) {
  const v = String(q || "").trim().toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, "")
    .replace(/\/.*$/, "")
    .replace(/^www\./, "");
  return DOMAIN_RE.test(v) ? v : "";
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
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        ...(opts.headers || {}),
      },
    });
  } finally { clearTimeout(t); }
}

// RDAP is the modern, structured replacement for WHOIS. rdap.org redirects
// (302) to the authoritative registry/registrar server.
async function rdapLookup(domain) {
  try {
    const r = await fetchWithTimeout("https://rdap.org/domain/" + encodeURIComponent(domain), {}, 12000);
    const text = await r.text().catch(() => "");
    if (r.status === 404) return { ok: true, data: null, note: "No RDAP record (domain may not be registered)" };
    if (r.status !== 200) return { ok: false, detail: `RDAP responded HTTP ${r.status}` };
    let data;
    try { data = JSON.parse(text); } catch { return { ok: false, detail: "Invalid RDAP response" }; }

    // Extract registrar from entities (roles include "registrar").
    let registrar = "", registrarUrl = "";
    const entities = Array.isArray(data.entities) ? data.entities : [];
    for (const e of entities) {
      const roles = Array.isArray(e.roles) ? e.roles : [];
      if (roles.includes("registrar")) {
        const vcard = Array.isArray(e.vcardArray) ? e.vcardArray[1] : [];
        for (const item of vcard) {
          if (item[0] === "fn" && item[3]) registrar = String(item[3]);
          if (item[0] === "url" && item[3]) registrarUrl = String(item[3]);
        }
        if (!registrar && e.handle) registrar = String(e.handle);
      }
    }

    const events = {};
    for (const ev of (Array.isArray(data.events) ? data.events : [])) {
      if (ev && ev.eventAction) events[ev.eventAction] = ev.eventDate || null;
    }

    return {
      ok: true,
      data: {
        handle: data.handle || "",
        registrar,
        registrarUrl,
        status: Array.isArray(data.status) ? data.status : [],
        nameservers: (Array.isArray(data.nameservers) ? data.nameservers : []).map(n => (n && n.ldhName) || "").filter(Boolean),
        events,
        secureDNS: { delegationSigned: !!(data.secureDNS && data.secureDNS.delegationSigned), dnssec: !!(data.secureDNS && data.secureDNS.delegationSigned) },
      },
    };
  } catch (e) {
    return { ok: false, detail: "RDAP lookup failed: " + (e && e.name === "AbortError" ? "timeout" : "network") };
  }
}

// Certificate transparency logs via crt.sh (key-free).
async function certLookup(domain) {
  try {
    const r = await fetchWithTimeout("https://crt.sh/?q=" + encodeURIComponent(domain) + "&output=json", {}, 15000);
    if (r.status !== 200) return { ok: false, detail: `crt.sh responded HTTP ${r.status}` };
    let entries;
    try { entries = JSON.parse(await r.text()); } catch { return { ok: false, detail: "Invalid crt.sh response" }; }
    if (!Array.isArray(entries) || !entries.length) return { ok: true, data: { issuer: "", validFrom: "", validTo: "", subdomains: [] } };

    const seen = new Set();
    let issuer = "", validFrom = "", validTo = "";
    const subdomains = [];
    for (const e of entries) {
      if (!issuer && e.issuer_name) issuer = String(e.issuer_name);
      if (!validFrom && e.not_before) validFrom = String(e.not_before).slice(0, 10);
      if (!validTo && e.not_after) validTo = String(e.not_after).slice(0, 10);
      const names = String(e.name_value || "").split(/[\n,]/);
      for (const raw of names) {
        const name = raw.trim().replace(/^\*\./, "").toLowerCase();
        if (name && name.endsWith("." + domain)) {
          const base = name.slice(0, -(domain.length + 1));
          if (base && !seen.has(base)) { seen.add(base); subdomains.push(base); }
        }
      }
      if (subdomains.length >= 40) break;
    }
    return { ok: true, data: { issuer, validFrom, validTo, subdomains: subdomains.sort() } };
  } catch (e) {
    return { ok: false, detail: "crt.sh lookup failed: " + (e && e.name === "AbortError" ? "timeout" : "network") };
  }
}

// DNS record set.
async function dnsLookup(domain) {
  const out = { A: [], AAAA: [], MX: [], NS: [], TXT: [], CNAME: "", SOA: "", hasIP: false };
  const safe = async (fn, setter) => { try { const v = await fn(); setter(v); } catch (_) {} };
  await Promise.all([
    safe(() => dns.resolve4(domain), v => { out.A = v; out.hasIP = true; }),
    safe(() => dns.resolve6(domain), v => { out.AAAA = v; out.hasIP = true; }),
    safe(() => dns.resolveMx(domain), v => { out.MX = v.map(m => `${m.priority} ${m.exchange}`).sort(); }),
    safe(() => dns.resolveNs(domain), v => { out.NS = v; }),
    safe(() => dns.resolveTxt(domain), v => { out.TXT = v.map(s => s.join(" ")); }),
    safe(() => dns.resolveCname(domain), v => { out.CNAME = v; }),
    safe(() => dns.resolveSoa(domain), v => { out.SOA = `${v.nsname} ${v.mname} serial=${v.serial}`; }),
  ]);
  return out;
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

  const domain = sanitizeDomain(body.domain);
  if (!domain) return json(res, 400, { error: "Enter a valid domain (e.g. example.com)" });

  const limited = await kvRateLimit(`rl:domainlookup:${session.userId}`, 10, 60);
  if (limited) return json(res, 429, { error: "Rate limit reached. Wait a moment." });

  const started = Date.now();
  const [rdap, cert, dns] = await Promise.all([
    rdapLookup(domain),
    certLookup(domain),
    dnsLookup(domain),
  ]);

  const durationMs = Date.now() - started;
  if (!rdap.ok && !cert.ok && !dns.A.length && !dns.AAAA.length) {
    return json(res, 502, { domain, status: "error", detail: rdap.detail || cert.detail || "Lookup failed", dns, durationMs });
  }

  return json(res, 200, {
    domain,
    status: rdap.ok && rdap.data ? "found" : "partial",
    whois: rdap.ok ? rdap.data : null,
    rdapNote: rdap.note || "",
    rdapError: rdap.ok ? "" : (rdap.detail || ""),
    cert: cert.ok ? cert.data : null,
    certError: cert.ok ? "" : (cert.detail || ""),
    dns,
    durationMs,
  });
}

module.exports = handler;
module.exports.config = { maxDuration: 30 };
