"use strict";

// stealerlogs.com exposure search (free web search, no API token).
// Scrapes the server-rendered result table for an email identifier and
// returns normalized hits. Session-gated, rate-limited, defensive parser.
//
// Notes on scope: this is a read-only exposure lookup over publicly
// indexed stealer-log hits (same category as HIBP / Intel X). The free
// web search only exposes partial logins/passwords; we pass those through
// as-is and never attempt to bypass any paywall, auth, or anti-scraping.

const kv     = require("../lib/kv");
const { kvRateLimit, getCorsHeaders } = require("../lib/middleware");
const { verifySessionToken, isTokenBlacklisted } = require("../lib/session");

const EMAIL_RE = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
const SEARCH_BASE = "https://stealerlogs.com/search";

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
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        ...(opts.headers || {}),
      },
    });
  } finally { clearTimeout(t); }
}

// ---- minimal, defensive HTML table parser (no external deps) ----
function stripTags(s) {
  return String(s || "")
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
}
function decodeEntities(s) {
  return String(s || "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/g, "'");
}

function parseTables(html) {
  if (!html) return [];
  // isolate <table>...</table> blocks
  const tables = [];
  const re = /<table\b[^>]*>([\s\S]*?)<\/table>/gi;
  let m;
  while ((m = re.exec(html)) !== null) tables.push(m[1]);
  return tables;
}

function parseRows(tableHtml) {
  const rows = [];
  const re = /<tr\b[^>]*>([\s\S]*?)<\/tr>/gi;
  let m;
  while ((m = re.exec(tableHtml)) !== null) {
    const cells = [];
    const cre = /<t[dh]\b[^>]*>([\s\S]*?)<\/t[dh]>/gi;
    let c;
    while ((c = cre.exec(m[1])) !== null) cells.push(stripTags(decodeEntities(c[1])));
    if (cells.length) rows.push(cells);
  }
  return rows;
}

function findResultTable(html) {
  const tables = parseTables(html);
  // pick the table that contains a header cell mentioning "Origin" or "Login"
  for (const t of tables) {
    const head = /Origin|Login|Password/i.test(t);
    if (head) return t;
  }
  // fallback: largest table by row count
  let best = "";
  for (const t of tables) { if (t.length > best.length) best = t; }
  return best;
}

function parseSearchResults(html) {
  const out = { total: 0, page: 1, pageSize: 0, totalPages: 0, hits: [] };
  if (!html) return out;

  // total count line, e.g. "10,000 records · 1–25 · page 1 of 400"
  const totalM = /([\d,]+)\s*records?/i.exec(html);
  if (totalM) out.total = parseInt(totalM[1].replace(/,/g, ""), 10) || 0;
  const pageM = /page\s+(\d+)\s+of\s+(\d+)/i.exec(html);
  if (pageM) { out.page = parseInt(pageM[1], 10) || 1; out.totalPages = parseInt(pageM[2], 10) || 0; }
  const rangeM = /(\d+)\s*[–-]\s*(\d+)/.exec(html);
  if (rangeM) out.pageSize = parseInt(rangeM[2], 10) || 0;

  const table = findResultTable(html);
  if (!table) return out;

  const rows = parseRows(table);
  if (!rows.length) return out;

  // Determine header + column order if a header row is present.
  let header = null;
  let bodyStart = 0;
  const first = rows[0].map(c => c.toLowerCase());
  if (/origin|login|password|posted|source|files/.test(first.join(" "))) {
    header = first;
    bodyStart = 1;
  }
  const idx = (name) => {
    if (!header) return -1;
    return header.indexOf(name);
  };
  const iOrigin = idx("origin");
  const iLogin  = idx("login");
  const iPass   = idx("password");
  const iPosted = idx("posted");
  const iSource = idx("source");
  const iFiles  = idx("files");
  // If no header, assume fixed order: origin, login, password, posted, source, files
  const coord = (row, i) => (i >= 0 ? row[i] : (i >= 0 ? undefined : undefined));

  for (let r = bodyStart; r < rows.length; r++) {
    const row = rows[r];
    if (row.length < 2) continue;
    const origin  = iOrigin >= 0 ? (row[iOrigin] || "") : (row[0] || "");
    const login   = iLogin  >= 0 ? (row[iLogin]  || "") : (row[1] || "");
    const password = iPass  >= 0 ? (row[iPass]  || "") : (row[2] || "");
    const posted  = iPosted >= 0 ? (row[iPosted] || "") : (row[3] || "");
    const source  = iSource >= 0 ? (row[iSource] || "") : (row[4] || "");
    const files   = iFiles  >= 0 ? (row[iFiles]  || "") : (row[5] || "");
    const hasData = origin || login || password;
    if (!hasData) continue;
    out.hits.push({
      origin: String(origin).slice(0, 200),
      login: String(login).slice(0, 200),
      password: String(password).slice(0, 120),
      posted: String(posted).slice(0, 120),
      source: String(source).slice(0, 120),
      files: String(files).slice(0, 40),
    });
  }

  if (!out.pageSize && out.hits.length) out.pageSize = out.hits.length;
  return out;
}

// Parse a Markdown table (as rendered by the JS-rendering fetch) into hits.
// Header: | Origin | Login | Password | Posted | Source | Files |
function parseMarkdownTable(md) {
  const out = { total: 0, page: 1, pageSize: 0, totalPages: 0, hits: [] };
  if (!md) return out;
  const lines = String(md).split(/\r?\n/);

  const totalM = /([\d,]+)\s*records?/i.exec(md);
  if (totalM) out.total = parseInt(totalM[1].replace(/,/g, ""), 10) || 0;
  const pageM = /page\s+(\d+)\s+of\s+(\d+)/i.exec(md);
  if (pageM) { out.page = parseInt(pageM[1], 10) || 1; out.totalPages = parseInt(pageM[2], 10) || 0; }
  const rangeM = /(\d+)\s*[–-]\s*(\d+)/.exec(md);
  if (rangeM) out.pageSize = parseInt(rangeM[2], 10) || 0;

  // find the table header row
  let headerIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (/^\|.*Origin.*\|/i.test(lines[i]) && /Login/i.test(lines[i])) { headerIdx = i; break; }
  }
  if (headerIdx < 0) return out;

  const splitRow = (line) => line.replace(/^\|/, "").replace(/\|$/, "").split("|").map(c => decodeEntities(stripTags(c)).trim());
  const header = splitRow(lines[headerIdx]).map(c => c.toLowerCase());
  const iOrigin = header.indexOf("origin");
  const iLogin  = header.indexOf("login");
  const iPass   = header.indexOf("password");
  const iPosted = header.indexOf("posted");
  const iSource = header.indexOf("source");
  const iFiles  = header.indexOf("files");

  // skip separator row (| --- | --- |)
  let r = headerIdx + 1;
  if (r < lines.length && /^\|[\s:\-|]+\|$/.test(lines[r].trim())) r++;

  for (; r < lines.length; r++) {
    const line = lines[r];
    if (!/^\|/.test(line)) break;
    const cells = splitRow(line);
    const origin   = iOrigin >= 0 ? (cells[iOrigin] || "") : "";
    const login    = iLogin  >= 0 ? (cells[iLogin]  || "") : "";
    const password = iPass   >= 0 ? (cells[iPass]   || "") : "";
    const posted   = iPosted >= 0 ? (cells[iPosted] || "") : "";
    const source   = iSource >= 0 ? (cells[iSource] || "") : "";
    const files    = iFiles  >= 0 ? (cells[iFiles]  || "") : "";
    if (!origin && !login && !password) continue;
    out.hits.push({
      origin: String(origin).slice(0, 200),
      login: String(login).slice(0, 200),
      password: String(password).slice(0, 120),
      posted: String(posted).slice(0, 120),
      source: String(source).slice(0, 120),
      files: String(files).slice(0, 40),
    });
  }

  if (!out.pageSize && out.hits.length) out.pageSize = out.hits.length;
  return out;
}

// stealerlogs.com is a Next.js SPA: search results are rendered client-side,
// so a plain HTML fetch only yields a "Searching…" skeleton (no <table>).
// We use a server-side JS-rendering fetch (r.jina.ai reader) that executes the
// page JS and returns the rendered Markdown table. This is the same free web
// tier (partial credentials) the site exposes to a browser; no API token and no
// paywall bypass. Any reader error is surfaced (not silently masked by the
// empty skeleton) so the UI can show the real reason instead of "no hits".
const RENDER_BASE = "https://r.jina.ai/";
function readerError(status, body) {
  const low = String(body || "").toLowerCase();
  const snippet = String(body || "").replace(/\s+/g, " ").slice(0, 120);
  if (status === 429 || low.includes("rate limit") || low.includes("too many requests"))
    return { ok: false, status: "rate_limit", detail: `Exposure index rate limited the request${snippet ? ` · ${snippet}` : ""}` };
  if (status === 401 || status === 403 || low.includes("unauthorized") || low.includes("api key"))
    return { ok: false, status: "error", detail: `Rendering reader rejected the request (auth/IP)${snippet ? ` · ${snippet}` : ""}` };
  if (status === 404) return { ok: false, status: "error", detail: `Rendering reader: target not found${snippet ? ` · ${snippet}` : ""}` };
  return { ok: false, status: "error", detail: `Rendering reader responded HTTP ${status}${snippet ? ` · ${snippet}` : ""}` };
}
async function searchEmail(email) {
  const targetUrl = `${SEARCH_BASE}?q=${encodeURIComponent(email)}&type=email`;
  // 1) JS-rendered markdown via reader (primary path)
  try {
    const r = await fetchWithTimeout(`${RENDER_BASE}${targetUrl}`, { headers: { "X-Return-Format": "markdown" } }, 45000);
    const md = await r.text().catch(() => "");
    if (r.status === 200 && md) {
      // reader may wrap JSON error even on 200
      if (/"error"\s*:/.test(md) && !/Origin/i.test(md)) {
        return readerError(200, md);
      }
      const parsed = parseMarkdownTable(md);
      const noResults = /no more results found/i.test(md);
      if (parsed.hits.length || noResults || parsed.total) {
        return { ok: true, status: parsed.hits.length ? "found" : (noResults ? "not_found" : "inconclusive"), detail: noResults ? "No hits in the index" : "", parsed };
      }
      // 200 but no recognizable table — the rendered page may not have loaded
      // results in time; treat as inconclusive rather than masking as not_found.
      return { ok: true, status: "inconclusive", detail: "Rendered page did not contain results", parsed };
    }
    return readerError(r.status, md);
  } catch (e) {
    // network/abort — do NOT fall through to the empty skeleton; surface it
    return { ok: false, status: "error", detail: "Rendering reader timed out or failed: " + (e && e.name === "AbortError" ? "timeout" : "network") };
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

  const email = sanitizeEmail(body.email);
  if (!email) return json(res, 400, { error: "Invalid email address" });

  const limited = await kvRateLimit(`rl:stealercheck:${session.userId}`, 6, 60);
  if (limited) return json(res, 429, { error: "Rate limit reached. Wait a moment." });

  const started = Date.now();
  const result = await searchEmail(email).catch(() => ({ ok: false, status: "error", detail: "Network request failed" }));
  const durationMs = Date.now() - started;

  if (!result.ok) {
    return json(res, 502, { email, status: result.status, detail: result.detail, hits: [], total: 0, durationMs });
  }

  const hits = result.parsed.hits;
  return json(res, 200, {
    email,
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
