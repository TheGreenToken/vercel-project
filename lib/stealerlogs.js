"use strict";

// Shared stealerlogs.com scraping logic used by both the email Exposure Search
// and the IP Exposure module.
//
// stealerlogs.com is a Next.js App-Router app. Two data paths exist:
//
// 1) Server Action (PRIMARY, supports pagination):
//    POST https://stealerlogs.com/search?q=<q>&type=<type>
//    Headers: Accept: text/x-component
//             next-action: <ACTION_ID>            (build-specific hash)
//             next-router-state-tree: <tree>      (search route tree)
//             Content-Type: application/json
//    Body: [{"q": "<q>", "type": "<type>", "wildcard": false, "files": false, "page": N}]
//    Returns React Server Component flight data (text/x-component). The result
//    object {"ok":true,"hits":[...],"total":N,"partial":true} is one line of
//    that flight data, which we parse back to JSON. Page size is 25, so we
//    walk pages 1..maxPages and aggregate.
//
// 2) r.jina.ai reader (FALLBACK, page 1 only): renders the search page and
//    parses the Markdown result table. Used when the Server Action is blocked
//    or the build hash changes.
//
// Free web tier only exposes partial (masked) credentials; we pass those
// through as-is and never attempt to bypass any paywall, auth, or
// anti-scraping.

const SEARCH_BASE = "https://stealerlogs.com/search";
const RENDER_BASE = "https://r.jina.ai/";

// Build-specific Server Action id + search-route state tree, captured from the
// live site. These change when stealerlogs redeploys; if they go stale the
// action path fails and we transparently fall back to the reader (page 1).
const ACTION_ID = "40599c346155bbce5c7c61e71e4e3ab60fce52f10e";
const STATE_TREE = encodeURIComponent(
  '["",{"children":["search",{"children":["__PAGE__",{},null,null,4096]},null,null,4100]},null,null,4120]'
);
const PAGE_SIZE = 25;

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

// ---- minimal, defensive HTML/Markdown parsers (no external deps) ----
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
  for (const t of tables) {
    if (/Origin|Login|Password/i.test(t)) return t;
  }
  let best = "";
  for (const t of tables) { if (t.length > best.length) best = t; }
  return best;
}

function parseSearchResults(html) {
  const out = { total: 0, page: 1, pageSize: 0, totalPages: 0, hits: [] };
  if (!html) return out;
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
  let header = null;
  let bodyStart = 0;
  const first = rows[0].map(c => c.toLowerCase());
  if (/origin|login|password|posted|source|files/.test(first.join(" "))) { header = first; bodyStart = 1; }
  const idx = (name) => (header ? header.indexOf(name) : -1);
  const iOrigin = idx("origin"), iLogin = idx("login"), iPass = idx("password"), iPosted = idx("posted"), iSource = idx("source"), iFiles = idx("files");
  for (let r = bodyStart; r < rows.length; r++) {
    const row = rows[r];
    if (row.length < 2) continue;
    const origin = iOrigin >= 0 ? (row[iOrigin] || "") : (row[0] || "");
    const login = iLogin >= 0 ? (row[iLogin] || "") : (row[1] || "");
    const password = iPass >= 0 ? (row[iPass] || "") : (row[2] || "");
    const posted = iPosted >= 0 ? (row[iPosted] || "") : (row[3] || "");
    const source = iSource >= 0 ? (row[iSource] || "") : (row[4] || "");
    const files = iFiles >= 0 ? (row[iFiles] || "") : (row[5] || "");
    if (!origin && !login && !password) continue;
    out.hits.push({ origin: String(origin).slice(0, 200), login: String(login).slice(0, 200), password: String(password).slice(0, 120), posted: String(posted).slice(0, 120), source: String(source).slice(0, 120), files: String(files).slice(0, 40) });
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

  let headerIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (/^\|.*Origin.*\|/i.test(lines[i]) && /Login/i.test(lines[i])) { headerIdx = i; break; }
  }
  if (headerIdx < 0) return out;

  const splitRow = (line) => line.replace(/^\|/, "").replace(/\|$/, "").split("|").map(c => decodeEntities(stripTags(c)).trim());
  const header = splitRow(lines[headerIdx]).map(c => c.toLowerCase());
  const iOrigin = header.indexOf("origin");
  const iLogin = header.indexOf("login");
  const iPass = header.indexOf("password");
  const iPosted = header.indexOf("posted");
  const iSource = header.indexOf("source");
  const iFiles = header.indexOf("files");

  let r = headerIdx + 1;
  if (r < lines.length && /^\|[\s:\-|]+$/.test(lines[r].trim())) r++;

  for (; r < lines.length; r++) {
    const line = lines[r];
    if (!/^\|/.test(line)) break;
    const cells = splitRow(line);
    const origin = iOrigin >= 0 ? (cells[iOrigin] || "") : "";
    const login = iLogin >= 0 ? (cells[iLogin] || "") : "";
    const password = iPass >= 0 ? (cells[iPass] || "") : "";
    const posted = iPosted >= 0 ? (cells[iPosted] || "") : "";
    const source = iSource >= 0 ? (cells[iSource] || "") : "";
    const files = iFiles >= 0 ? (cells[iFiles] || "") : "";
    if (!origin && !login && !password) continue;
    out.hits.push({ origin: String(origin).slice(0, 200), login: String(login).slice(0, 200), password: String(password).slice(0, 120), posted: String(posted).slice(0, 120), source: String(source).slice(0, 120), files: String(files).slice(0, 40) });
  }
  if (!out.pageSize && out.hits.length) out.pageSize = out.hits.length;
  return out;
}

// Extract the result payload {"ok":true,"hits":[...],"total":N} from React
// Server Component flight data. Each line is "<id>:<json>"; we scan for the
// line whose JSON carries a hits array.
function parseRscPayload(text) {
  if (!text) return null;
  const lines = String(text).split(/\r?\n/);
  for (const line of lines) {
    const m = /^\d+:(.*)$/.exec(line);
    if (!m) continue;
    const s = m[1].trim();
    if (!s.startsWith("{")) continue;
    try {
      const obj = JSON.parse(s);
      if (obj && Array.isArray(obj.hits)) return obj;
    } catch (_) { /* not this line */ }
  }
  return null;
}

function formatPosted(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return String(iso).slice(0, 120);
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const h = d.getHours();
  const min = d.getMinutes();
  const ampm = h >= 12 ? "PM" : "AM";
  const hh = h % 12 || 12;
  return `${months[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()}, ${hh}:${String(min).padStart(2, "0")} ${ampm}`;
}

function mapActionHit(h) {
  return {
    id: String(h.id || "").slice(0, 64),
    origin: String(h.origin || "").slice(0, 200),
    login: String(h.login || "").slice(0, 200),
    password: String(h.password || "").slice(0, 120),
    posted: formatPosted(h.timePosted),
    source: String(h.source || "").slice(0, 120),
    files: String(h.files || "").slice(0, 40),
  };
}

// Fetch one page via the Next.js Server Action. Returns the parsed payload or
// null (with a best-effort status hint) on failure.
async function fetchSearchPageViaAction(query, type, page) {
  const url = `${SEARCH_BASE}?q=${encodeURIComponent(query)}&type=${encodeURIComponent(type)}`;
  const body = JSON.stringify([{ q: query, type, wildcard: false, files: false, page }]);
  try {
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: {
        "Accept": "text/x-component",
        "Content-Type": "application/json",
        "next-action": ACTION_ID,
        "next-router-state-tree": STATE_TREE,
      },
      body,
    }, 30000);
    const text = await r.text().catch(() => "");
    if (!r.ok) {
      const low = text.toLowerCase();
      if (r.status === 401 || r.status === 403 || low.includes("unauthorized")) return { payload: null, blocked: true };
      return { payload: null, blocked: false };
    }
    const payload = parseRscPayload(text);
    if (!payload) return { payload: null, blocked: false };
    return { payload, blocked: false };
  } catch (e) {
    return { payload: null, blocked: false, error: (e && e.name === "AbortError" ? "timeout" : "network") };
  }
}

// Walk pages 1..maxPages via the Server Action and aggregate hits.
async function searchViaAction(query, type, maxPages) {
  const allHits = [];
  const seen = new Set();
  let total = 0;
  let totalPages = 0;
  let lastPage = 0;
  let page1Ok = false;

  for (let p = 1; p <= maxPages; p++) {
    const { payload } = await fetchSearchPageViaAction(query, type, p);
    if (!payload) {
      if (p === 1) return { ok: false }; // action path unavailable -> fall back
      break; // later page failed; keep what we have
    }
    page1Ok = true;
    if (payload.total) total = payload.total;
    const hits = Array.isArray(payload.hits) ? payload.hits : [];
    if (!hits.length) {
      if (p === 1) return { ok: false }; // empty first page is not a valid action result
      break;
    }
    for (const h of hits) {
      const mapped = mapActionHit(h);
      const key = mapped.id || `${mapped.origin}|${mapped.login}|${mapped.password}`;
      if (seen.has(key)) continue;
      seen.add(key);
      allHits.push(mapped);
    }
    lastPage = p;
    if (hits.length < PAGE_SIZE) break; // last page
  }

  if (!page1Ok) return { ok: false };

  if (total > 0) totalPages = Math.ceil(total / PAGE_SIZE);
  const status = allHits.length ? "found" : (total > 0 ? "inconclusive" : "not_found");
  return {
    ok: true,
    status,
    detail: allHits.length ? `${allHits.length} hits across ${lastPage} page(s)` : "",
    parsed: { total, page: lastPage, totalPages, pageSize: PAGE_SIZE, hits: allHits },
  };
}

// Reader fallback: render page 1 and parse the Markdown table.
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

async function searchViaReader(query, type) {
  const targetUrl = `${SEARCH_BASE}?q=${encodeURIComponent(query)}&type=${encodeURIComponent(type)}`;
  try {
    const r = await fetchWithTimeout(`${RENDER_BASE}${targetUrl}`, { headers: { "X-Return-Format": "markdown" } }, 45000);
    const md = await r.text().catch(() => "");
    if (r.status === 200 && md) {
      if (/"error"\s*:/.test(md) && !/Origin/i.test(md)) {
        return readerError(200, md);
      }
      const parsed = parseMarkdownTable(md);
      const noResults = /no more results found/i.test(md);
      if (parsed.hits.length || noResults || parsed.total) {
        return { ok: true, status: parsed.hits.length ? "found" : (noResults ? "not_found" : "inconclusive"), detail: noResults ? "No hits in the index" : "", parsed };
      }
      return { ok: true, status: "inconclusive", detail: "Rendered page did not contain results", parsed };
    }
    return readerError(r.status, md);
  } catch (e) {
    return { ok: false, status: "error", detail: "Rendering reader timed out or failed: " + (e && e.name === "AbortError" ? "timeout" : "network") };
  }
}

// Core search: page through the Server Action (primary), falling back to the
// reader (page 1) when the action path is unavailable. type is "email" or "ip".
async function searchStealthlogs(query, type, opts = {}) {
  const maxPages = Math.min(Math.max(1, parseInt(opts.maxPages, 10) || 5), 20);
  const actionResult = await searchViaAction(query, type, maxPages);
  if (actionResult && actionResult.ok) return actionResult;
  return searchViaReader(query, type);
}

module.exports = {
  SEARCH_BASE,
  ACTION_ID,
  PAGE_SIZE,
  searchStealthlogs,
  parseRscPayload,
  parseMarkdownTable,
  parseSearchResults,
  readerError,
};
