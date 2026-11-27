"use strict";

// Shared stealerlogs.com scraping logic used by both the email Exposure Search
// and the IP Exposure module. stealerlogs.com is a Next.js SPA: results are
// rendered client-side, so a plain HTML fetch only yields a "Searching…"
// skeleton. We render via the r.jina.ai reader (free web tier, partial
// credentials) and parse the resulting Markdown table. No API token, no
// paywall bypass. Any reader error is surfaced, not masked as "no hits".

const SEARCH_BASE = "https://stealerlogs.com/search";
const RENDER_BASE = "https://r.jina.ai/";

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
  if (r < lines.length && /^\|[\s:\-|]+\|$/.test(lines[r].trim())) r++;

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

// Core search: render the stealerlogs search page for a query + type via the
// reader and parse the Markdown table. type is "email" or "ip".
async function searchStealthlogs(query, type) {
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

module.exports = { SEARCH_BASE, searchStealthlogs, parseMarkdownTable, parseSearchResults, readerError };
