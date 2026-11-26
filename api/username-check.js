"use strict";

// Username Lookup (key-free). Checks a username across a curated set of
// public platforms using their public/open endpoints. Session-gated,
// rate-limited, defensive OSINT.
//
// Scope: read-only presence checks over public profile URLs/endpoints. We never
// attempt to bypass any rate limit, paywall, or auth.

const crypto = require("crypto");
const kv = require("../lib/kv");
const { kvRateLimit, getCorsHeaders } = require("../lib/middleware");
const { verifySessionToken, isTokenBlacklisted } = require("../lib/session");

const USERNAME_RE = /^[a-zA-Z0-9._-]{1,64}$/;

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
function sanitizeUsername(q) {
  const v = String(q || "").trim().replace(/^@/, "").replace(/^https?:\/\/[^/]+\//i, "").replace(/\/.*$/, "").slice(0, 64);
  return USERNAME_RE.test(v) ? v : "";
}

const UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

async function fetchWithTimeout(url, opts = {}, ms = 9000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, {
      ...opts,
      signal: ctrl.signal,
      redirect: opts.redirect || "follow",
      headers: { "User-Agent": UA, "Accept": "application/json, text/html, */*", "Accept-Language": "en-US,en;q=0.9", ...(opts.headers || {}) },
    });
  } finally { clearTimeout(t); }
}

// ---- Platform registry ----------------------------------------------------
// type: "html" | "json" | "redirect"
// url: build the probe URL for a username.
// notFound: regexes against the body that force not_found even on HTTP 200.
// found: regexes that force found even on HTTP 200 (when status is ambiguous).
const PLATFORMS = [
  { name: "GitHub", domain: "github.com", category: "dev", type: "json", url: u => `https://api.github.com/users/${encodeURIComponent(u)}` },
  { name: "GitLab", domain: "gitlab.com", category: "dev", type: "json", url: u => `https://gitlab.com/api/v4/users?username=${encodeURIComponent(u)}`, jsonFound: d => Array.isArray(d) && d.length > 0 },
  { name: "Bitbucket", domain: "bitbucket.org", category: "dev", type: "html", url: u => `https://bitbucket.org/${encodeURIComponent(u)}/` },
  { name: "CodePen", domain: "codepen.io", category: "dev", type: "html", url: u => `https://codepen.io/${encodeURIComponent(u)}` },
  { name: "Codeberg", domain: "codeberg.org", category: "dev", type: "html", url: u => `https://codeberg.org/${encodeURIComponent(u)}` },
  { name: "Dev.to", domain: "dev.to", category: "dev", type: "html", url: u => `https://dev.to/${encodeURIComponent(u)}` },
  { name: "Replit", domain: "replit.com", category: "dev", type: "html", url: u => `https://replit.com/@${encodeURIComponent(u)}` },
  { name: "Hacker News", domain: "news.ycombinator.com", category: "forum", type: "html", url: u => `https://news.ycombinator.com/user?id=${encodeURIComponent(u)}`, notFound: [/no user/i, /unknown user/i] },
  { name: "Reddit", domain: "reddit.com", category: "social", type: "json", url: u => `https://www.reddit.com/user/${encodeURIComponent(u)}.json`, headers: (u) => ({ "User-Agent": `osint-research/1.0 by ${u}` }) },
  { name: "Twitter / X", domain: "twitter.com", category: "social", type: "html", url: u => `https://twitter.com/${encodeURIComponent(u)}`, notFound: [/this account doesn/i, /doesn't exist/i, /suspended/i] },
  { name: "Instagram", domain: "instagram.com", category: "social", type: "html", url: u => `https://www.instagram.com/${encodeURIComponent(u)}/`, notFound: [/sorry, this page/i, /page isn't available/i] },
  { name: "TikTok", domain: "tiktok.com", category: "social", type: "json", url: u => `https://www.tiktok.com/oembed?url=https://www.tiktok.com/@${encodeURIComponent(u)}` },
  { name: "YouTube", domain: "youtube.com", category: "social", type: "json", url: u => `https://www.youtube.com/oembed?url=https://www.youtube.com/@${encodeURIComponent(u)}&format=json` },
  { name: "Twitch", domain: "twitch.tv", category: "social", type: "html", url: u => `https://www.twitch.tv/${encodeURIComponent(u)}`, notFound: [/404|not found/i] },
  { name: "Telegram", domain: "t.me", category: "social", type: "html", url: u => `https://t.me/${encodeURIComponent(u)}`, notFound: [/page not found/i, /404/i] },
  { name: "Pinterest", domain: "pinterest.com", category: "social", type: "html", url: u => `https://www.pinterest.com/${encodeURIComponent(u)}/`, notFound: [/404/i] },
  { name: "Tumblr", domain: "tumblr.com", category: "social", type: "html", url: u => `https://${encodeURIComponent(u)}.tumblr.com/`, notFound: [/404/i] },
  { name: "VSCO", domain: "vsco.co", category: "social", type: "html", url: u => `https://vsco.co/${encodeURIComponent(u)}` },
  { name: "Flickr", domain: "flickr.com", category: "social", type: "html", url: u => `https://www.flickr.com/people/${encodeURIComponent(u)}/` },
  { name: "Mastodon", domain: "mastodon.social", category: "social", type: "json", url: u => `https://mastodon.social/api/v1/accounts/lookup?acct=${encodeURIComponent(u)}` },
  { name: "Medium", domain: "medium.com", category: "writing", type: "html", url: u => `https://medium.com/@${encodeURIComponent(u)}`, notFound: [/404/i, /page not found/i] },
  { name: "WordPress.com", domain: "wordpress.com", category: "writing", type: "html", url: u => `https://${encodeURIComponent(u)}.wordpress.com/`, notFound: [/404/i, /not found/i] },
  { name: "Blogger", domain: "blogspot.com", category: "writing", type: "html", url: u => `https://${encodeURIComponent(u)}.blogspot.com/`, notFound: [/404/i, /not found/i] },
  { name: "Substack", domain: "substack.com", category: "writing", type: "html", url: u => `https://${encodeURIComponent(u)}.substack.com/` },
  { name: "Patreon", domain: "patreon.com", category: "creator", type: "html", url: u => `https://www.patreon.com/${encodeURIComponent(u)}` },
  { name: "OnlyFans", domain: "onlyfans.com", category: "creator", type: "html", url: u => `https://onlyfans.com/${encodeURIComponent(u)}`, notFound: [/404/i] },
  { name: "SoundCloud", domain: "soundcloud.com", category: "music", type: "html", url: u => `https://soundcloud.com/${encodeURIComponent(u)}` },
  { name: "Spotify", domain: "spotify.com", category: "music", type: "html", url: u => `https://open.spotify.com/user/${encodeURIComponent(u)}`, notFound: [/404/i] },
  { name: "Bandcamp", domain: "bandcamp.com", category: "music", type: "html", url: u => `https://${encodeURIComponent(u)}.bandcamp.com/` },
  { name: "Last.fm", domain: "last.fm", category: "music", type: "html", url: u => `https://www.last.fm/user/${encodeURIComponent(u)}` },
  { name: "Vimeo", domain: "vimeo.com", category: "video", type: "html", url: u => `https://vimeo.com/${encodeURIComponent(u)}` },
  { name: "Dailymotion", domain: "dailymotion.com", category: "video", type: "html", url: u => `https://www.dailymotion.com/${encodeURIComponent(u)}` },
  { name: "Steam", domain: "steamcommunity.com", category: "gaming", type: "html", url: u => `https://steamcommunity.com/id/${encodeURIComponent(u)}`, notFound: [/404/i, /no profile/i] },
  { name: "Dribbble", domain: "dribbble.com", category: "design", type: "html", url: u => `https://dribbble.com/${encodeURIComponent(u)}` },
  { name: "Behance", domain: "behance.net", category: "design", type: "html", url: u => `https://www.behance.net/${encodeURIComponent(u)}` },
  { name: "500px", domain: "500px.com", category: "photo", type: "html", url: u => `https://500px.com/p/${encodeURIComponent(u)}` },
  { name: "Ello", domain: "ello.co", category: "social", type: "html", url: u => `https://ello.co/${encodeURIComponent(u)}` },
  { name: "Keybase", domain: "keybase.io", category: "security", type: "html", url: u => `https://keybase.io/${encodeURIComponent(u)}` },
  { name: "Gravatar", domain: "gravatar.com", category: "profile", type: "json", url: u => { const h = crypto.createHash("md5").update(u.toLowerCase()).digest("hex"); return `https://gravatar.com/${h}.json`; } },
  { name: "About.me", domain: "about.me", category: "profile", type: "html", url: u => `https://about.me/${encodeURIComponent(u)}` },
  { name: "Product Hunt", domain: "producthunt.com", category: "creator", type: "html", url: u => `https://www.producthunt.com/@${encodeURIComponent(u)}` },
  { name: "SlideShare", domain: "slideshare.net", category: "creator", type: "html", url: u => `https://www.slideshare.net/${encodeURIComponent(u)}` },
  { name: "Kickstarter", domain: "kickstarter.com", category: "creator", type: "html", url: u => `https://www.kickstarter.com/people/${encodeURIComponent(u)}` },
  { name: "Pastebin", domain: "pastebin.com", category: "dev", type: "html", url: u => `https://pastebin.com/u/${encodeURIComponent(u)}` },
  { name: "Pinboard", domain: "pinboard.in", category: "bookmark", type: "html", url: u => `https://pinboard.in/u/${encodeURIComponent(u)}/` },
];

async function probe(p, username) {
  const meta = { name: p.name, domain: p.domain, category: p.category, status: "error", detail: "Request failed" };
  const url = p.url(username);
  try {
    const r = await fetchWithTimeout(url, { headers: (typeof p.headers === 'function') ? p.headers(username) : (p.headers || {}) }, 9000);
    const text = await r.text().catch(() => "");

    if (r.status === 429) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404 || r.status === 410) return { ...meta, status: "not_found", detail: "No account found" };

    if (p.type === "json") {
      if (r.status !== 200) return { ...meta, status: "inconclusive", detail: `HTTP ${r.status}` };
      let data;
      try { data = JSON.parse(text); } catch { return { ...meta, status: "inconclusive", detail: "Invalid JSON" }; }
      if (p.jsonFound) {
        return { ...meta, status: p.jsonFound(data) ? "found" : "not_found", detail: p.jsonFound(data) ? "Account exists" : "No account found" };
      }
      if (data && (data.message || data.error)) {
        if (/not found|no user|does not exist/i.test(String(data.message || data.error))) return { ...meta, status: "not_found", detail: "No account found" };
        return { ...meta, status: "inconclusive", detail: String(data.message || data.error).slice(0, 80) };
      }
      return { ...meta, status: "found", detail: "Account exists" };
    }

    // html
    if (p.notFound && p.notFound.some(re => re.test(text))) {
      return { ...meta, status: "not_found", detail: "No account found" };
    }
    if (r.status === 200) return { ...meta, status: "found", detail: "Profile page exists" };
    return { ...meta, status: "inconclusive", detail: `HTTP ${r.status}` };
  } catch (e) {
    return { ...meta, status: "error", detail: e && e.name === "AbortError" ? "timeout" : "network" };
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

  const username = sanitizeUsername(body.username);
  if (!username) return json(res, 400, { error: "Enter a valid username" });

  const limited = await kvRateLimit(`rl:username:${session.userId}`, 10, 60);
  if (limited) return json(res, 429, { error: "Rate limit reached. Wait a moment." });

  const started = Date.now();
  const results = [];
  const concurrency = 6;
  let idx = 0;
  const worker = async () => { while (idx < PLATFORMS.length) { const i = idx++; results[i] = await probe(PLATFORMS[i], username); } };
  await Promise.all(Array.from({ length: concurrency }, worker));

  const found = results.filter(r => r.status === "found");
  const durationMs = Date.now() - started;

  return json(res, 200, {
    username,
    status: found.length ? "found" : "none",
    count: found.length,
    total: results.length,
    results,
    durationMs,
  });
}

module.exports = handler;
module.exports.config = { maxDuration: 60 };
