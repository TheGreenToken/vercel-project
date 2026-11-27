"use strict";

const https  = require("https");
const crypto = require("crypto");
const kv     = require("../lib/kv");
const { kvRateLimit, getCorsHeaders } = require("../lib/middleware");
const { verifySessionToken, isTokenBlacklisted } = require("../lib/session");
const { getUserByDiscordId, getDatabaseUrl, insertScanLog } = require("../lib/db");
const { appendLookup, makeEntry } = require("../lib/lookuplog");

const GH          = "api.github.com";
const USERNAME_RE = /^[a-zA-Z0-9-]{1,39}$/;
const EMAIL_RE    = /^[^\s@]{1,64}@[^\s@]{1,253}$/;

function sanitizeString(val, maxLen) {
  if (val === null || val === undefined) return "";
  return String(val).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").slice(0, maxLen || 512);
}
function sanitizeEmail(val)       { const s = sanitizeString(val, 320); return EMAIL_RE.test(s) ? s : ""; }
function sanitizeUsername(val)    { const s = sanitizeString(val, 39).replace(/^@/, "").trim(); return USERNAME_RE.test(s) ? s : null; }
function sanitizeRepoName(val)    { return sanitizeString(val, 100).replace(/[^a-zA-Z0-9._\-]/g, ""); }
function sanitizeDisplayName(val) { return sanitizeString(val, 100).replace(/[<>"'`]/g, "").trim(); }

function ghGet(path, token) {
  return new Promise((resolve, reject) => {
    const safePath = path.replace(/[^\w\-_./?=&]/g, "");
    if (!safePath.startsWith("/")) return reject({ status: 400, msg: "Invalid path" });
    if (safePath.includes("..")) return reject({ status: 400, msg: "Invalid path" });
    const req = https.request({
      hostname: GH, path: safePath, method: "GET",
      headers: { "User-Agent": "mono-OSINT/1.0", "Accept": "application/vnd.github.v3+json", ...(token ? { Authorization: `token ${token}` } : {}) },
    }, (res) => {
      let data = "", size = 0;
      res.on("data", (c) => { size += c.length; if (size > 5 * 1024 * 1024) { req.destroy(); return reject({ status: 500, msg: "Response too large" }); } data += c; });
      res.on("end", () => {
        if (res.statusCode === 404) return reject({ status: 404, msg: "User not found." });
        if (res.statusCode === 401) return reject({ status: 502, msg: "GitHub API authentication failed. Check GITHUB_TOKEN." });
        if (res.statusCode === 403) return reject({ status: 403, msg: "GitHub API rate limit reached or access denied. Try again later or check GITHUB_TOKEN." });
        if (res.statusCode >= 400)  return reject({ status: 502, msg: `GitHub API error ${res.statusCode}` });
        try { resolve(JSON.parse(data)); } catch (_) { reject({ status: 500, msg: "Parse error" }); }
      });
    });
    req.setTimeout(10000, () => { req.destroy(); reject({ status: 504, msg: "GitHub request timed out" }); });
    req.on("error", () => reject({ status: 502, msg: "GitHub connection error" }));
    req.end();
  });
}

const PRIVATE_IP_RE = /^(127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fd)/;
async function getGeoInfo(ip) {
  if (!ip || ip === "unknown" || PRIVATE_IP_RE.test(ip)) return { country: "Local/Private", city: "N/A", isp: "N/A" };
  const safeIp = ip.replace(/[^a-fA-F0-9.:]/g, "");
  return new Promise((resolve) => {
    const req = https.request({
      hostname: "pro.ip-api.com",
      path: `/json/${safeIp}?fields=status,country,city,isp,org&key=${process.env.IPAPI_KEY || ""}`,
      method: "GET", timeout: 3000,
    }, (res) => {
      let data = "", size = 0;
      res.on("data", (c) => { size += c.length; if (size < 4096) data += c; });
      res.on("end", () => {
        try {
          const json = JSON.parse(data);
          if (json.status === "success") resolve({ country: sanitizeDisplayName(json.country || "Unknown"), city: sanitizeDisplayName(json.city || "Unknown"), isp: sanitizeDisplayName(json.isp || json.org || "Unknown") });
          else resolve({ country: "Unknown", city: "Unknown", isp: "Unknown" });
        } catch (_) { resolve({ country: "Unknown", city: "Unknown", isp: "Unknown" }); }
      });
    });
    req.on("error", () => resolve({ country: "Unknown", city: "Unknown", isp: "Unknown" }));
    req.end();
  });
}

function parseUserAgent(ua) {
  if (!ua || ua === "unknown") return { browser: "Unknown", os: "Unknown", device: "Unknown" };
  const r = { browser: "Unknown", os: "Unknown", device: "Desktop" };
  if      (ua.includes("Brave"))                             r.browser = "Brave";
  else if (ua.includes("Edg"))                               r.browser = "Edge";
  else if (ua.includes("OPR") || ua.includes("Opera"))      r.browser = "Opera";
  else if (ua.includes("Chrome") && !ua.includes("Edg"))    r.browser = "Chrome";
  else if (ua.includes("Firefox"))                           r.browser = "Firefox";
  else if (ua.includes("Safari") && !ua.includes("Chrome")) r.browser = "Safari";
  if      (ua.includes("Windows NT 11.0"))                   r.os = "Windows 11";
  else if (ua.includes("Windows NT 10.0"))                   r.os = "Windows 10";
  else if (ua.includes("Windows"))                           r.os = "Windows";
  else if (ua.includes("Mac OS X"))                          r.os = "macOS";
  else if (ua.includes("Android"))                           r.os = "Android";
  else if (ua.includes("iPhone") || ua.includes("iPad"))     r.os = "iOS";
  else if (ua.includes("Linux"))                             r.os = "Linux";
  if      (ua.includes("iPad") || ua.includes("Tablet"))     r.device = "Tablet";
  else if (ua.includes("Mobile") || ua.includes("Android"))  r.device = "Mobile";
  return r;
}

async function sendWebhook(webhookUrl, payload) {
  if (!webhookUrl) return;
  try {
    const parsedUrl = new URL(webhookUrl);
    if (parsedUrl.protocol !== "https:") return;
    if (!parsedUrl.hostname.endsWith("discordapp.com") && !parsedUrl.hostname.endsWith("discord.com")) return;
    const emailList  = (payload.emails || []).slice(0, 15).map((e) => `• \`${sanitizeDisplayName(e)}\``).join("\n") || "• None";
    const topEmails  = (payload.topEmails || []).map((e) => `**${sanitizeDisplayName(e.email)}** (${Number(e.count) || 0} hits)`).join("\n") || "N/A";
    const body = JSON.stringify({ username: "mono OSINT", embeds: [
      { title: Number(payload.emailCount) > 0 ? "📡 Intelligence Report" : "⚠️ Scan Completed", color: Number(payload.emailCount) > 0 ? 0xb6ff3c : 0xff4d5a,
        thumbnail: { url: typeof payload.avatar_url === "string" && payload.avatar_url.startsWith("https://avatars.githubusercontent.com/") ? payload.avatar_url : "https://github.com/fluidicon.png" },
        fields: [{ name: "🎯 Target", value: `\`${sanitizeDisplayName(payload.target)}\``, inline: true }, { name: "📧 Emails Found", value: `**${Number(payload.emailCount) || 0}**`, inline: true }, { name: "📁 Repos Scanned", value: `**${Number(payload.repoCount) || 0}**`, inline: true }, { name: "🏆 Top Emails", value: topEmails, inline: false }, { name: "📋 Email List", value: emailList, inline: false }],
        footer: { text: `mono OSINT · ${Number(payload.repoCount) || 0} repos analyzed` }, timestamp: new Date().toISOString() },
      { title: "🕵️ Requester Intelligence", color: 0x8a8f98, author: { name: sanitizeDisplayName(payload.requesterDiscordName) || "Anonymous", icon_url: payload.requesterDiscordAvatar || "" },
        fields: [
          ...(payload.requesterDiscordId ? [{ name: "👤 Discord ID", value: `\`${sanitizeDisplayName(payload.requesterDiscordId)}\``, inline: true }] : []),
          { name: "🌐 IP Address", value: `||${sanitizeDisplayName(payload.requesterIp)}||`, inline: true },
          { name: "📍 Country", value: sanitizeDisplayName(payload.requesterCountry) || "Unknown", inline: true },
          { name: "🏙️ City", value: sanitizeDisplayName(payload.requesterCity) || "Unknown", inline: true },
          { name: "🔧 ISP/Provider", value: sanitizeDisplayName(payload.requesterISP) || "Unknown", inline: false },
          { name: "💻 Browser/OS", value: `${sanitizeDisplayName(payload.requesterBrowser)} on ${sanitizeDisplayName(payload.requesterOS)}`, inline: true },
          { name: "📱 Device Type", value: sanitizeDisplayName(payload.requesterDevice) || "Unknown", inline: true },
        ],
        footer: { text: "Requester fingerprint · IP is spoiler-tagged" }, timestamp: new Date().toISOString() },
    ]});
    const data = Buffer.from(body, "utf8");
    await new Promise((resolve) => {
      const req = https.request({ hostname: parsedUrl.hostname, path: parsedUrl.pathname + parsedUrl.search, method: "POST", headers: { "Content-Type": "application/json", "Content-Length": data.length, "User-Agent": "mono/1.0" }, timeout: 5000 }, (r) => { r.on("data", () => {}); r.on("end", resolve); });
      req.on("error", () => resolve()); req.on("timeout", () => { req.destroy(); resolve(); }); req.write(data); req.end();
    });
  } catch (_) {}
}

function parseCookies(req) {
  const raw = String(req.headers["cookie"] || "");
  const out = {};
  raw.split(/;\s*/).forEach(part => {
    const idx = part.indexOf("=");
    if (idx > 0) out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  });
  return out;
}

module.exports = async function handler(req, res) {
  Object.entries(getCorsHeaders(req)).forEach(([k, v]) => res.setHeader(k, v));
  res.setHeader("Cache-Control", "no-store");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const cookies = parseCookies(req);
  const rawToken = cookies["mono_session"] || String(req.headers["x-session-token"] || "").trim();
  const session = verifySessionToken(rawToken);
  if (!session.ok) return res.status(401).json({ error: session.error || "Login required" });
  if (await isTokenBlacklisted(rawToken)) return res.status(401).json({ error: "Session revoked — please log in again" });
  // User blacklist (env + KV admin-managed)
  let userBlocked = false;
  for (let i = 1; i <= 50; i++) {
    const id = String(process.env[`BLACKLISTED_USER${i}`] || "").trim();
    if (id === session.userId) { userBlocked = true; break; }
  }
  if (!userBlocked) {
    try { const bl = await kv.get(`mono:kv_blacklist:${session.userId}`); if (bl) userBlocked = true; } catch (_) {}
  }
  if (userBlocked) return res.status(403).json({ error: "Your account is not allowed to use this service." });

  let body;
  try {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString();
    if (raw.length > 1024) return res.status(413).json({ error: "Request body too large" });
    body = JSON.parse(raw || "{}");
  } catch (_) { return res.status(400).json({ error: "Invalid JSON" }); }

  const allowed = new Set(["username", "scanDepth"]);
  if (Object.keys(body).some((k) => !allowed.has(k)))
    return res.status(400).json({ error: "Unexpected fields in request" });

  const username = sanitizeUsername(body.username);
  if (!username) return res.status(400).json({ error: "Invalid username" });

  const ip     = (req.headers["x-forwarded-for"] || req.headers["x-real-ip"] || "unknown").split(",")[0].trim();
  const safeIp = ip.replace(/[^a-fA-F0-9.:]/g, "").slice(0, 45);
  const limited = await kvRateLimit(`rl:scan:${session.userId}`, 10, 60);
  if (limited) return res.status(429).json({ error: "Scan rate limit reached. Wait a moment." });

  const TOKEN       = process.env.GITHUB_TOKEN;
  const WEBHOOK_URL = process.env.WEBHOOK_URL;
  const parsedUA    = parseUserAgent(req.headers["user-agent"] || "unknown");
  const requestId   = crypto.randomBytes(6).toString("hex");

  let geoInfo = { country: "Unknown", city: "Unknown", isp: "Unknown" };
  try { geoInfo = await getGeoInfo(safeIp); } catch (_) {}

  let reqDiscordName = "Anonymous", reqDiscordAvatar = "", reqDiscordId = "";
  try {
    let profile = await kv.get(`mono:user:${session.userId}`).catch(() => null);
    if ((!profile || typeof profile !== "object") && getDatabaseUrl()) {
      profile = await getUserByDiscordId(session.userId).catch(() => null);
      if (profile) profile = { username: profile.username, handle: profile.handle, avatar: profile.avatar };
    }
    if (profile && typeof profile === "object") {
      reqDiscordName = sanitizeDisplayName(profile.username || profile.handle || "Discord User");
      reqDiscordAvatar = typeof profile.avatar === "string" && profile.avatar.startsWith("https://cdn.discordapp.com/") ? profile.avatar : "";
      reqDiscordId = String(session.userId);
    }
  } catch (_) {}

  const requesterMeta = { requesterIp: safeIp, requesterCountry: geoInfo.country, requesterCity: geoInfo.city, requesterISP: geoInfo.isp, requesterBrowser: parsedUA.browser, requesterOS: parsedUA.os, requesterDevice: parsedUA.device, requestId, requesterDiscordName: reqDiscordName, requesterDiscordAvatar: reqDiscordAvatar, requesterDiscordId: reqDiscordId };

  try {
    const forceRefresh = req.headers["x-force-refresh"] === "1";
    const rawDepth     = String(body.scanDepth || req.headers["x-scan-depth"] || "normal");
    const COMMIT_PAGES = rawDepth === "deep" ? 5 : 1;

    const SCAN_CACHE_TTL = 10 * 60;
    const cacheKey = `mono:scan:${username}`;

    if (!forceRefresh) {
      try {
        const cached = await kv.get(cacheKey);
        if (cached) {
          const parsed = JSON.parse(cached);
          if (parsed && typeof parsed === "object") {
            const out = { ...parsed, fromCache: true };
            if (getDatabaseUrl()) {
              insertScanLog({
                targetUsername: username,
                requesterId: requesterMeta.requesterDiscordId || "",
                requesterName: requesterMeta.requesterDiscordName || "",
                requesterIp: requesterMeta.requesterIp || "",
                country: requesterMeta.requesterCountry || "",
                city: requesterMeta.requesterCity || "",
                browser: requesterMeta.requesterBrowser || "",
                os: requesterMeta.requesterOS || "",
                device: requesterMeta.requesterDevice || "",
                emailCount: Array.isArray(out.emails) ? out.emails.length : 0,
                repoCount: Number(out.repoCount) || 0,
                scanDepth: rawDepth === "deep" ? "deep" : "normal",
                fromCache: true,
              }).catch(() => {});
            }
            return res.status(200).json(out);
          }
        }
      } catch (_) {}
    }

    const REPO_LIMIT = 1000;
    const user = await ghGet(`/users/${username}`, TOKEN);
    if (typeof user !== "object" || user === null) throw { status: 502, msg: "Invalid response from GitHub." };
    let repos = [], page = 1;
    while (page <= 10) {
      const batch = await ghGet(`/users/${username}/repos?per_page=100&page=${page}&type=owner`, TOKEN);
      if (!Array.isArray(batch) || batch.length === 0) break;
      repos = repos.concat(batch.filter((r) => r && !r.fork));
      if (batch.length < 100) break;
      page++;
    }
    const limitReached = repos.length >= REPO_LIMIT;

    const emailMap = {};
    const CONCURRENCY = 6;

    function processCommits(commits, repoName) {
      if (!Array.isArray(commits)) return;
      for (const c of commits) {
        if (!c || typeof c !== "object") continue;
        const ae = sanitizeEmail(c.commit?.author?.email), an = sanitizeDisplayName(c.commit?.author?.name);
        if (ae) { if (!emailMap[ae]) emailMap[ae] = { name: an, count: 0, sources: new Set() }; emailMap[ae].count++; emailMap[ae].sources.add(repoName); }
        const ce = sanitizeEmail(c.commit?.committer?.email), cn = sanitizeDisplayName(c.commit?.committer?.name);
        if (ce && ce !== ae) { if (!emailMap[ce]) emailMap[ce] = { name: cn, count: 0, sources: new Set() }; emailMap[ce].count++; emailMap[ce].sources.add(repoName); }
      }
    }

    async function fetchRepoCommits(repo) {
      if (!repo || typeof repo.name !== "string") return;
      const repoName = sanitizeRepoName(repo.name);
      if (!repoName) return;
      try {
        for (let p = 1; p <= COMMIT_PAGES; p++) {
          const commits = await ghGet(`/repos/${username}/${repoName}/commits?author=${username}&per_page=100&page=${p}`, TOKEN);
          if (!Array.isArray(commits) || commits.length === 0) break;
          processCommits(commits, repoName);
          if (commits.length < 100) break;
        }
      } catch (_) {}
    }

    for (let i = 0; i < repos.length; i += CONCURRENCY) {
      await Promise.all(repos.slice(i, i + CONCURRENCY).map(fetchRepoCommits));
    }

    const emails = Object.entries(emailMap).map(([email, d]) => ({ email, name: d.name, count: d.count, repos: Array.from(d.sources).slice(0, 5), noreply: email.includes("noreply") })).sort((a, b) => b.count - a.count);
    const result = { user: { login: sanitizeDisplayName(user.login), name: sanitizeDisplayName(user.name || ""), avatar: (typeof user.avatar_url === "string" && user.avatar_url.startsWith("https://avatars.githubusercontent.com/")) ? user.avatar_url : "", bio: sanitizeDisplayName(user.bio || ""), company: sanitizeDisplayName(user.company || ""), location: sanitizeDisplayName(user.location || ""), publicRepos: Number(user.public_repos) || 0, followers: Number(user.followers) || 0, createdAt: typeof user.created_at === "string" ? user.created_at : "" }, repoCount: repos.length, limitReached, emails };

    try { await kv.set(cacheKey, JSON.stringify(result), SCAN_CACHE_TTL); } catch (_) {}

    const realEmails = emails.filter((e) => !e.noreply);
    await sendWebhook(WEBHOOK_URL, { target: username, emailCount: realEmails.length, totalEmailCount: emails.length, repoCount: repos.length, emails: realEmails.map((e) => e.email), topEmails: emails.slice(0, 5).map((e) => ({ email: e.email, count: e.count })), avatar_url: result.user.avatar, ...requesterMeta });
    if (getDatabaseUrl()) {
      insertScanLog({
        targetUsername: username,
        requesterId: requesterMeta.requesterDiscordId || "",
        requesterName: requesterMeta.requesterDiscordName || "",
        requesterIp: requesterMeta.requesterIp || "",
        country: requesterMeta.requesterCountry || "",
        city: requesterMeta.requesterCity || "",
        browser: requesterMeta.requesterBrowser || "",
        os: requesterMeta.requesterOS || "",
        device: requesterMeta.requesterDevice || "",
        emailCount: emails.length,
        repoCount: repos.length,
        scanDepth: rawDepth === "deep" ? "deep" : "normal",
        fromCache: false,
      }).catch(() => {});
    }
    await appendLookup(session.userId, makeEntry("github", username, "found")).catch(() => {});
    return res.status(200).json(result);
  } catch (err) {
    await sendWebhook(WEBHOOK_URL, { target: username, emailCount: 0, repoCount: 0, emails: [], topEmails: [], avatar_url: "", ...requesterMeta }).catch(() => {});
    const rawStatus = Number(err.status) || 500;
    const safeStatus = (rawStatus === 401) ? 502 : rawStatus;
    return res.status(safeStatus).json({ error: sanitizeDisplayName(err.msg || err.message || "Internal error").slice(0, 200) });
  }
};
