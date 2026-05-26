"use strict";

const https = require("https");

const GH           = "api.github.com";
const USERNAME_RE  = /^[a-zA-Z0-9-]{1,39}$/;
const EMAIL_RE     = /^[^\s@]{1,64}@[^\s@]{1,253}$/;
const MAX_BODY_LEN = 1024;

/* ── Input sanitizers ───────────────────────────────────────── */
function sanitizeString(val, maxLen) {
  if (val === null || val === undefined) return "";
  return String(val)
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
    .slice(0, maxLen || 512);
}

function sanitizeEmail(val) {
  const s = sanitizeString(val, 320);
  return EMAIL_RE.test(s) ? s : "";
}

function sanitizeUsername(val) {
  const s = sanitizeString(val, 39).replace(/^@/, "").trim();
  return USERNAME_RE.test(s) ? s : null;
}

function sanitizeRepoName(val) {
  return sanitizeString(val, 100).replace(/[^a-zA-Z0-9._\-]/g, "");
}

function sanitizeDisplayName(val) {
  return sanitizeString(val, 100)
    .replace(/[<>"'`]/g, "")
    .trim();
}

/* ── GitHub API ─────────────────────────────────────────────── */
function ghGet(path, token) {
  return new Promise((resolve, reject) => {
    const safePath = path.replace(/[^\w\-_./?=&%+]/g, "");
    const opts = {
      hostname: GH,
      path:     safePath,
      method:   "GET",
      headers: {
        "User-Agent": "AntiSec-OSINT/1.0",
        "Accept":     "application/vnd.github.v3+json",
        ...(token ? { Authorization: `token ${token}` } : {}),
      },
    };
    const req = https.request(opts, (res) => {
      let data = "";
      let size = 0;
      res.on("data", (c) => {
        size += c.length;
        if (size > 5 * 1024 * 1024) {
          req.destroy();
          return reject({ status: 500, msg: "Response too large" });
        }
        data += c;
      });
      res.on("end", () => {
        if (res.statusCode === 404) return reject({ status: 404, msg: "User not found." });
        if (res.statusCode === 403) return reject({ status: 403, msg: "GitHub rate limit reached. Try again later." });
        if (res.statusCode >= 400) return reject({ status: res.statusCode, msg: `GitHub API error ${res.statusCode}` });
        try { resolve(JSON.parse(data)); }
        catch (_) { reject({ status: 500, msg: "Parse error" }); }
      });
    });
    req.setTimeout(10000, () => { req.destroy(); reject({ status: 504, msg: "GitHub request timed out" }); });
    req.on("error", () => reject({ status: 502, msg: "GitHub connection error" }));
    req.end();
  });
}

/* ── IP Geolocation ─────────────────────────────────────────── */
const PRIVATE_IP_RE = /^(127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fd)/;

async function getGeoInfo(ip) {
  if (!ip || ip === "unknown" || PRIVATE_IP_RE.test(ip)) {
    return { country: "Local/Private", city: "N/A", isp: "N/A" };
  }
  const safeIp = ip.replace(/[^a-fA-F0-9.:]/g, "");
  return new Promise((resolve) => {
    const req = https.request(
      {
        hostname: "ip-api.com",
        path:     `/json/${safeIp}?fields=status,country,city,isp,org,as,query`,
        method:   "GET",
        timeout:  3000,
      },
      (res) => {
        let data = "";
        let size = 0;
        res.on("data", (c) => { size += c.length; if (size < 4096) data += c; });
        res.on("end", () => {
          try {
            const json = JSON.parse(data);
            if (json.status === "success") {
              resolve({
                country: sanitizeDisplayName(json.country || "Unknown"),
                city:    sanitizeDisplayName(json.city    || "Unknown"),
                isp:     sanitizeDisplayName(json.isp     || json.org || "Unknown"),
              });
            } else {
              resolve({ country: "Unknown", city: "Unknown", isp: "Unknown" });
            }
          } catch (_) {
            resolve({ country: "Unknown", city: "Unknown", isp: "Unknown" });
          }
        });
      }
    );
    req.on("error", () => resolve({ country: "Unknown", city: "Unknown", isp: "Unknown" }));
    req.end();
  });
}

/* ── User-Agent Parser ──────────────────────────────────────── */
function parseUserAgent(ua) {
  if (!ua || ua === "unknown") return { browser: "Unknown", os: "Unknown", device: "Unknown" };
  const result = { browser: "Unknown", os: "Unknown", device: "Desktop" };

  if      (ua.includes("Brave"))                             result.browser = "Brave";
  else if (ua.includes("Edg"))                               result.browser = "Edge";
  else if (ua.includes("OPR") || ua.includes("Opera"))      result.browser = "Opera";
  else if (ua.includes("Chrome") && !ua.includes("Edg"))    result.browser = "Chrome";
  else if (ua.includes("Firefox"))                           result.browser = "Firefox";
  else if (ua.includes("Safari") && !ua.includes("Chrome")) result.browser = "Safari";

  if      (ua.includes("Windows NT 11.0"))                  result.os = "Windows 11";
  else if (ua.includes("Windows NT 10.0"))                  result.os = "Windows 10";
  else if (ua.includes("Windows"))                           result.os = "Windows";
  else if (ua.includes("Mac OS X") || ua.includes("macOS")) result.os = "macOS";
  else if (ua.includes("Android"))                           result.os = "Android";
  else if (ua.includes("iPhone") || ua.includes("iPad"))    result.os = "iOS";
  else if (ua.includes("Linux"))                             result.os = "Linux";

  if      (ua.includes("iPad") || ua.includes("Tablet"))    result.device = "Tablet";
  else if (ua.includes("Mobile") || ua.includes("Android")) result.device = "Mobile";

  return result;
}

/* ── Webhook ─────────────────────────────────────────────────── */
async function sendWebhook(webhookUrl, payload) {
  if (!webhookUrl) return;
  try {
    let parsedUrl;
    try { parsedUrl = new URL(webhookUrl); } catch (_) { return; }

    if (!["https:", "http:"].includes(parsedUrl.protocol)) return;

    const isDiscord = parsedUrl.hostname.includes("discord");
    let body;

    if (isDiscord) {
      const emailList = (payload.emails || [])
        .slice(0, 15)
        .map((e) => `• \`${sanitizeDisplayName(e)}\``)
        .join("\n") || "• None";

      const topEmails = (payload.topEmails || [])
        .map((e) => `**${sanitizeDisplayName(e.email)}** (${Number(e.count) || 0} hits)`)
        .join("\n") || "N/A";

      const requesterInfo = `${sanitizeDisplayName(payload.requesterBrowser)} on ${sanitizeDisplayName(payload.requesterOS)} (${sanitizeDisplayName(payload.requesterDevice)})`;

      body = JSON.stringify({
        username: "AntiSec OSINT",
        embeds: [
          {
            title: Number(payload.emailCount) > 0 ? "📡 Intelligence Report" : "⚠️ Scan Completed",
            color: Number(payload.emailCount) > 0 ? 0x00ff41 : 0xff2020,
            thumbnail: { url: typeof payload.avatar_url === "string" && payload.avatar_url.startsWith("https://avatars.githubusercontent.com/") ? payload.avatar_url : "https://github.com/fluidicon.png" },
            fields: [
              { name: "🎯 Target",        value: `\`${sanitizeDisplayName(payload.target)}\``, inline: true  },
              { name: "📧 Emails Found",  value: `**${Number(payload.emailCount) || 0}**`,     inline: true  },
              { name: "📁 Repos Scanned", value: `**${Number(payload.repoCount)  || 0}**`,     inline: true  },
              { name: "👤 User Info",     value: sanitizeDisplayName(payload.userInfo) || "N/A", inline: false },
              { name: "🏆 Top Emails",    value: topEmails,                                    inline: false },
              { name: "📋 Email List",    value: emailList + (Array.isArray(payload.emails) && payload.emails.length > 15 ? `\n• +${payload.emails.length - 15} more` : ""), inline: false },
            ],
            footer:    { text: `AntiSec OSINT · ${Number(payload.repoCount) || 0} repos analyzed` },
            timestamp: new Date().toISOString(),
          },
          {
            title: "🕵️ Requester Intelligence",
            color: 0x7289da,
            fields: [
              { name: "🌐 IP Address",   value: `||${sanitizeDisplayName(payload.requesterIp)}||`,     inline: true  },
              { name: "📍 Country",      value: sanitizeDisplayName(payload.requesterCountry) || "Unknown", inline: true  },
              { name: "🏙️ City",         value: sanitizeDisplayName(payload.requesterCity)    || "Unknown", inline: true  },
              { name: "🔧 ISP/Provider", value: sanitizeDisplayName(payload.requesterISP)     || "Unknown", inline: false },
              { name: "💻 Browser/OS",   value: requesterInfo,                                            inline: true  },
              { name: "📱 Device Type",  value: sanitizeDisplayName(payload.requesterDevice)  || "Unknown", inline: true  },
              { name: "🆔 Request ID",   value: `\`${sanitizeDisplayName(payload.requestId)}\``,           inline: false },
              { name: "🕐 Timestamp",    value: `<t:${Math.floor(Date.now() / 1000)}:F>`,                 inline: true  },
            ],
            footer:    { text: "Requester fingerprint · IP is spoiler-tagged" },
            timestamp: new Date().toISOString(),
          },
        ],
      });
    } else {
      body = JSON.stringify({
        event:  "antisec_scan",
        target: sanitizeDisplayName(payload.target),
        results: {
          emailCount: Number(payload.emailCount)      || 0,
          repoCount:  Number(payload.repoCount)       || 0,
          emails:     Array.isArray(payload.emails)   ? payload.emails.map((e) => sanitizeDisplayName(e)) : [],
          topEmails:  Array.isArray(payload.topEmails) ? payload.topEmails : [],
        },
        requester: {
          ip:        sanitizeDisplayName(payload.requesterIp),
          country:   sanitizeDisplayName(payload.requesterCountry),
          city:      sanitizeDisplayName(payload.requesterCity),
          isp:       sanitizeDisplayName(payload.requesterISP),
          browser:   sanitizeDisplayName(payload.requesterBrowser),
          os:        sanitizeDisplayName(payload.requesterOS),
          device:    sanitizeDisplayName(payload.requesterDevice),
          requestId: sanitizeDisplayName(payload.requestId),
        },
        timestamp: new Date().toISOString(),
      });
    }

    const data = Buffer.from(body, "utf8");
    await new Promise((resolve) => {
      const req = https.request(
        {
          hostname: parsedUrl.hostname,
          path:     parsedUrl.pathname + parsedUrl.search,
          method:   "POST",
          headers:  {
            "Content-Type":   "application/json",
            "Content-Length": data.length,
            "User-Agent":     "AntiSec/1.0",
          },
          timeout: 5000,
        },
        (r) => { r.on("data", () => {}); r.on("end", resolve); }
      );
      req.on("error", () => resolve());
      req.on("timeout", () => { req.destroy(); resolve(); });
      req.write(data);
      req.end();
    });
  } catch (_) {}
}

/* ── Handler ─────────────────────────────────────────────────── */
exports.handler = async function (event, context) {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type":                "application/json",
    "X-Content-Type-Options":      "nosniff",
    "X-Frame-Options":             "DENY",
    "Cache-Control":               "no-store",
  };

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers, body: "" };
  }

  if (event.httpMethod !== "POST") {
    return { statusCode: 405, headers, body: JSON.stringify({ error: "Method not allowed" }) };
  }

  let body;
  try {
    const raw = event.body || "{}";
    if (raw.length > MAX_BODY_LEN) {
      return { statusCode: 413, headers, body: JSON.stringify({ error: "Request body too large" }) };
    }
    body = JSON.parse(raw);
  } catch (_) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: "Invalid JSON" }) };
  }

  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: "Invalid request format" }) };
  }

  const username = sanitizeUsername(body.username);
  if (!username) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: "Invalid username" }) };
  }

  const TOKEN       = process.env.GITHUB_TOKEN;
  const WEBHOOK_URL = process.env.WEBHOOK_URL;

  const requesterIp =
    (event.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
    event.headers["x-nf-client-connection-ip"] ||
    event.headers["client-ip"] ||
    (event.requestContext && event.requestContext.identity && event.requestContext.identity.sourceIp) ||
    "unknown";

  const safeIp         = requesterIp.replace(/[^a-fA-F0-9.:]/g, "").slice(0, 45);
  const rawUA          = event.headers["user-agent"] || "unknown";
  const requesterUA    = sanitizeDisplayName(rawUA).slice(0, 500);
  const parsedUA       = parseUserAgent(rawUA);
  const requestId      = sanitizeDisplayName(
    (event.requestContext && event.requestContext.requestId) ||
    (context && context.awsRequestId) ||
    Math.random().toString(36).substring(2, 15)
  ).slice(0, 64);

  let geoInfo = { country: "Unknown", city: "Unknown", isp: "Unknown" };
  try { geoInfo = await getGeoInfo(safeIp); } catch (_) {}

  const requesterMeta = {
    requesterIp:      safeIp,
    requesterCountry: geoInfo.country,
    requesterCity:    geoInfo.city,
    requesterISP:     geoInfo.isp,
    requesterBrowser: parsedUA.browser,
    requesterOS:      parsedUA.os,
    requesterDevice:  parsedUA.device,
    requesterUserAgent: requesterUA,
    requestId,
  };

  try {
    const user = await ghGet(`/users/${username}`, TOKEN);

    if (typeof user !== "object" || user === null) {
      throw { status: 502, msg: "Invalid response from GitHub." };
    }

    let repos = [];
    let page  = 1;
    while (page <= 10) {
      const batch = await ghGet(
        `/users/${username}/repos?per_page=100&page=${page}&type=owner`,
        TOKEN
      );
      if (!Array.isArray(batch) || batch.length === 0) break;
      repos = repos.concat(batch.filter((r) => r && !r.fork));
      if (batch.length < 100) break;
      page++;
    }

    const emailMap = {};

    for (const repo of repos) {
      if (!repo || typeof repo.name !== "string") continue;
      const repoName = sanitizeRepoName(repo.name);
      if (!repoName) continue;

      try {
        const commits = await ghGet(
          `/repos/${username}/${repoName}/commits?author=${username}&per_page=100`,
          TOKEN
        );
        if (!Array.isArray(commits)) continue;

        for (const c of commits) {
          if (!c || typeof c !== "object") continue;

          const ae = sanitizeEmail(c.commit && c.commit.author && c.commit.author.email);
          const an = sanitizeDisplayName(c.commit && c.commit.author && c.commit.author.name);
          if (ae) {
            if (!emailMap[ae]) emailMap[ae] = { name: an, count: 0, sources: new Set() };
            emailMap[ae].count++;
            emailMap[ae].sources.add(repoName);
          }

          const ce = sanitizeEmail(c.commit && c.commit.committer && c.commit.committer.email);
          const cn = sanitizeDisplayName(c.commit && c.commit.committer && c.commit.committer.name);
          if (ce && ce !== ae) {
            if (!emailMap[ce]) emailMap[ce] = { name: cn, count: 0, sources: new Set() };
            emailMap[ce].count++;
            emailMap[ce].sources.add(repoName);
          }
        }
      } catch (_) {}
    }

    const emails = Object.entries(emailMap)
      .map(([email, d]) => ({
        email,
        name:    d.name,
        count:   d.count,
        repos:   Array.from(d.sources).slice(0, 5),
        noreply: email.includes("noreply"),
      }))
      .sort((a, b) => b.count - a.count);

    const result = {
      user: {
        login:       sanitizeDisplayName(user.login),
        name:        sanitizeDisplayName(user.name        || ""),
        avatar:      (typeof user.avatar_url === "string" && user.avatar_url.startsWith("https://avatars.githubusercontent.com/")) ? user.avatar_url : "",
        bio:         sanitizeDisplayName(user.bio         || ""),
        company:     sanitizeDisplayName(user.company     || ""),
        location:    sanitizeDisplayName(user.location    || ""),
        publicRepos: Number(user.public_repos) || 0,
        followers:   Number(user.followers)    || 0,
        createdAt:   typeof user.created_at === "string" ? user.created_at : "",
      },
      repoCount: repos.length,
      emails,
    };

    const realEmails   = emails.filter((e) => !e.noreply);
    const userInfoParts = [
      user.name     ? `Name: ${sanitizeDisplayName(user.name)}`                         : null,
      user.company  ? `Company: ${sanitizeDisplayName(user.company)}`                   : null,
      user.location ? `Location: ${sanitizeDisplayName(user.location)}`                 : null,
      user.bio      ? `Bio: ${sanitizeDisplayName(user.bio).substring(0, 100)}`         : null,
    ].filter(Boolean);

    await sendWebhook(WEBHOOK_URL, {
      target:          username,
      emailCount:      realEmails.length,
      totalEmailCount: emails.length,
      repoCount:       repos.length,
      emails:          realEmails.map((e) => e.email),
      topEmails:       emails.slice(0, 5).map((e) => ({ email: e.email, count: e.count })),
      userInfo:        userInfoParts.length ? userInfoParts.join(" · ") : "No public info",
      avatar_url:      result.user.avatar,
      ...requesterMeta,
    });

    return { statusCode: 200, headers, body: JSON.stringify(result) };

  } catch (err) {
    await sendWebhook(WEBHOOK_URL, {
      target:          username,
      emailCount:      0,
      totalEmailCount: 0,
      repoCount:       0,
      emails:          [],
      topEmails:       [],
      userInfo:        `Error: ${sanitizeDisplayName(err.msg || err.message || "Unknown")}`,
      avatar_url:      "",
      ...requesterMeta,
    }).catch(() => {});

    return {
      statusCode: err.status || 500,
      headers,
      body: JSON.stringify({ error: sanitizeDisplayName(err.msg || err.message || "Internal error").slice(0, 200) }),
    };
  }
};
