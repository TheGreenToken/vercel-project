"use strict";

const crypto = require("crypto");
const https  = require("https");
const { createSessionToken }             = require("./session");
const { envCheck, kvRateLimit, replayGuard, getCorsHeaders } = require("./middleware");
const kv = require("./kv");

const TAG_SUFFIX = "ᵃⁿᵗⁱ";
const TAG_PREFIX = "𝐴𝐧𝐭𝐢|";

function getSpecialUsers() {
  const ids = new Set();
  for (let i = 1; i <= 50; i++) {
    const val = (process.env[`SPECIAL_USER${i}`] || "").trim();
    if (val && /^\d{17,19}$/.test(val)) ids.add(val);
  }
  return ids;
}

const MAX_ATTEMPTS        = 5;
const WINDOW_MS           = 15 * 60 * 1000;
const BRUTE_ALERT_THRESHOLD = 3;

function getClientIP(req) {
  return (req.headers["x-forwarded-for"] || req.headers["x-real-ip"] || "unknown").split(",")[0].trim();
}

function timingSafeCompare(a, b) {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) { crypto.timingSafeEqual(bufA, Buffer.alloc(bufA.length)); return false; }
  return crypto.timingSafeEqual(bufA, bufB);
}

async function getDiscordProfile(userId) {
  const GUILD_ID = process.env.DISCORD_GUILD_ID, BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
  if (!GUILD_ID || !BOT_TOKEN) return { name: userId, avatarUrl: "" };
  try {
    const res = await fetch(`https://discord.com/api/v10/guilds/${GUILD_ID}/members/${userId}`,
      { headers: { Authorization: `Bot ${BOT_TOKEN}`, "Content-Type": "application/json" } });
    if (!res.ok) return { name: userId, avatarUrl: "" };
    const d = await res.json().catch(() => ({}));
    const name = d.nick || d.user?.global_name || d.user?.username || userId;
    let avatarUrl = "";
    if (d.avatar)            avatarUrl = `https://cdn.discordapp.com/guilds/${GUILD_ID}/users/${userId}/avatars/${d.avatar}.png?size=128`;
    else if (d.user?.avatar) avatarUrl = `https://cdn.discordapp.com/avatars/${userId}/${d.user.avatar}.png?size=128`;
    else                     avatarUrl = `https://cdn.discordapp.com/embed/avatars/${(BigInt(userId) >> 22n) % 6n}.png`;
    return { name, avatarUrl };
  } catch { return { name: userId, avatarUrl: "" }; }
}

async function sendWebhook(embed) {
  const WEBHOOK_URL = process.env.WEBHOOK_URL;
  if (!WEBHOOK_URL) return;
  try {
    const parsedUrl = new URL(WEBHOOK_URL);
    if (parsedUrl.protocol !== "https:") return;
    if (!parsedUrl.hostname.endsWith("discordapp.com") && !parsedUrl.hostname.endsWith("discord.com")) return;
    const body = Buffer.from(JSON.stringify({ username: "AntiSec OSINT", embeds: [embed] }), "utf8");
    await new Promise((resolve) => {
      const req = https.request({ hostname: parsedUrl.hostname, path: parsedUrl.pathname + parsedUrl.search, method: "POST", headers: { "Content-Type": "application/json", "Content-Length": body.length, "User-Agent": "AntiSec/1.0" }, timeout: 5000 },
        (r) => { r.on("data", () => {}); r.on("end", resolve); });
      req.on("error", () => resolve()); req.on("timeout", () => { req.destroy(); resolve(); });
      req.write(body); req.end();
    });
  } catch (_) {}
}

module.exports = async function handler(req, res) {
  Object.entries(getCorsHeaders(req)).forEach(([k, v]) => res.setHeader(k, v));
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method Not Allowed" });

  const envErr = envCheck();
  if (envErr) return res.status(500).json({ ok: false, error: envErr.error });

  const replayErr = replayGuard(req);
  if (replayErr) return res.status(400).json({ ok: false, error: replayErr });

  const ip = getClientIP(req);

  const limited = await kvRateLimit(`rl:auth:${ip}`, MAX_ATTEMPTS, WINDOW_MS / 1000);
  if (limited) { res.setHeader("Retry-After", String(WINDOW_MS / 1000)); return res.status(429).json({ ok: false, error: "Too many attempts. Try again later." }); }

  let payload;
  try {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString();
    if (raw.length > 512) return res.status(400).json({ ok: false, error: "Request body too large" });
    payload = JSON.parse(raw || "{}");
  } catch (_) { return res.status(400).json({ ok: false, error: "Invalid JSON" }); }

  if (typeof payload !== "object" || payload === null || Array.isArray(payload))
    return res.status(400).json({ ok: false, error: "Invalid request format" });

  const allowed = new Set(["password", "userId"]);
  if (Object.keys(payload).some((k) => !allowed.has(k)))
    return res.status(400).json({ ok: false, error: "Unexpected fields in request" });

  const { password, userId } = payload;
  const uid = String(userId || "").trim();
  if (!uid || !/^\d{17,19}$/.test(uid)) return res.status(401).json({ ok: false, error: "Missing or invalid Discord User ID" });

  const kvEntry        = await kv.get(`${KV_CONFIRMED}${uid}`);
  const confirmedUntil = kvEntry?.confirmedUntil || 0;
  if (Date.now() > confirmedUntil) {
    const INVITE = process.env.DISCORD_INVITE;
    return res.status(403).json({ ok: false, error: `We couldn't verify your account. Please join our server (${INVITE}) and wear our Tag to access our Premium Tool.` });
  }

  if (!getSpecialUsers().has(uid)) {
    const GUILD_ID  = process.env.DISCORD_GUILD_ID;
    const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
    const ROLE_ID   = process.env.DISCORD_ROLE_ID;
    if (GUILD_ID && BOT_TOKEN && ROLE_ID) {
      const memberRes = await fetch(`https://discord.com/api/v10/guilds/${GUILD_ID}/members/${uid}`,
        { headers: { Authorization: `Bot ${BOT_TOKEN}`, "Content-Type": "application/json" } }).catch(() => null);
      if (memberRes && memberRes.ok) {
        const memberData = await memberRes.json().catch(() => ({}));
        const displayName = memberData.nick || memberData.user?.global_name || memberData.user?.username || "";
        const hasTag = displayName.endsWith(TAG_SUFFIX) || displayName.startsWith(TAG_PREFIX);
        if (!hasTag) {
          await fetch(`https://discord.com/api/v10/guilds/${GUILD_ID}/members/${uid}/roles/${ROLE_ID}`,
            { method: "DELETE", headers: { Authorization: `Bot ${BOT_TOKEN}`, "Content-Type": "application/json" } }).catch(() => {});
          return res.status(403).json({ ok: false, error: `Tag not found — add ${TAG_SUFFIX} to your server nickname to access this tool.`, requirement: "tag" });
        }
      }
    }
  }

  if (typeof password !== "string" || password.length === 0 || password.length > 128)
    return res.status(400).json({ ok: false, error: "Missing or invalid password field" });

  const expected = process.env.ANTISEC_PASSWORD;
  if (!expected) { console.error("ANTISEC_PASSWORD not set"); return res.status(500).json({ ok: false, error: "Server configuration error." }); }

  const valid   = timingSafeCompare(password, expected);
  const profile = await getDiscordProfile(uid);
  const safeIp  = ip.replace(/[^a-fA-F0-9.:]/g, "").slice(0, 45);
  const ts      = new Date().toISOString();

  if (!valid) {
    await new Promise((r) => setTimeout(r, 400 + Math.random() * 200));
    const failKey  = `antisec:fails:${uid}`;
    const failCount = await kv.incr(failKey, WINDOW_MS / 1000);
    const isBruteForce = failCount >= BRUTE_ALERT_THRESHOLD;
    await sendWebhook({
      title: isBruteForce ? "🚨 Brute-Force Alert" : "🔐 Failed Login Attempt",
      color: isBruteForce ? 0xff0000 : 0xff8800,
      author: { name: profile.name, icon_url: profile.avatarUrl },
      fields: [
        { name: "🏷️ Discord ID",     value: `\`${uid}\``,    inline: true },
        { name: "🌐 IP Address",     value: `||${safeIp}||`, inline: true },
        { name: "🔢 Failed Attempts",value: `**${failCount}**`, inline: true },
        ...(isBruteForce ? [{ name: "⚠️ Status", value: "Possible brute-force attack", inline: false }] : []),
      ],
      footer: { text: "AntiSec Auth Log · failed login" }, timestamp: ts,
    }).catch(() => {});
    return res.status(401).json({ ok: false, error: "Invalid credentials" });
  }

  await kv.del(`antisec:fails:${uid}`).catch(() => {});
  let token;
  try { token = createSessionToken(uid); }
  catch (e) { console.error("Token generation failed:", e.message); return res.status(500).json({ ok: false, error: "Server configuration error." }); }

  await sendWebhook({
    title: "✅ Successful Login", color: 0x00cc44,
    author: { name: profile.name, icon_url: profile.avatarUrl },
    fields: [{ name: "🏷️ Discord ID", value: `\`${uid}\``, inline: true }, { name: "🌐 IP Address", value: `||${safeIp}||`, inline: true }],
    footer: { text: "AntiSec Auth Log · successful login" }, timestamp: ts,
  }).catch(() => {});

  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({ ok: true, token });
};
