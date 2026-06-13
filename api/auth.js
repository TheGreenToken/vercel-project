"use strict";

const crypto = require("crypto");
const kv     = require("./kv");
const { envCheck, kvRateLimit, replayGuard, getCorsHeaders } = require("./middleware");
const { createSessionToken } = require("./session");

const KV_CONFIRMED = "antisec:confirmed:";
const WINDOW_SECS  = 15 * 60;
const MAX_IP       = 10;

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

async function getDiscordProfile(userId) {
  try {
    const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
    const GUILD_ID  = process.env.DISCORD_GUILD_ID;
    if (!BOT_TOKEN || !GUILD_ID) return {};
    const r = await fetch(`https://discord.com/api/v10/guilds/${GUILD_ID}/members/${userId}`,
      { headers: { Authorization: `Bot ${BOT_TOKEN}`, "Content-Type": "application/json" } });
    if (!r.ok) return {};
    return await r.json().catch(() => ({}));
  } catch { return {}; }
}

module.exports = async function handler(req, res) {
  Object.entries(getCorsHeaders(req)).forEach(([k, v]) => res.setHeader(k, v));
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST")    return res.status(405).json({ ok: false, error: "Method Not Allowed" });

  const envErr = envCheck();
  if (envErr) return res.status(500).json({ ok: false, error: "Server misconfiguration." });

  const replayErr = replayGuard(req);
  if (replayErr) return res.status(400).json({ ok: false, error: replayErr });

  const ip = (req.headers["x-forwarded-for"] || req.headers["x-real-ip"] || "unknown").split(",")[0].trim();
  if (await kvRateLimit(`rl:auth:${ip}`, MAX_IP, WINDOW_SECS))
    return res.status(429).json({ ok: false, error: "Too many requests. Try again later." });

  let payload;
  try {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString();
    if (raw.length > 512) return res.status(400).json({ ok: false, error: "Request too large" });
    payload = JSON.parse(raw || "{}");
  } catch { return res.status(400).json({ ok: false, error: "Invalid JSON" }); }

  if (typeof payload !== "object" || payload === null || Array.isArray(payload))
    return res.status(400).json({ ok: false, error: "Invalid request format" });

  const allowed = new Set(["userId"]);
  if (Object.keys(payload).some((k) => !allowed.has(k)))
    return res.status(400).json({ ok: false, error: "Unexpected fields in request" });

  const uid = String(payload.userId || "").trim();
  if (!uid || !/^\d{17,19}$/.test(uid))
    return res.status(401).json({ ok: false, error: "Missing or invalid Discord User ID" });

  let kvEntry;
  try {
    kvEntry = await kv.get(`${KV_CONFIRMED}${uid}`);
  } catch (e) {
    return res.status(500).json({ ok: false, error: "Verification check failed. Please try again." });
  }

  if (!kvEntry || typeof kvEntry !== "object") {
    const INVITE = process.env.DISCORD_INVITE;
    return res.status(403).json({ ok: false, error: `You haven't confirmed your identity yet. Please click the DM link first.` });
  }

  const confirmedUntil = Number(kvEntry.confirmedUntil) || 0;
  if (Date.now() > confirmedUntil) {
    const INVITE = process.env.DISCORD_INVITE;
    return res.status(403).json({ ok: false, error: `Confirmation expired. Please verify again.` });
  }

  if (!getSpecialUsers().has(uid)) {
    const GUILD_ID  = process.env.DISCORD_GUILD_ID;
    const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
    const ROLE_ID   = process.env.DISCORD_ROLE_ID;
    if (GUILD_ID && BOT_TOKEN && ROLE_ID) {
      const memberData = await getDiscordProfile(uid);
      if (memberData && typeof memberData === "object") {
        const displayName = memberData.nick || memberData.user?.global_name || memberData.user?.username || "";
        const hasTag = displayName.endsWith(TAG_SUFFIX) || displayName.startsWith(TAG_PREFIX);
        if (!hasTag) {
          await fetch(`https://discord.com/api/v10/guilds/${GUILD_ID}/members/${uid}/roles/${ROLE_ID}`,
            { method: "DELETE", headers: { Authorization: `Bot ${BOT_TOKEN}`, "Content-Type": "application/json" } }).catch(() => {});
          return res.status(403).json({ ok: false, error: `Tag not found — add ${TAG_SUFFIX} to your server nickname.`, requirement: "tag" });
        }
      }
    }
  }

  await kv.del(`${KV_CONFIRMED}${uid}`).catch(() => {});

  const safeIp = ip.replace(/[^a-fA-F0-9.:]/g, "").slice(0, 45);
  const ts     = new Date().toISOString();
  const token  = createSessionToken(uid);

  const WEBHOOK_URL = process.env.WEBHOOK_URL;
  if (WEBHOOK_URL) {
    try {
      const pu = new URL(WEBHOOK_URL);
      if (pu.protocol === "https:" && (pu.hostname.endsWith("discord.com") || pu.hostname.endsWith("discordapp.com"))) {
        const profile = await getDiscordProfile(uid);
        const name    = profile?.nick || profile?.user?.global_name || profile?.user?.username || uid;
        await fetch(WEBHOOK_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
          username: "AntiSec Auth",
          embeds: [{ title: "✅ Successful Login", color: 0x2a6600,
            fields: [
              { name: "Discord", value: `${name} (\`${uid}\`)`, inline: true },
              { name: "IP",      value: `||${safeIp}||`,         inline: true },
              { name: "Time",    value: ts,                       inline: false },
            ], timestamp: ts }]
        }) });
      }
    } catch (_) {}
  }

  return res.status(200).json({ ok: true, token });
};
