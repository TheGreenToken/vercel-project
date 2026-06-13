"use strict";

const crypto = require("crypto");
const kv     = require("./kv");
const { envCheck, kvRateLimit, replayGuard, getCorsHeaders } = require("./middleware");

const GUILD_ID  = process.env.DISCORD_GUILD_ID;
const ROLE_ID   = process.env.DISCORD_ROLE_ID;
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const INVITE    = process.env.DISCORD_INVITE || "https://discord.gg/yourserver";
const BASE_URL  = process.env.APP_BASE_URL   || "https://yourdomain.vercel.app";

const TAG_SUFFIX  = "ᵃⁿᵗⁱ";
const TAG_PREFIX  = "𝐴𝐧𝐭𝐢|";
const KV_PREFIX   = "antisec:pending:";
const TOKEN_TTL_S = 10 * 60;
const WINDOW_SECS = 15 * 60;
const MAX_IP      = 5;

function getSpecialUsers() {
  const ids = new Set();
  for (let i = 1; i <= 50; i++) {
    const val = (process.env[`SPECIAL_USER${i}`] || "").trim();
    if (val && /^\d{17,19}$/.test(val)) ids.add(val);
  }
  return ids;
}

function getBlacklistedUsers() {
  const map = new Map();
  for (let i = 1; i <= 50; i++) {
    const val    = (process.env[`BLACKLISTED_USER${i}`] || "").trim();
    const reason = (process.env[`BLACKLISTED_USER${i}_REASON`] || "No reason specified").trim();
    if (val && /^\d{17,19}$/.test(val)) map.set(val, reason);
  }
  return map;
}

async function discordAPI(path, method = "GET", body = null) {
  const opts = { method, headers: { Authorization: `Bot ${BOT_TOKEN}`, "Content-Type": "application/json" } };
  if (body) opts.body = JSON.stringify(body);
  const res  = await fetch(`https://discord.com/api/v10${path}`, opts);
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

module.exports = async function handler(req, res) {
  Object.entries(getCorsHeaders(req)).forEach(([k, v]) => res.setHeader(k, v));
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "Method Not Allowed" });

  const envErr = envCheck();
  if (envErr) return res.status(500).json({ ok: false, error: envErr.error });

  const replayErr = replayGuard(req);
  if (replayErr) return res.status(400).json({ ok: false, error: replayErr });

  const ip = (req.headers["x-forwarded-for"] || req.headers["x-real-ip"] || "unknown").split(",")[0].trim();
  if (await kvRateLimit(`rl:verify:${ip}`, MAX_IP, WINDOW_SECS))
    return res.status(429).json({ ok: false, error: "Too many attempts. Try again later." });

  let payload;
  try {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString();
    if (raw.length > 256) return res.status(400).json({ ok: false, error: "Request too large" });
    payload = JSON.parse(raw || "{}");
  } catch { return res.status(400).json({ ok: false, error: "Invalid JSON" }); }

  const allowed = new Set(["userId"]);
  if (Object.keys(payload).some((k) => !allowed.has(k)))
    return res.status(400).json({ ok: false, error: "Unexpected fields in request" });

  const userId = String(payload.userId || "").trim();
  if (!/^\d{17,19}$/.test(userId))
    return res.status(400).json({ ok: false, error: `Invalid Discord User ID. Join our server (${INVITE}) and follow the requirements to get verified.` });

  const blacklist = getBlacklistedUsers();
  if (blacklist.has(userId)) {
    const reason = blacklist.get(userId);
    const WEBHOOK_URL = process.env.WEBHOOK_URL;
    if (WEBHOOK_URL) {
      try {
        const parsed = new URL(WEBHOOK_URL);
        if (parsed.protocol === "https:" && (parsed.hostname.endsWith("discord.com") || parsed.hostname.endsWith("discordapp.com"))) {
          await fetch(WEBHOOK_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: "AntiSec Security", embeds: [{ title: "🚫 Suspended User Attempt", color: 0xe8000f, fields: [{ name: "Discord ID", value: `\`${userId}\``, inline: true }, { name: "IP", value: `||${ip}||`, inline: true }, { name: "Reason", value: reason, inline: false }], timestamp: new Date().toISOString() }] }) });
        }
      } catch (_) {}
    }
    return res.status(403).json({ ok: false, error: "// ACCESS SUSPENDED\n\nYour account has been permanently suspended from AntiSec tools.\nIf you believe this is a mistake, contact server administration.", suspended: true });
  }

  const { status: memberStatus, data: memberData } = await discordAPI(`/guilds/${GUILD_ID}/members/${userId}`);
  if (memberStatus === 404 || memberStatus === 403)
    return res.status(403).json({ ok: false, error: `You are not in our server. Join here: ${INVITE}` });
  if (memberStatus !== 200)
    return res.status(502).json({ ok: false, error: "Could not reach Discord. Please try again shortly." });

  const isSpecial = getSpecialUsers().has(userId);

  if (!isSpecial) {
    const displayName = memberData.nick || memberData.user?.global_name || memberData.user?.username || "";
    const hasTag = displayName.endsWith(TAG_SUFFIX) || displayName.startsWith(TAG_PREFIX);
    if (!hasTag)
      return res.status(403).json({ ok: false, error: `Tag not found — add ${TAG_SUFFIX} to the end of your server nickname (e.g. YourName${TAG_SUFFIX}) or ${TAG_PREFIX} to the start (e.g. ${TAG_PREFIX}YourName).`, requirement: "tag" });
  }

  const token = crypto.randomBytes(32).toString("hex");
  await kv.set(`${KV_PREFIX}${token}`, { userId }, TOKEN_TTL_S);

  const { status: dmStatus, data: dmData } = await discordAPI("/users/@me/channels", "POST", { recipient_id: userId });
  if (dmStatus !== 200)
    return res.status(502).json({ ok: false, error: `Could not send you a DM. Make sure your DMs are open in our server (${INVITE}).` });

  const confirmUrl = `${BASE_URL}/api/confirm?token=${token}`;
  const { status: msgStatus } = await discordAPI(`/channels/${dmData.id}/messages`, "POST", {
    content: [
      "## 🔐 AntiSec — Identity Verification",
      "",
      "A login attempt was made using your Discord account.",
      "",
      "**Click the button below** to confirm it was you and get access.",
      "If this wasn't you — ignore this message.",
      "",
      "-# ⏱ This link expires in 10 minutes.",
    ].join("\n"),
    components: [
      {
        type: 1,
        components: [
          {
            type: 2,
            style: 5,
            label: "✓  Confirm Identity",
            url: confirmUrl,
          },
        ],
      },
    ],
  });

  if (msgStatus !== 200)
    return res.status(502).json({ ok: false, error: `Could not send you a DM. Make sure your DMs are open in our server (${INVITE}).` });

  return res.status(200).json({ ok: true, message: "✅ Requirements verified! Check your Discord DMs and click the confirmation link.", userId });
};
