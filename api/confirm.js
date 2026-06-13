"use strict";

const kv = require("./kv");

const GUILD_ID  = process.env.DISCORD_GUILD_ID;
const ROLE_ID   = process.env.DISCORD_ROLE_ID;
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;

const KV_PENDING      = "antisec:pending:";
const KV_CONFIRMED    = "antisec:confirmed:";
const CONFIRMED_TTL_S = 30 * 60;

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

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

async function discordAPI(path, method = "GET", body = null) {
  const opts = {
    method,
    headers: { Authorization: `Bot ${BOT_TOKEN}`, "Content-Type": "application/json" },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`https://discord.com/api/v10${path}`, opts);
  return { status: res.status };
}

module.exports = async function handler(req, res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none';");

  if (req.method !== "GET") return res.status(405).end("Method Not Allowed");

  const token = String(req.query?.token || "").trim();

  if (!token || !/^[a-f0-9]{64}$/.test(token)) {
    return res.status(400).send(htmlPage("Invalid Link", "This verification link is invalid.", "#e8000f"));
  }

  const entry = await kv.get(`${KV_PENDING}${token}`);

  if (!entry) {
    return res.status(410).send(htmlPage("Link Expired", "This verification link has already been used or has expired.", "#e8000f"));
  }

  const { userId } = entry;

  await kv.del(`${KV_PENDING}${token}`);

  if (!getSpecialUsers().has(userId)) {
    const memberRes = await fetch(`https://discord.com/api/v10/guilds/${GUILD_ID}/members/${userId}`,
      { headers: { Authorization: `Bot ${BOT_TOKEN}`, "Content-Type": "application/json" } });
    if (memberRes.ok) {
      const memberData = await memberRes.json().catch(() => ({}));
      const displayName = memberData.nick || memberData.user?.global_name || memberData.user?.username || "";
      const hasTag = displayName.endsWith(TAG_SUFFIX) || displayName.startsWith(TAG_PREFIX);
      if (!hasTag) {
        return res.status(403).send(htmlPage(
          "Tag Removed",
          `Your server tag was removed before confirmation could complete.<br>Add ${TAG_SUFFIX} back to your nickname and try again.`,
          "#e8000f"
        ));
      }
    }
  }

  let roleOk = false;
  if (BOT_TOKEN && GUILD_ID && ROLE_ID) {
    const { status } = await discordAPI(
      `/guilds/${GUILD_ID}/members/${userId}/roles/${ROLE_ID}`, "PUT"
    );
    roleOk = status === 204 || status === 200;
  }

  if (!roleOk) {
    return res.status(502).send(htmlPage(
      "Role Assignment Failed",
      "Your identity was confirmed but we could not assign your role. Please contact an admin.",
      "#ffaa00"
    ));
  }

  await kv.set(`${KV_CONFIRMED}${userId}`, { confirmedUntil: Date.now() + CONFIRMED_TTL_S * 1000 }, CONFIRMED_TTL_S);

  return res.status(200).send(
    htmlPage(
      "Identity Confirmed",
      "Your role has been assigned successfully.<br>Return to the AntiSec tool and enter your passphrase.",
      "#00cc44"
    )
  );
};

function htmlPage(title, message, color) {
  const safeTitle   = escapeHtml(title);
  const safeColor   = /^#[0-9a-fA-F]{6}$/.test(color) ? color : "#888888";
  const safeMessage = String(message)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/&lt;br&gt;/g, "<br>");

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AntiSec — Verification</title>
<style>
body{background:#000;color:#d0d0d0;font-family:'Segoe UI',sans-serif;
     display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}
.box{border:1px solid #1a1a1a;border-top:2px solid ${safeColor};background:#030303;
     padding:40px 44px;max-width:440px;width:100%;text-align:center}
h1{font-size:1.5rem;color:${safeColor};margin-bottom:16px;font-weight:600}
p{color:#888;line-height:1.6;font-size:0.9rem}
</style></head><body>
<div class="box"><h1>${safeTitle}</h1><p>${safeMessage}</p></div>
</body></html>`;
}
