"use strict";

const crypto = require("crypto");
const kv     = require("../lib/kv");
const { kvRateLimit, getCorsHeaders } = require("../lib/middleware");
const { createSessionToken, verifySessionToken, blacklistToken } = require("../lib/session");
const { upsertUserLogin, getUserByDiscordId, getDatabaseUrl } = require("../lib/db");

const SESSION_COOKIE = "mono_session";
const STATE_TTL = 10 * 60; // 10 min

function getEnvBlacklist() {
  const map = new Map();
  for (let i = 1; i <= 50; i++) {
    const id = String(process.env[`BLACKLISTED_USER${i}`] || "").trim();
    const reason = String(process.env[`BLACKLISTED_USER${i}_REASON`] || "No reason").trim();
    if (id && /^\d{17,19}$/.test(id)) map.set(id, reason);
  }
  return map;
}

async function isUserBlacklisted(userId) {
  const envBl = getEnvBlacklist();
  if (envBl.has(userId)) return { blocked: true, reason: envBl.get(userId) || "Blacklisted" };
  try {
    const entry = await kv.get(`mono:kv_blacklist:${userId}`);
    if (entry) return { blocked: true, reason: String(entry.reason || "Blacklisted").slice(0, 100) };
  } catch (_) {}
  return { blocked: false, reason: "" };
}

function getBaseUrl(req) {
  const env = process.env.APP_BASE_URL;
  if (env) return env.replace(/\/$/, "");
  const proto = (req.headers["x-forwarded-proto"] || "https").split(",")[0].trim();
  const host  = (req.headers["x-forwarded-host"] || req.headers["host"] || "").split(",")[0].trim();
  return `${proto}://${host}`;
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

function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (opts.maxAge !== undefined) parts.push(`Max-Age=${opts.maxAge}`);
  parts.push(`Path=${opts.path || "/"}`);
  if (opts.httpOnly) parts.push("HttpOnly");
  if (opts.secure !== false) parts.push("Secure");
  parts.push(`SameSite=${opts.sameSite || "Lax"}`);
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearCookie(res, name) {
  setCookie(res, name, "", { maxAge: 0, httpOnly: true, sameSite: "Lax" });
}

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

function getSession(req) {
  const cookies = parseCookies(req);
  const token = cookies[SESSION_COOKIE] || String(req.headers["x-session-token"] || "").trim();
  if (!token) return { ok: false };
  const session = verifySessionToken(token);
  if (!session.ok) return { ok: false };
  return { ...session, token };
}

async function getDiscordUser(accessToken) {
  const r = await fetch("https://discord.com/api/v10/users/@me", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!r.ok) throw new Error("Discord user fetch failed");
  return r.json();
}

function avatarUrl(user) {
  if (user.avatar) return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=128`;
  const idx = user.discriminator && user.discriminator !== "0"
    ? Number(user.discriminator) % 5
    : Number((BigInt(user.id) >> 22n) % 6n);
  return `https://cdn.discordapp.com/embed/avatars/${idx}.png`;
}

module.exports = async function handler(req, res) {
  Object.entries(getCorsHeaders(req)).forEach(([k, v]) => res.setHeader(k, v));
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "OPTIONS") return res.status(204).end();

  const url = new URL(req.url, getBaseUrl(req));
  const action = String(req.query.action || url.searchParams.get("action") || "").trim();

  const ip = (req.headers["x-forwarded-for"] || req.headers["x-real-ip"] || "unknown").split(",")[0].trim().slice(0, 45);
  const rlKey = `rl:auth:${action || "unknown"}:${ip}`;
  const rlLimit = action === "callback" ? 30 : 60;
  if (await kvRateLimit(rlKey, rlLimit, 60)) {
    return json(res, 429, { error: "Too many requests. Try again later." });
  }

  function signState(payload) {
    const secret = process.env.SESSION_SECRET || "";
    return crypto.createHmac("sha256", secret).update(payload).digest("hex");
  }
  function makeState() {
    const nonce = crypto.randomBytes(16).toString("hex");
    const ts = Date.now().toString(36);
    const payload = `${nonce}.${ts}`;
    return `${payload}.${signState(payload)}`;
  }
  function verifyState(state) {
    if (!state || typeof state !== "string") return false;
    const parts = state.split(".");
    if (parts.length !== 3) return false;
    const [nonce, ts36, sig] = parts;
    if (!/^[a-f0-9]{32}$/.test(nonce)) return false;
    if (!/^[a-z0-9]+$/.test(ts36)) return false;
    if (!/^[a-f0-9]{64}$/.test(sig)) return false;
    const payload = `${nonce}.${ts36}`;
    const expected = signState(payload);
    try {
      const a = Buffer.from(sig, "hex");
      const b = Buffer.from(expected, "hex");
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
    } catch { return false; }
    const ts = parseInt(ts36, 36);
    if (!Number.isFinite(ts)) return false;
    if (Math.abs(Date.now() - ts) > STATE_TTL * 1000) return false;
    return true;
  }

  // ---- LOGIN ----
  if (action === "login") {
    if (req.method !== "GET") return json(res, 405, { error: "Method Not Allowed" });
    const clientId = process.env.DISCORD_CLIENT_ID;
    const baseUrl  = getBaseUrl(req);
    const redirectUri = `${baseUrl}/api/auth/callback`;
    if (!clientId || !process.env.SESSION_SECRET) {
      res.statusCode = 302;
      res.setHeader("Location", `${baseUrl}/?auth_error=server_config`);
      return res.end();
    }

    const state = makeState();

    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "identify email",
      state,
      prompt: "consent",
    });
    res.statusCode = 302;
    res.setHeader("Location", `https://discord.com/oauth2/authorize?${params.toString()}`);
    return res.end();
  }

  // ---- CALLBACK ----
  if (action === "callback") {
    if (req.method !== "GET") return json(res, 405, { error: "Method Not Allowed" });
    const baseUrl = getBaseUrl(req);
    const code  = String(req.query.code || "").trim();
    const state = String(req.query.state || "").trim();
    const err   = String(req.query.error || "").trim();

    if (err) {
      res.statusCode = 302;
      res.setHeader("Location", `${baseUrl}/?auth_error=${encodeURIComponent(err)}`);
      return res.end();
    }
    if (!code || !/^[a-zA-Z0-9_-]+$/.test(code) || !state) {
      res.statusCode = 302;
      res.setHeader("Location", `${baseUrl}/?auth_error=invalid_callback`);
      return res.end();
    }

    if (!verifyState(state)) {
      res.statusCode = 302;
      res.setHeader("Location", `${baseUrl}/?auth_error=invalid_state`);
      return res.end();
    }

    const clientId     = process.env.DISCORD_CLIENT_ID;
    const clientSecret = process.env.DISCORD_CLIENT_SECRET;
    const redirectUri  = `${baseUrl}/api/auth/callback`;
    if (!clientId || !clientSecret) {
      res.statusCode = 302;
      res.setHeader("Location", `${baseUrl}/?auth_error=server_config`);
      return res.end();
    }

    try {
      const tokenRes = await fetch("https://discord.com/api/v10/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          grant_type: "authorization_code",
          code,
          redirect_uri: redirectUri,
        }),
      });
      const tokenData = await tokenRes.json().catch(() => ({}));
      if (!tokenRes.ok || !tokenData.access_token) {
        res.statusCode = 302;
        res.setHeader("Location", `${baseUrl}/?auth_error=token_exchange_failed`);
        return res.end();
      }

      const user = await getDiscordUser(tokenData.access_token);
      if (!user || !/^\d{17,19}$/.test(String(user.id || ""))) {
        res.statusCode = 302;
        res.setHeader("Location", `${baseUrl}/?auth_error=user_fetch_failed`);
        return res.end();
      }

      const ip = (req.headers["x-forwarded-for"] || req.headers["x-real-ip"] || "unknown").split(",")[0].trim().slice(0, 45);
      const email = typeof user.email === "string" ? user.email.trim().toLowerCase().slice(0, 254) : "";
      const now = new Date().toISOString();

      const profile = {
        id: String(user.id),
        username: String(user.global_name || user.username || "Unknown").slice(0, 100),
        handle: String(user.username || "").slice(0, 100),
        avatar: avatarUrl(user),
        email,
      };

      const bl = await isUserBlacklisted(profile.id);
      if (bl.blocked) {
        res.statusCode = 302;
        res.setHeader("Location", `${baseUrl}/?auth_error=blacklisted`);
        return res.end();
      }

      await kv.set(`mono:user:${profile.id}`, profile, 30 * 24 * 60 * 60);

      // Persist login record in Neon database
      if (getDatabaseUrl()) {
        try {
          await upsertUserLogin({
            discordId: profile.id,
            email,
            username: profile.username,
            handle: profile.handle,
            avatar: profile.avatar,
            ip,
          });
        } catch (dbErr) {
          console.error("[mono] Failed to persist login to Neon:", dbErr?.message || dbErr);
        }
      } else {
        console.error("[mono] DATABASE_URL not configured - login not persisted to Neon");
      }

      const sessionToken = createSessionToken(profile.id);
      setCookie(res, SESSION_COOKIE, sessionToken, { httpOnly: true, sameSite: "Lax", maxAge: 30 * 24 * 60 * 60, secure: true });

      res.statusCode = 302;
      res.setHeader("Location", `${baseUrl}/?auth=ok`);
      return res.end();
    } catch (e) {
      res.statusCode = 302;
      res.setHeader("Location", `${baseUrl}/?auth_error=callback_failed`);
      return res.end();
    }
  }

  // ---- ME ----
  if (action === "me") {
    if (req.method !== "GET") return json(res, 405, { error: "Method Not Allowed" });
    const session = getSession(req);
    if (!session.ok) return json(res, 200, { authenticated: false });

    const bl = await isUserBlacklisted(session.userId);
    if (bl.blocked) {
      setCookie(res, SESSION_COOKIE, "", { httpOnly: true, sameSite: "Lax", maxAge: 0, secure: true });
      return json(res, 200, { authenticated: false, error: "blacklisted" });
    }

    let profile = await kv.get(`mono:user:${session.userId}`).catch(() => null);
    if (!profile || typeof profile !== "object") {
      if (getDatabaseUrl()) {
        const dbUser = await getUserByDiscordId(session.userId).catch(() => null);
        if (dbUser) {
          profile = {
            id: String(dbUser.discord_id),
            username: String(dbUser.username || "Discord User"),
            handle: String(dbUser.handle || ""),
            avatar: String(dbUser.avatar || ""),
            email: String(dbUser.email || ""),
          };
        }
      }
    }
    if (!profile || typeof profile !== "object") {
      profile = { id: session.userId, username: "Discord User", handle: "", avatar: "https://cdn.discordapp.com/embed/avatars/0.png", email: "" };
    }
    return json(res, 200, {
      authenticated: true,
      token: session.token,
      user: {
        id: String(profile.id || session.userId),
        username: String(profile.username || "Discord User").slice(0, 100),
        handle: String(profile.handle || "").slice(0, 100),
        avatar: typeof profile.avatar === "string" && profile.avatar.startsWith("https://cdn.discordapp.com/") ? profile.avatar : "https://cdn.discordapp.com/embed/avatars/0.png",
        email: typeof profile.email === "string" ? profile.email.slice(0, 254) : "",
      },
    });
  }

  // ---- LOGOUT ----
  if (action === "logout") {
    if (req.method !== "POST") return json(res, 405, { error: "Method Not Allowed" });
    const session = getSession(req);
    if (session.ok) {
      await blacklistToken(session.token, session.expiresAt).catch(() => {});
    }
    clearCookie(res, SESSION_COOKIE);
    return json(res, 200, { ok: true });
  }

  return json(res, 404, { error: "Not found" });
};
