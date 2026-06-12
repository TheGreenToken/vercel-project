"use strict";

const crypto = require("crypto");
const kv     = require("./kv");

const SESSION_TTL = 30 * 24 * 60 * 60 * 1000;

function getSecret() {
  const s = process.env.SESSION_SECRET;
  if (!s || s.length < 32) throw new Error("SESSION_SECRET not set or too short (min 32 chars)");
  return s;
}

function createSessionToken(userId) {
  const secret    = getSecret();
  const expiresAt = Date.now() + SESSION_TTL;
  const jti       = crypto.randomBytes(8).toString("hex"); // unique token ID for blacklisting
  const payload   = `${userId}|${expiresAt}|${jti}`;
  const hmac      = crypto.createHmac("sha256", secret).update(payload).digest("hex");
  return Buffer.from(`${payload}|${hmac}`).toString("base64url");
}

function verifySessionToken(token) {
  if (typeof token !== "string" || token.length === 0 || token.length > 512) {
    return { ok: false, error: "Missing or malformed session token" };
  }
  let decoded;
  try { decoded = Buffer.from(token, "base64url").toString("utf8"); }
  catch { return { ok: false, error: "Invalid token encoding" }; }

  const lastPipe     = decoded.lastIndexOf("|");
  if (lastPipe < 1)  return { ok: false, error: "Invalid token structure" };

  const payload      = decoded.slice(0, lastPipe);
  const receivedHmac = decoded.slice(lastPipe + 1);
  const parts        = payload.split("|");
  if (parts.length !== 3) return { ok: false, error: "Invalid token structure" };

  const [userId, expiresAtStr, jti] = parts;
  if (!/^\d{17,19}$/.test(userId))   return { ok: false, error: "Invalid user ID in token" };
  if (!/^\d+$/.test(expiresAtStr))   return { ok: false, error: "Invalid expiry in token" };
  if (!/^[a-f0-9]{16}$/.test(jti))  return { ok: false, error: "Invalid token ID" };

  let secret;
  try { secret = getSecret(); } catch (e) { return { ok: false, error: "Server configuration error" }; }

  const expectedHmac = crypto.createHmac("sha256", secret).update(payload).digest("hex");
  const buf1 = Buffer.from(receivedHmac, "utf8");
  const buf2 = Buffer.from(expectedHmac, "utf8");
  let valid  = false;
  try { valid = buf1.length === buf2.length && crypto.timingSafeEqual(buf1, buf2); } catch { valid = false; }
  if (!valid) return { ok: false, error: "Invalid session token signature" };

  const expiresAt = parseInt(expiresAtStr, 10);
  if (Date.now() > expiresAt) return { ok: false, error: "Session expired — please log in again" };

  return { ok: true, userId, expiresAt, jti };
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

async function blacklistToken(token, expiresAt) {
  const ttl = Math.max(1, Math.ceil((expiresAt - Date.now()) / 1000));
  await kv.blacklistToken(hashToken(token), ttl);
}

async function isTokenBlacklisted(token) {
  return kv.isBlacklisted(hashToken(token));
}

module.exports = { createSessionToken, verifySessionToken, blacklistToken, isTokenBlacklisted };
