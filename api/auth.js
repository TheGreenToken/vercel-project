"use strict";

const crypto = require("crypto");

const DEFAULT_PASSWORD = "4nT!S3c#OSINT_2025$xZ9";

const attempts = {};
const MAX_ATTEMPTS = 5;
const WINDOW_MS    = 15 * 60 * 1000;

function getClientIP(req) {
  return (
    req.headers["x-forwarded-for"] ||
    req.headers["x-real-ip"] ||
    "unknown"
  ).split(",")[0].trim();
}

function isRateLimited(ip) {
  const now = Date.now();
  if (!attempts[ip] || now > attempts[ip].resetAt) {
    attempts[ip] = { count: 0, resetAt: now + WINDOW_MS };
  }
  attempts[ip].count++;
  return attempts[ip].count > MAX_ATTEMPTS;
}

function timingSafeCompare(a, b) {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(bufA, Buffer.alloc(bufA.length));
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function isValidPasswordInput(pw) {
  if (typeof pw !== "string") return false;
  if (pw.length === 0 || pw.length > 128) return false;
  return true;
}

const corsHeaders = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "X-Content-Type-Options":       "nosniff",
  "X-Frame-Options":              "DENY",
  "Referrer-Policy":              "no-referrer",
};

module.exports = async function handler(req, res) {
  Object.entries(corsHeaders).forEach(([k, v]) => res.setHeader(k, v));

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST, OPTIONS");
    return res.status(405).json({ error: "Method Not Allowed" });
  }

  const ip = getClientIP(req);
  if (isRateLimited(ip)) {
    res.setHeader("Retry-After", String(WINDOW_MS / 1000));
    return res.status(429).json({ ok: false, error: "Too many attempts. Try again later." });
  }

  let payload;
  try {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString();
    if (raw.length > 512) return res.status(400).json({ ok: false, error: "Request body too large" });
    payload = JSON.parse(raw || "{}");
  } catch (_) {
    return res.status(400).json({ ok: false, error: "Invalid JSON" });
  }

  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return res.status(400).json({ ok: false, error: "Invalid request format" });
  }

  const { password } = payload;
  if (!isValidPasswordInput(password)) {
    return res.status(400).json({ ok: false, error: "Missing or invalid password field" });
  }

  const expected = process.env.ANTISEC_PASSWORD || DEFAULT_PASSWORD;
  const valid    = timingSafeCompare(password, expected);

  if (!valid) {
    await new Promise((r) => setTimeout(r, 400 + Math.random() * 200));
    return res.status(401).json({ ok: false, error: "Invalid credentials" });
  }

  res.setHeader("Cache-Control", "no-store");
  return res.status(200).json({ ok: true });
};
