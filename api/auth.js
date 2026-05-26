"use strict";

const crypto = require("crypto");

const DEFAULT_PASSWORD = "4nT!S3c#OSINT_2025$xZ9";

const attempts = {};
const MAX_ATTEMPTS = 5;
const WINDOW_MS    = 15 * 60 * 1000;

function getClientIP(event) {
  return (
    (event.headers && (
      event.headers["x-forwarded-for"] ||
      event.headers["x-nf-client-connection-ip"] ||
      event.headers["client-ip"]
    )) || "unknown"
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

exports.handler = async (event) => {
  const corsHeaders = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "X-Content-Type-Options":       "nosniff",
    "X-Frame-Options":              "DENY",
    "Referrer-Policy":              "no-referrer",
  };

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: corsHeaders, body: "" };
  }

  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      headers: { ...corsHeaders, Allow: "POST, OPTIONS" },
      body: JSON.stringify({ error: "Method Not Allowed" }),
    };
  }

  const ip = getClientIP(event);

  if (isRateLimited(ip)) {
    return {
      statusCode: 429,
      headers: { ...corsHeaders, "Retry-After": String(WINDOW_MS / 1000) },
      body: JSON.stringify({ ok: false, error: "Too many attempts. Try again later." }),
    };
  }

  let payload;
  try {
    const raw = event.body || "{}";
    if (raw.length > 512) {
      return {
        statusCode: 400,
        headers: corsHeaders,
        body: JSON.stringify({ ok: false, error: "Request body too large" }),
      };
    }
    payload = JSON.parse(raw);
  } catch (_) {
    return {
      statusCode: 400,
      headers: corsHeaders,
      body: JSON.stringify({ ok: false, error: "Invalid JSON" }),
    };
  }

  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return {
      statusCode: 400,
      headers: corsHeaders,
      body: JSON.stringify({ ok: false, error: "Invalid request format" }),
    };
  }

  const { password } = payload;

  if (!isValidPasswordInput(password)) {
    return {
      statusCode: 400,
      headers: corsHeaders,
      body: JSON.stringify({ ok: false, error: "Missing or invalid password field" }),
    };
  }

  const expected = process.env.ANTISEC_PASSWORD || DEFAULT_PASSWORD;
  const valid    = timingSafeCompare(password, expected);

  if (!valid) {
    await new Promise((r) => setTimeout(r, 400 + Math.random() * 200));
    return {
      statusCode: 401,
      headers: corsHeaders,
      body: JSON.stringify({ ok: false, error: "Invalid credentials" }),
    };
  }

  return {
    statusCode: 200,
    headers: {
      ...corsHeaders,
      "Cache-Control": "no-store",
      "Content-Type":  "application/json",
    },
    body: JSON.stringify({ ok: true }),
  };
};

