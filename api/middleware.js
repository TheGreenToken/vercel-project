"use strict";

const kv = require("./kv");

async function kvRateLimit(key, max, windowSecs) {
  const count = await kv.incr(key, windowSecs);
  return count > max;
}

function getCorsHeaders(req) {
  const origin  = req.headers["origin"] || "";
  const allowed = process.env.APP_BASE_URL;
  const ao      = allowed && origin === allowed ? origin : (allowed || "null");
  return {
    "Access-Control-Allow-Origin":  ao,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Request-Time, X-Session-Token, X-Force-Refresh, X-Scan-Depth",
    "Access-Control-Allow-Credentials": "true",
    "X-Content-Type-Options":       "nosniff",
    "X-Frame-Options":              "DENY",
    "Referrer-Policy":              "no-referrer",
    "Vary":                         "Origin",
  };
}

module.exports = { kvRateLimit, getCorsHeaders };
