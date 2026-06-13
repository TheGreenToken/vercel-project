"use strict";

const { verifySessionToken, blacklistToken } = require("./session");
const { envCheck, replayGuard, getCorsHeaders } = require("./middleware");

module.exports = async function handler(req, res) {
  Object.entries(getCorsHeaders(req)).forEach(([k, v]) => res.setHeader(k, v));
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ ok: false, error: "Method Not Allowed" });

  const envErr = envCheck();
  if (envErr) return res.status(500).json({ ok: false, error: "Server misconfiguration." });

  const replayErr = replayGuard(req);
  if (replayErr) return res.status(400).json({ ok: false, error: replayErr });

  const rawToken = String(req.headers["x-session-token"] || "").trim();
  const session  = verifySessionToken(rawToken);

  if (session.ok) {
    await blacklistToken(rawToken, session.expiresAt).catch(() => {});
  }

  return res.status(200).json({ ok: true });
};
