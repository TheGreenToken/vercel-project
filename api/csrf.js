"use strict";


const { verifySessionToken, isTokenBlacklisted } = require("./session");
const { makeCsrfToken, getCorsHeaders, envCheck, replayGuard } = require("./middleware");

module.exports = async function handler(req, res) {
  const cors = getCorsHeaders(req);
  Object.entries(cors).forEach(([k, v]) => res.setHeader(k, v));
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET") return res.status(405).json({ error: "Method Not Allowed" });

  const envErr = envCheck();
  if (envErr) return res.status(500).json({ error: "Server misconfiguration." });

  const replayErr = replayGuard(req);
  if (replayErr) return res.status(400).json({ error: replayErr });

  const rawToken = String(req.headers["x-session-token"] || "").trim();
  const session  = verifySessionToken(rawToken);
  if (!session.ok) return res.status(401).json({ error: "Unauthorized" });

  if (await isTokenBlacklisted(rawToken)) {
    return res.status(401).json({ error: "Session revoked — please log in again" });
  }

  return res.status(200).json({ csrfToken: makeCsrfToken(session.userId) });
};
