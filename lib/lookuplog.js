"use strict";

// Shared lookup activity log. Every tool endpoint records its lookups here so
// all activity across modules is captured in one place regardless of which
// tool produced it. Persisted in the Neon Postgres database (lookup_logs
// table) — the project's real infrastructure — instead of KV.

const { insertLookupLog, listLookupLogs, deleteLookupLogs, getDatabaseUrl } = require("./db");

const MAX_USER_ENTRIES = 60;

// Normalize a tool + query into a compact log entry.
function makeEntry(tool, query, status, durationMs) {
  return {
    tool,
    query: String(query || "").slice(0, 253),
    status,
    at: new Date().toISOString(),
    durationMs: durationMs != null ? durationMs : null,
  };
}

function rowToEntry(r) {
  return {
    tool: r.tool || "",
    query: r.query || "",
    status: r.status || "",
    at: r.created_at ? new Date(r.created_at).toISOString() : "",
    durationMs: r.duration_ms != null ? r.duration_ms : null,
    userId: r.discord_id || "",
  };
}

// Append a lookup for the given user. Best-effort: if the DB is not
// configured or the insert fails, this is a silent no-op so logging never
// breaks the actual lookup.
async function appendLookup(userId, entry) {
  if (!getDatabaseUrl()) return [];
  try {
    await insertLookupLog({
      discordId: userId || "",
      tool: entry.tool,
      query: entry.query,
      status: entry.status,
      durationMs: entry.durationMs,
    });
  } catch (_) {
    return [];
  }
  return [];
}

// The user's own recent lookups (for their Activity Log tab).
async function getLookups(userId) {
  if (!getDatabaseUrl() || !userId) return [];
  try {
    const { rows } = await listLookupLogs({ discordId: userId, limit: MAX_USER_ENTRIES });
    return (rows || []).map(rowToEntry);
  } catch (_) {
    return [];
  }
}

// Global feed across all users (for the admin panel).
async function getAllLookups() {
  if (!getDatabaseUrl()) return [];
  try {
    const { rows } = await listLookupLogs({ limit: 100 });
    return (rows || []).map(rowToEntry);
  } catch (_) {
    return [];
  }
}

async function clearLookups(userId) {
  if (!getDatabaseUrl() || !userId) return;
  try { await deleteLookupLogs({ discordId: userId }); } catch (_) {}
}

// Admin: wipe the entire lookup log.
async function clearAllLookups() {
  if (!getDatabaseUrl()) return;
  try { await deleteLookupLogs({}); } catch (_) {}
}

module.exports = { appendLookup, getLookups, getAllLookups, clearLookups, clearAllLookups, makeEntry, MAX_USER_ENTRIES };
