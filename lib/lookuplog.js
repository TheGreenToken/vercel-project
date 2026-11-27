"use strict";

// Shared lookup activity log. Every tool endpoint records its lookups here,
// keyed by user, so all activity across modules is captured in one place
// regardless of which tool produced it. Stored as a JSON array in KV.

const kv = require("./kv");

const KEY = (userId) => `mono:lookuplog:${userId}`;
const GLOBAL_KEY = "mono:lookuplog:all";
const MAX_ENTRIES = 60;
const MAX_GLOBAL = 300;

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

// Append a lookup to the user's log (newest first), trimmed to MAX_ENTRIES,
// and to a global feed (newest first, trimmed to MAX_GLOBAL) so admins can
// see activity across all users.
async function appendLookup(userId, entry) {
  if (userId) {
    const key = KEY(userId);
    let list = [];
    try { const cur = await kv.get(key); if (Array.isArray(cur)) list = cur; } catch (_) {}
    list.unshift(entry);
    if (list.length > MAX_ENTRIES) list = list.slice(0, MAX_ENTRIES);
    try { await kv.set(key, list); } catch (_) {}
  }
  const globalEntry = { ...entry, userId: userId || "" };
  let global = [];
  try { const cur = await kv.get(GLOBAL_KEY); if (Array.isArray(cur)) global = cur; } catch (_) {}
  global.unshift(globalEntry);
  if (global.length > MAX_GLOBAL) global = global.slice(0, MAX_GLOBAL);
  try { await kv.set(GLOBAL_KEY, global); } catch (_) {}
  return list;
}

async function getLookups(userId) {
  if (!userId) return [];
  try { const cur = await kv.get(KEY(userId)); return Array.isArray(cur) ? cur : []; } catch (_) { return []; }
}

// Global feed across all users (for the admin panel).
async function getAllLookups() {
  try { const cur = await kv.get(GLOBAL_KEY); return Array.isArray(cur) ? cur : []; } catch (_) { return []; }
}

async function clearLookups(userId) {
  if (!userId) return;
  try { await kv.del(KEY(userId)); } catch (_) {}
}

// Admin: wipe the global feed entirely.
async function clearAllLookups() {
  try { await kv.del(GLOBAL_KEY); } catch (_) {}
}

module.exports = { appendLookup, getLookups, getAllLookups, clearLookups, clearAllLookups, makeEntry, MAX_ENTRIES, MAX_GLOBAL };
