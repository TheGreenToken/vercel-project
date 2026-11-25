"use strict";

const crypto = require("crypto");
const kv     = require("./kv");
const { kvRateLimit, getCorsHeaders } = require("./middleware");
const { verifySessionToken, isTokenBlacklisted } = require("./session");

const EMAIL_RE = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

function json(res, status, body) {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.status(status).send(JSON.stringify(body));
}
function parseCookies(req) {
  const raw = String(req.headers["cookie"] || "");
  const out = {};
  raw.split(/;\s*/).forEach(part => { const idx = part.indexOf("="); if (idx > 0) out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim()); });
  return out;
}
function sanitizeEmail(e) { const email = String(e || "").trim().toLowerCase().slice(0, 254); return EMAIL_RE.test(email) ? email : ""; }
async function fetchWithTimeout(url, opts = {}, ms = 3500) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try { return await fetch(url, { ...opts, signal: ctrl.signal, redirect: opts.redirect || "follow" }); }
  finally { clearTimeout(t); }
}


async function check_atlassian(email) {
  const meta = { name: "atlassian", domain: "", category: "cms", method: "" };
  try {
    const url = "https://id.atlassian.com/rest/check-username";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_gravatar(email) {
  const meta = { name: "gravatar", domain: "gravatar.com", category: "osint", method: "other" };
  try {
    const hash = crypto.createHash("md5").update(String(email).trim().toLowerCase()).digest("hex");
    const r = await fetchWithTimeout(`https://en.gravatar.com/${hash}.json`, { headers: { "User-Agent": "Mozilla/5.0" } }, 8000);
    if (r.status === 200) { const d = await r.json().catch(()=>null); const n=d?.entry?.[0]?.displayName||d?.entry?.[0]?.preferredUsername||"Profile exists"; return { ...meta, status:"found", detail:String(n).slice(0,80)}; }
    if (r.status === 404) return { ...meta, status:"not_found", detail:"No public profile" };
    if (r.status === 429) return { ...meta, status:"rate_limit", detail:"Rate limited" };
    return { ...meta, status:"error", detail:`HTTP ${r.status}` };
  } catch { return { ...meta, status:"error", detail:"Request failed" }; }
}


async function check_voxmedia(email) {
  const meta = { name: "voxmedia", domain: "", category: "cms", method: "" };
  try {
    const url = "https://auth.voxmedia.com/chorus_auth/email_valid.json";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_wordpress(email) {
  const meta = { name: "wordpress", domain: "wordpress.com", category: "cms", method: "login" };
  try {
    const r = await fetchWithTimeout(`https://public-api.wordpress.com/rest/v1.1/users/${encodeURIComponent(email)}/auth-options`, { headers:{'User-Agent':'Mozilla/5.0'} }, 8000);
    if (r.status===200) return { ...meta, status:"found", detail:"Account exists" };
    if (r.status===404) return { ...meta, status:"not_found", detail:"No account found" };
    if (r.status===429) return { ...meta, status:"rate_limit", detail:"Rate limited" };
    return { ...meta, status:"error", detail:`HTTP ${r.status}` };
  } catch { return { ...meta, status:"error", detail:"Request failed" }; }
}


async function check_aboutme(email) {
  const meta = { name: "aboutme", domain: "", category: "company", method: "" };
  try {
    const url = "https://about.me/n/signup";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_amocrm(email) {
  const meta = { name: "amocrm", domain: "", category: "crm", method: "" };
  try {
    const url = "https://www.amocrm.com/account/check_login.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_axonaut(email) {
  const meta = { name: "axonaut", domain: "", category: "crm", method: "" };
  try {
    const url = "https://axonaut.com/onboarding/?email=";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_hubspot(email) {
  const meta = { name: "hubspot", domain: "", category: "crm", method: "" };
  try {
    const url = "https://api.hubspot.com/login-api/v1/login";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_insightly(email) {
  const meta = { name: "insightly", domain: "", category: "crm", method: "" };
  try {
    const url = "https://accounts.insightly.com/signup/isemailvalid";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_nimble(email) {
  const meta = { name: "nimble", domain: "", category: "crm", method: "" };
  try {
    const url = "https://www.nimble.com/lib/register.php?email=";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_nocrm(email) {
  const meta = { name: "nocrm", domain: "", category: "crm", method: "" };
  try {
    const url = "https://register.nocrm.io/register/check_trial_duplicate?email=";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_nutshell(email) {
  const meta = { name: "nutshell", domain: "", category: "crm", method: "" };
  try {
    const url = "https://app.nutshell.com/auth";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_pipedrive(email) {
  const meta = { name: "pipedrive", domain: "", category: "crm", method: "" };
  try {
    const url = "https://app.pipedrive.com/signup-service/start";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_teamleader(email) {
  const meta = { name: "teamleader", domain: "", category: "crm", method: "" };
  try {
    const url = "https://focus.teamleader.eu/app/emails/availability";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_zoho(email) {
  const meta = { name: "zoho", domain: "", category: "crm", method: "" };
  try {
    const url = "https://accounts.zoho.com/signin/v2/lookup/";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_buymeacoffee(email) {
  const meta = { name: "buymeacoffee", domain: "", category: "crowfunding", method: "" };
  try {
    const url = "https://www.buymeacoffee.com/auth/validate_email_and_password";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_babeshows(email) {
  const meta = { name: "babeshows", domain: "", category: "forum", method: "" };
  try {
    const url = "https://www.babeshows.co.uk/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_badeggsonline(email) {
  const meta = { name: "badeggsonline", domain: "", category: "forum", method: "" };
  try {
    const url = "https://www.badeggsonline.com/beo2-forum/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_biosmods(email) {
  const meta = { name: "biosmods", domain: "", category: "forum", method: "" };
  try {
    const url = "https://bios-mods.com/forum/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_biotechnologyforums(email) {
  const meta = { name: "biotechnologyforums", domain: "", category: "forum", method: "" };
  try {
    const url = "https://biotechnologyforums.com/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_blackworldforum(email) {
  const meta = { name: "blackworldforum", domain: "", category: "forum", method: "" };
  try {
    const url = "http://blackworldforum.com/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_blitzortung(email) {
  const meta = { name: "blitzortung", domain: "", category: "forum", method: "" };
  try {
    const url = "https://forum.blitzortung.org/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_bluegrassrivals(email) {
  const meta = { name: "bluegrassrivals", domain: "", category: "forum", method: "" };
  try {
    const url = "http://bluegrassrivals.com/forum/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_cambridgemt(email) {
  const meta = { name: "cambridgemt", domain: "", category: "forum", method: "" };
  try {
    const url = "https://discussion.cambridge-mt.com/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_chinaphonearena(email) {
  const meta = { name: "chinaphonearena", domain: "", category: "forum", method: "" };
  try {
    const url = "https://www.chinaphonearena.com/forum/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_clashfarmer(email) {
  const meta = { name: "clashfarmer", domain: "", category: "forum", method: "" };
  try {
    const url = "https://www.clashfarmer.com/forum/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_codeigniter(email) {
  const meta = { name: "codeigniter", domain: "", category: "forum", method: "" };
  try {
    const url = "https://forum.codeigniter.com/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_cpaelites(email) {
  const meta = { name: "cpaelites", domain: "", category: "forum", method: "" };
  try {
    const url = "https://www.cpaelites.com/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_cpahero(email) {
  const meta = { name: "cpahero", domain: "", category: "forum", method: "" };
  try {
    const url = "https://www.cpahero.com/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_cracked_to(email) {
  const meta = { name: "cracked_to", domain: "", category: "forum", method: "" };
  try {
    const url = "https://cracked.to/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_demonforums(email) {
  const meta = { name: "demonforums", domain: "", category: "forum", method: "" };
  try {
    const url = "https://demonforums.net/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_freiberg(email) {
  const meta = { name: "freiberg", domain: "", category: "forum", method: "" };
  try {
    const url = "https://drachenhort.user.stunet.tu-freiberg.de/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_koditv(email) {
  const meta = { name: "koditv", domain: "", category: "forum", method: "" };
  try {
    const url = "https://forum.kodi.tv/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_mybb(email) {
  const meta = { name: "mybb", domain: "", category: "forum", method: "" };
  try {
    const url = "https://community.mybb.com/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_nattyornot(email) {
  const meta = { name: "nattyornot", domain: "", category: "forum", method: "" };
  try {
    const url = "https://nattyornotforum.nattyornot.com/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_ndemiccreations(email) {
  const meta = { name: "ndemiccreations", domain: "", category: "forum", method: "" };
  try {
    const url = "https://forum.ndemiccreations.com/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_nextpvr(email) {
  const meta = { name: "nextpvr", domain: "", category: "forum", method: "" };
  try {
    const url = "https://forums.nextpvr.com/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_onlinesequencer(email) {
  const meta = { name: "onlinesequencer", domain: "", category: "forum", method: "" };
  try {
    const url = "https://onlinesequencer.net/forum/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_thecardboard(email) {
  const meta = { name: "thecardboard", domain: "", category: "forum", method: "" };
  try {
    const url = "https://thecardboard.org/board/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_therianguide(email) {
  const meta = { name: "therianguide", domain: "", category: "forum", method: "" };
  try {
    const url = "https://forums.therian-guide.com/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_thevapingforum(email) {
  const meta = { name: "thevapingforum", domain: "", category: "forum", method: "" };
  try {
    const url = "http://www.thevapingforum.com/xmlhttp.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_coroflot(email) {
  const meta = { name: "coroflot", domain: "", category: "jobs", method: "" };
  try {
    const url = "https://www.coroflot.com/home/signup_email_check";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_freelancer(email) {
  const meta = { name: "freelancer", domain: "", category: "jobs", method: "" };
  try {
    const url = "https://www.freelancer.com/api/users/0.1/users/check?compact=true&new_errors=true";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_seoclerks(email) {
  const meta = { name: "seoclerks", domain: "", category: "jobs", method: "" };
  try {
    const url = "https://www.seoclerks.com/signup/check";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_diigo(email) {
  const meta = { name: "diigo", domain: "", category: "learning", method: "" };
  try {
    const url = "https://www.diigo.com/user_mana2/check_email";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_duolingo(email) {
  const meta = { name: "duolingo", domain: "", category: "learning", method: "" };
  try {
    const url = "https://www.duolingo.com/2017-06-30/users?email=";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_quora(email) {
  const meta = { name: "quora", domain: "", category: "learning", method: "" };
  try {
    const url = "https://fr.quora.com/webnode2/server_call_POST";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_google(email) {
  const meta = { name: "google", domain: "", category: "mails", method: "" };
  try {
    const url = "https://accounts.google.com/_/signup/webusernameavailability";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_laposte(email) {
  const meta = { name: "laposte", domain: "", category: "mails", method: "" };
  try {
    const url = "https://www.laposte.fr/authentification";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_mail_ru(email) {
  const meta = { name: "mail_ru", domain: "", category: "mails", method: "" };
  try {
    const url = "https://account.mail.ru/api/v1/user/password/restore";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_protonmail(email) {
  const meta = { name: "protonmail", domain: "protonmail.ch", category: "mails", method: "other" };
  try {
    const r = await fetchWithTimeout(`https://api.protonmail.ch/pks/lookup?op=index&search=${encodeURIComponent(email)}`, { headers: { "User-Agent": "Mozilla/5.0" } }, 8000);
    const txt = await r.text().catch(()=> "");
    if (txt.includes("info:1:1")) return { ...meta, status: "found", detail: "Account exists" };
    if (txt.includes("info:1:0")) return { ...meta, status: "not_found", detail: "No account found" };
    if (r.status === 429) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_yahoo(email) {
  const meta = { name: "yahoo", domain: "yahoo.com", category: "mails", method: "login" };
  try {
    const headers = { "User-Agent": "Mozilla/5.0", "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5" };
    const r1 = await fetchWithTimeout("https://login.yahoo.com/", { headers }, 8000);
    const html = await r1.text().catch(()=> "");
    const acr = html.match(/name="acrumb" value="([^"]+)"/);
    const ses = html.match(/name="sessionIndex" value="([^"]+)"/);
    if (!acr || !ses) return { ...meta, status: "inconclusive", detail: "Could not verify" };
    const body = new URLSearchParams({ acrumb: acr[1], sessionIndex: ses[1], username: email, passwd: "", signin: "Next", persistent: "y" }).toString();
    const r2 = await fetchWithTimeout("https://login.yahoo.com/?src=fpctx&intl=ca&lang=en-CA&done=https://ca.yahoo.com", {
      method: "POST", headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "X-Requested-With": "XMLHttpRequest", "Origin": "https://login.yahoo.com" }, body
    }, 8000);
    const txt = await r2.text().catch(()=> "");
    let j = null; try { j = JSON.parse(txt); } catch {}
    if (j && j.error === false) return { ...meta, status: "found", detail: "Account exists" };
    if (j && j.render && j.render.error === "messages.ERROR_INVALID_USERNAME") return { ...meta, status: "not_found", detail: "No account found" };
    if (j && j.location) return { ...meta, status: "found", detail: "Account exists" };
    if (r2.status === 429) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_ello(email) {
  const meta = { name: "ello", domain: "", category: "medias", method: "" };
  try {
    const url = "https://ello.co/api/v2/availability";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_flickr(email) {
  const meta = { name: "flickr", domain: "", category: "medias", method: "" };
  try {
    const url = "https://identity-api.flickr.com/migration";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_komoot(email) {
  const meta = { name: "komoot", domain: "", category: "medias", method: "" };
  try {
    const url = "https://account.komoot.com/v1/signin";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_rambler(email) {
  const meta = { name: "rambler", domain: "", category: "medias", method: "" };
  try {
    const url = "https://id.rambler.ru/jsonrpc";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_sporcle(email) {
  const meta = { name: "sporcle", domain: "", category: "medias", method: "" };
  try {
    const url = "https://www.sporcle.com/auth/ajax/verify.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_caringbridge(email) {
  const meta = { name: "caringbridge", domain: "", category: "medical", method: "" };
  try {
    const url = "https://www.caringbridge.org/signin";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_sevencups(email) {
  const meta = { name: "sevencups", domain: "", category: "medical", method: "" };
  try {
    const url = "https://www.7cups.com/listener/CreateAccount.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_blip(email) {
  const meta = { name: "blip", domain: "", category: "music", method: "" };
  try {
    const url = "https://blip.fm/signup/save";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_lastfm(email) {
  const meta = { name: "lastfm", domain: "", category: "music", method: "" };
  try {
    const url = "https://www.last.fm/join/partial/validate";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_smule(email) {
  const meta = { name: "smule", domain: "", category: "music", method: "" };
  try {
    const url = "https://www.smule.com/user/check_email";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_soundcloud(email) {
  const meta = { name: "soundcloud", domain: "", category: "music", method: "" };
  try {
    const url = "https://soundcloud.com/octobersveryown";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_spotify(email) {
  const meta = { name: "spotify", domain: "spotify.com", category: "music", method: "register" };
  try {
    const r = await fetchWithTimeout(`https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email=${encodeURIComponent(email)}`, { headers:{'User-Agent':'Mozilla/5.0'} }, 8000);
    if (r.status===200){ const d=await r.json().catch(()=>({})); if(d?.status===20) return {...meta,status:"found",detail:"Account exists"}; if(d?.status===1) return {...meta,status:"not_found",detail:"No account found"}; }
    if (r.status===429) return {...meta,status:"rate_limit",detail:"Rate limited"};
    return {...meta,status:"error",detail:`HTTP ${r.status}`};
  } catch { return {...meta,status:"error",detail:"Request failed"}; }
}


async function check_tunefind(email) {
  const meta = { name: "tunefind", domain: "", category: "music", method: "" };
  try {
    const url = "https://www.tunefind.com/user/join";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_rocketreach(email) {
  const meta = { name: "rocketreach", domain: "", category: "osint", method: "" };
  try {
    const url = "https://rocketreach.co/signup";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_venmo(email) {
  const meta = { name: "venmo", domain: "", category: "payment", method: "" };
  try {
    const url = "https://venmo.com/api/v5/users";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_anydo(email) {
  const meta = { name: "anydo", domain: "", category: "productivity", method: "" };
  try {
    const url = "https://sm-prod2.any.do/check_email";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_evernote(email) {
  const meta = { name: "evernote", domain: "evernote.com", category: "productivity", method: "login" };
  try {
    const r = await fetchWithTimeout(`https://www.evernote.com/Login.action?username=${encodeURIComponent(email)}&evaluateUsername=&checkUsername=true`, { headers: { "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/javascript, */*; q=0.01", "X-Requested-With": "XMLHttpRequest" } }, 8000);
    const txt = await r.text().catch(()=> "");
    const low = txt.toLowerCase();
    if (low.includes("usepasswordauth") || low.includes('"valid":true')) return { ...meta, status: "found", detail: "Account exists" };
    if (low.includes("incorrectemail") || low.includes("displaymessage")) return { ...meta, status: "not_found", detail: "No account found" };
    if (r.status === 429) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_eventbrite(email) {
  const meta = { name: "eventbrite", domain: "", category: "products", method: "" };
  try {
    const url = "https://www.eventbrite.com/api/v3/users/lookup/";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_nike(email) {
  const meta = { name: "nike", domain: "", category: "products", method: "" };
  try {
    const url = "https://unite.nike.com/account/email/v1";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_samsung(email) {
  const meta = { name: "samsung", domain: "", category: "products", method: "" };
  try {
    const url = "https://account.samsung.com/accounts/v1/Samsung_com_FR/signUpCheckEmailIDProc";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_codecademy(email) {
  const meta = { name: "codecademy", domain: "", category: "programing", method: "" };
  try {
    const url = "https://www.codecademy.com/register/validate";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_codepen(email) {
  const meta = { name: "codepen", domain: "", category: "programing", method: "" };
  try {
    const url = "https://codepen.io/accounts/duplicate_check";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_devrant(email) {
  const meta = { name: "devrant", domain: "", category: "programing", method: "" };
  try {
    const url = "https://devrant.com/api/users";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_github(email) {
  const meta = { name: "github", domain: "github.com", category: "software", method: "register" };
  try {
    const r = await fetchWithTimeout(`https://github.com/signup_check/email?value=${encodeURIComponent(email)}`, { headers:{'User-Agent':'Mozilla/5.0','Accept':'*/*','X-Requested-With':'XMLHttpRequest'} }, 8000);
    const txt = await r.text().catch(()=>'');
    const low = txt.toLowerCase();
    if (low.includes('already taken') || low.includes('already_exists')) return { ...meta, status:"found", detail:"Account exists" };
    if (r.status===200 && low.includes('available')) return { ...meta, status:"not_found", detail:"No account found" };
    if (r.status===422) return { ...meta, status:"found", detail:"Account exists" };
    if (r.status===429) return { ...meta, status:"rate_limit", detail:"Rate limited" };
    return { ...meta, status:"error", detail:"Inconclusive response" };
  } catch { return { ...meta, status:"error", detail:"Request failed" }; }
}


async function check_replit(email) {
  const meta = { name: "replit", domain: "", category: "programing", method: "" };
  try {
    const url = "https://replit.com/data/user/exists";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_teamtreehouse(email) {
  const meta = { name: "teamtreehouse", domain: "", category: "programing", method: "" };
  try {
    const url = "https://teamtreehouse.com/account/email_address";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_vrbo(email) {
  const meta = { name: "vrbo", domain: "", category: "real_estate", method: "" };
  try {
    const url = "https://www.vrbo.com/auth/aam/v3/status";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_amazon(email) {
  const meta = { name: "amazon", domain: "amazon.com", category: "shopping", method: "login" };
  try {
    const headers = { "User-Agent": "Mozilla/5.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" };
    const r1 = await fetchWithTimeout("https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com%2F&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=usflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0", { headers }, 8000);
    const html = await r1.text().catch(()=> "");
    const inputs = {};
    let m; const re = /<input[^>]+name=["']([^"']+)["'][^>]+value=["']([^"']*)["'][^>]*>/gi;
    while ((m = re.exec(html))) inputs[m[1]] = m[2];
    const re2 = /<input[^>]+value=["']([^"']*)["'][^>]+name=["']([^"']+)["'][^>]*>/gi;
    while ((m = re2.exec(html))) inputs[m[2]] = m[1];
    inputs.email = email;
    const body = new URLSearchParams(inputs).toString();
    const r2 = await fetchWithTimeout("https://www.amazon.com/ap/signin", { method: "POST", headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" }, body }, 8000);
    const t2 = await r2.text().catch(()=> "");
    if (t2.includes("auth-password-missing-alert")) return { ...meta, status: "found", detail: "Account exists" };
    if (t2.includes("We cannot find an account") || t2.includes("auth-error-message-box")) return { ...meta, status: "not_found", detail: "No account found" };
    if (r2.status === 429) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_armurerieauxerre(email) {
  const meta = { name: "armurerieauxerre", domain: "", category: "shopping", method: "" };
  try {
    const url = "https://www.armurerie-auxerre.com/customer/Email/email/";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_deliveroo(email) {
  const meta = { name: "deliveroo", domain: "", category: "shopping", method: "" };
  try {
    const url = "https://consumer-ow-api.deliveroo.com/orderapp/v1/check-email";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_dominosfr(email) {
  const meta = { name: "dominosfr", domain: "", category: "shopping", method: "" };
  try {
    const url = "https://commande.dominos.fr/eStore/fr/Signup";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_ebay(email) {
  const meta = { name: "ebay", domain: "", category: "shopping", method: "" };
  try {
    const url = "https://signin.ebay.com/signin/srv/identifer";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_envato(email) {
  const meta = { name: "envato", domain: "", category: "shopping", method: "" };
  try {
    const url = "https://account.envato.com/api/validate_email";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_garmin(email) {
  const meta = { name: "garmin", domain: "", category: "shopping", method: "" };
  try {
    const url = "https://sso.garmin.com/sso/validateNewAccount";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_naturabuy(email) {
  const meta = { name: "naturabuy", domain: "", category: "shopping", method: "" };
  try {
    const url = "https://www.naturabuy.fr/includes/ajax/register.php";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_vivino(email) {
  const meta = { name: "vivino", domain: "", category: "shopping", method: "" };
  try {
    const url = "https://www.vivino.com/api/login";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_bitmoji(email) {
  const meta = { name: "bitmoji", domain: "", category: "social_media", method: "" };
  try {
    const url = "https://accounts.snapchat.com";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_crevado(email) {
  const meta = { name: "crevado", domain: "", category: "social_media", method: "" };
  try {
    const url = "https://crevado.com/";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_discord(email) {
  const meta = { name: "discord", domain: "discord.com", category: "social_media", method: "register" };
  try {
    const r = await fetchWithTimeout('https://discord.com/api/v9/auth/register', {
      method:'POST', headers:{'Content-Type':'application/json','User-Agent':'Mozilla/5.0'},
      body: JSON.stringify({email, username:'mono'+Math.random().toString(36).slice(2,10), password:'A'+Math.random().toString(36).slice(2)+'!1', consent:true, fingerprint:null, invite:null, date_of_birth:'1990-01-01', gift_code_sku_id:null, captcha_key:null})
    }, 8000);
    const txt = await r.text().catch(()=>'');
    const low = txt.toLowerCase();
    if (low.includes('email_already_registered') || low.includes('already registered')) return { ...meta, status:"found", detail:"Account exists" };
    if (r.status === 429 || low.includes('rate limit') || low.includes('captcha-required')) return { ...meta, status:"rate_limit", detail:"Rate limited / captcha" };
    if (r.status === 400 && low.includes('email')) return { ...meta, status:"not_found", detail:"No account found" };
    return { ...meta, status:"not_found", detail:"No account found" };
  } catch { return { ...meta, status:"error", detail:"Request failed" }; }
}


async function check_facebook(email) {
  const meta = { name: "facebook", domain: "", category: "social_media", method: "" };
  try {
    const url = "https://www.facebook.com/api/v1/web/accounts/web_create_ajax/attempt/";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_fanpop(email) {
  const meta = { name: "fanpop", domain: "", category: "social_media", method: "" };
  try {
    const url = "https://www.fanpop.com/login/superlogin";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_imgur(email) {
  const meta = { name: "imgur", domain: "", category: "social_media", method: "" };
  try {
    const url = "https://imgur.com/signin/ajax_email_available";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_instagram(email) {
  const meta = { name: "instagram", domain: "instagram.com", category: "social_media", method: "register" };
  try {
    const csrf = 'missing';
    const r = await fetchWithTimeout('https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/', {
      method:'POST',
      headers:{'User-Agent':'Mozilla/5.0','Content-Type':'application/x-www-form-urlencoded','X-CSRFToken':csrf,'X-IG-App-ID':'936619743392459','X-Requested-With':'XMLHttpRequest','Referer':'https://www.instagram.com/accounts/emailsignup/'},
      body:`email=${encodeURIComponent(email)}&username=&first_name=&opt_into_one_tap=false`
    }, 8000);
    const txt = await r.text().catch(()=>'');
    const low = txt.toLowerCase();
    if (low.includes('email_is_taken') || low.includes('another account is using')) return { ...meta, status:"found", detail:"Account exists" };
    if (low.includes('email') && low.includes('available')) return { ...meta, status:"not_found", detail:"No account found" };
    if (r.status===429) return { ...meta, status:"rate_limit", detail:"Rate limited" };
    return { ...meta, status:"error", detail:"Inconclusive response" };
  } catch { return { ...meta, status:"error", detail:"Request failed" }; }
}


async function check_myspace(email) {
  const meta = { name: "myspace", domain: "myspace.com", category: "social_media", method: "register" };
  try {
    const r1 = await fetchWithTimeout("https://myspace.com/signup/email", { headers: { "User-Agent": "Mozilla/5.0" } }, 8000);
    const html = await r1.text().catch(()=> "");
    const csrfM = html.match(/<input name="csrf" type="hidden" value="([^"]+)"/);
    if (!csrfM) return { ...meta, status: "inconclusive", detail: "Could not verify" };
    const r2 = await fetchWithTimeout("https://myspace.com/ajax/account/validateemail", {
      method: "POST",
      headers: { "User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "Hash": csrfM[1], "X-Requested-With": "XMLHttpRequest" },
      body: new URLSearchParams({ email }).toString()
    }, 8000);
    const txt = await r2.text().catch(()=> "");
    if (txt.includes("This email address was already used to create an account.")) return { ...meta, status: "found", detail: "Account exists" };
    if (r2.status === 200) return { ...meta, status: "not_found", detail: "No account found" };
    if (r2.status === 429) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_odnoklassniki(email) {
  const meta = { name: "odnoklassniki", domain: "", category: "social_media", method: "" };
  try {
    const url = "https://github.com/shllwrld/ok_checker/";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_parler(email) {
  const meta = { name: "parler", domain: "", category: "social_media", method: "" };
  try {
    const url = "https://api.parler.com/v2/login/new";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_patreon(email) {
  const meta = { name: "patreon", domain: "", category: "social_media", method: "" };
  try {
    const url = "https://www.patreon.com/api/email/available";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_pinterest(email) {
  const meta = { name: "pinterest", domain: "pinterest.com", category: "social_media", method: "register" };
  try {
    const params = new URLSearchParams({ source_url: "/", data: JSON.stringify({ options: { email }, context: "signup" }) });
    const r = await fetchWithTimeout(`https://www.pinterest.com/resource/EmailExistsResource/get/?${params.toString()}`, { headers:{'User-Agent':'Mozilla/5.0','Accept':'application/json'} }, 8000);
    const txt = await r.text().catch(()=>'');
    if (txt.includes('"email_exists": true') || txt.includes('"message":"Email has already been taken"')) return { ...meta, status:"found", detail:"Account exists" };
    if (txt.includes('"email_exists": false')) return { ...meta, status:"not_found", detail:"No account found" };
    if (r.status===429) return { ...meta, status:"rate_limit", detail:"Rate limited" };
    return { ...meta, status:"error", detail:"Inconclusive response" };
  } catch { return { ...meta, status:"error", detail:"Request failed" }; }
}


async function check_plurk(email) {
  const meta = { name: "plurk", domain: "", category: "social_media", method: "" };
  try {
    const url = "https://www.plurk.com/Users/isEmailFound";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_snapchat(email) {
  const meta = { name: "snapchat", domain: "snapchat.com", category: "social_media", method: "login" };
  try {
    const r = await fetchWithTimeout('https://bitmoji.api.snapchat.com/api/user/find', {
      method:'POST', headers:{'Content-Type':'application/json','User-Agent':'Mozilla/5.0'},
      body: JSON.stringify({email})
    }, 8000);
    const txt = await r.text().catch(()=>'');
    if (r.status===200 && txt.toLowerCase().includes('account_type')) return { ...meta, status:"found", detail:"Account exists" };
    if (r.status===404) return { ...meta, status:"not_found", detail:"No account found" };
    if (r.status===429) return { ...meta, status:"rate_limit", detail:"Rate limited" };
    return { ...meta, status:"error", detail:"Inconclusive response" };
  } catch { return { ...meta, status:"error", detail:"Request failed" }; }
}


async function check_strava(email) {
  const meta = { name: "strava", domain: "", category: "social_media", method: "" };
  try {
    const url = "https://www.strava.com/register/free?cta=sign-up&element=button&source=website_show";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_taringa(email) {
  const meta = { name: "taringa", domain: "", category: "social_media", method: "" };
  try {
    const url = "https://www.taringa.net/api/auth/availability/email";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_tellonym(email) {
  const meta = { name: "tellonym", domain: "", category: "social_media", method: "" };
  try {
    const url = "https://api.tellonym.me/accounts/check";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_tumblr(email) {
  const meta = { name: "tumblr", domain: "tumblr.com", category: "social_media", method: "register" };
  try {
    const r = await fetchWithTimeout('https://www.tumblr.com/api/v2/register/account/validate', {
      method:'POST', headers:{'Content-Type':'application/json','User-Agent':'Mozilla/5.0'},
      body: JSON.stringify({email})
    }, 8000);
    const txt = await r.text().catch(()=>'');
    const low = txt.toLowerCase();
    if (low.includes('already in use') || low.includes('email is already')) return { ...meta, status:"found", detail:"Account exists" };
    if (low.includes('"user_errors":[]') || (r.status===200 && !low.includes('error'))) return { ...meta, status:"not_found", detail:"No account found" };
    if (r.status===429) return { ...meta, status:"rate_limit", detail:"Rate limited" };
    return { ...meta, status:"error", detail:"Inconclusive response" };
  } catch { return { ...meta, status:"error", detail:"Request failed" }; }
}


async function check_twitter(email) {
  const meta = { name: "twitter", domain: "twitter.com", category: "social_media", method: "register" };
  try {
    const r = await fetchWithTimeout(`https://api.twitter.com/i/users/email_available.json?email=${encodeURIComponent(email)}`, { headers:{'User-Agent':'Mozilla/5.0'} }, 8000);
    const txt = await r.text().catch(()=>'');
    const low = txt.toLowerCase();
    if (low.includes('"taken":true') || low.includes('"valid":false')) return { ...meta, status:"found", detail:"Account exists" };
    if (low.includes('"taken":false')) return { ...meta, status:"not_found", detail:"No account found" };
    if (r.status===429) return { ...meta, status:"rate_limit", detail:"Rate limited" };
    return { ...meta, status:"error", detail:"Inconclusive response" };
  } catch { return { ...meta, status:"error", detail:"Request failed" }; }
}


async function check_vsco(email) {
  const meta = { name: "vsco", domain: "", category: "social_media", method: "" };
  try {
    const url = "https://api.vsco.co/2.0/users/email?email={email}";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_wattpad(email) {
  const meta = { name: "wattpad", domain: "", category: "social_media", method: "" };
  try {
    const url = "https://www.wattpad.com";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_xing(email) {
  const meta = { name: "xing", domain: "", category: "social_media", method: "" };
  try {
    const url = "https://www.xing.com/welcome/api/signup/validate";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_adobe(email) {
  const meta = { name: "adobe", domain: "adobe.com", category: "software", method: "password recovery" };
  try {
    const headers = {'User-Agent':'Mozilla/5.0','Accept':'application/json, text/plain, */*','Accept-Language':'en-US,en;q=0.5','X-IMS-CLIENTID':'adobedotcom2','Content-Type':'application/json;charset=utf-8'};
    const r = await fetchWithTimeout('https://auth.services.adobe.com/signin/v2/users/accounts', {method:'POST', headers, body: JSON.stringify({username:email})}, 8000);
    if (r.status === 200) {
      const data = await r.json().catch(()=>[]);
      if (Array.isArray(data) && data.length>0) return { ...meta, status:"found", detail:"Account exists" };
      return { ...meta, status:"not_found", detail:"No account found" };
    }
    if (r.status === 404) return { ...meta, status:"not_found", detail:"No account found" };
    if (r.status === 429) return { ...meta, status:"rate_limit", detail:"Rate limited" };
    // fallback old endpoint
    const r2 = await fetchWithTimeout('https://auth.services.adobe.com/signin/v1/authenticationstate', {method:'POST', headers, body: JSON.stringify({username:email, accountType:'individual'})}, 8000);
    const j = await r2.json().catch(()=>({}));
    if (j && !('errorCode' in j)) return { ...meta, status:"found", detail:"Account exists" };
    if (j && j.errorCode) return { ...meta, status:"not_found", detail:"No account found" };
    return { ...meta, status:"error", detail:`HTTP ${r.status}` };
  } catch { return { ...meta, status:"error", detail:"Request failed" }; }
}


async function check_archive(email) {
  const meta = { name: "archive", domain: "archive.org", category: "osint", method: "register" };
  try {
    const r = await fetchWithTimeout("https://archive.org/account/signup", { method:"POST", headers:{"Content-Type":"application/x-www-form-urlencoded","User-Agent":"Mozilla/5.0"}, body:`input=${encodeURIComponent(email)}&checkval=true` }, 8000);
    if (r.status===200){ const d=await r.json().catch(()=>({})); if(d?.success===false) return {...meta,status:"found",detail:"Account exists"}; return {...meta,status:"not_found",detail:"No account found"}; }
    if (r.status===429) return {...meta,status:"rate_limit",detail:"Rate limited"};
    return {...meta,status:"error",detail:`HTTP ${r.status}`};
  } catch { return {...meta,status:"error",detail:"Request failed"}; }
}


async function check_docker(email) {
  const meta = { name: "docker", domain: "", category: "software", method: "" };
  try {
    const url = "https://hub.docker.com/v2/users/signup/";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_firefox(email) {
  const meta = { name: "firefox", domain: "firefox.com", category: "software", method: "register" };
  try {
    const r = await fetchWithTimeout(`https://api.accounts.firefox.com/v1/account/status?email=${encodeURIComponent(email)}`, { headers:{'User-Agent':'Mozilla/5.0'} }, 8000);
    if (r.status===200) { const d=await r.json().catch(()=>({})); return { ...meta, status: d.exists ? "found":"not_found", detail: d.exists?"Account exists":"No account found" }; }
    if (r.status===429) return { ...meta, status:"rate_limit", detail:"Rate limited" };
    return { ...meta, status:"error", detail:`HTTP ${r.status}` };
  } catch { return { ...meta, status:"error", detail:"Request failed" }; }
}


async function check_issuu(email) {
  const meta = { name: "issuu", domain: "", category: "software", method: "" };
  try {
    const url = "https://issuu.com/call/signup/check-email/";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_lastpass(email) {
  const meta = { name: "lastpass", domain: "lastpass.com", category: "software", method: "register" };
  try {
    const r = await fetchWithTimeout(`https://lastpass.com/create_account.php?check=avail&skipcontent=1&mistype=1&username=${encodeURIComponent(email)}`, { headers: { "User-Agent": "Mozilla/5.0", "Accept": "*/*", "X-Requested-With": "XMLHttpRequest" } }, 8000);
    const txt = (await r.text().catch(()=> "")).trim().toLowerCase();
    if (txt === "no") return { ...meta, status: "found", detail: "Account exists" };
    if (txt === "ok" || txt === "emailinvalid") return { ...meta, status: "not_found", detail: "No account found" };
    if (r.status === 429) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_office365(email) {
  const meta = { name: "office365", domain: "", category: "software", method: "" };
  try {
    const url = "https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/{}?Protocol=Autodiscoverv1";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_bodybuilding(email) {
  const meta = { name: "bodybuilding", domain: "", category: "sport", method: "" };
  try {
    const url = "https://www.bodybuilding.com";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


async function check_blablacar(email) {
  const meta = { name: "blablacar", domain: "", category: "transport", method: "" };
  try {
    const url = "https://www.blablacar.fr/register";
    if (!url) return { ...meta, status: "inconclusive", detail: "Not implemented" };
    const r = await fetchWithTimeout(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0", "Accept": "application/json, text/plain, */*" },
      body: JSON.stringify({ email, username: email }),
    }, 8000);
    const txt = await r.text().catch(()=>"");
    const low = txt.toLowerCase();
    if (r.status === 429 || low.includes("rate limit") || low.includes("too many requests")) return { ...meta, status: "rate_limit", detail: "Rate limited" };
    if (r.status === 404) return { ...meta, status: "not_found", detail: "No account found" };
    // common positive signals
    const existsSignals = ["already exists","already registered","email_taken","email already","already in use","account exists","user exists","already used","email is taken","registered"];
    const notSignals = ["available","not found","no account","doesn't exist","does not exist","not registered","no user","free"];
    const hasExists = existsSignals.some(s=>low.includes(s));
    const hasNot = notSignals.some(s=>low.includes(s));
    if (hasExists && !hasNot) return { ...meta, status: "found", detail: "Account exists" };
    if (hasNot && !hasExists) return { ...meta, status: "not_found", detail: "No account found" };
    // try to interpret json
    try {
      const j = JSON.parse(txt);
      if (j && typeof j === 'object') {
        const js = JSON.stringify(j).toLowerCase();
        if (existsSignals.some(s=>js.includes(s))) return { ...meta, status: "found", detail: "Account exists" };
        if (notSignals.some(s=>js.includes(s))) return { ...meta, status: "not_found", detail: "No account found" };
        if (j.exists === true || j.taken === true || j.email_exists === true) return { ...meta, status: "found", detail: "Account exists" };
        if (j.exists === false || j.taken === false || j.email_exists === false) return { ...meta, status: "not_found", detail: "No account found" };
      }
    } catch(_){
    }
    return { ...meta, status: "inconclusive", detail: "Could not verify" };
  } catch (e) { return { ...meta, status: "error", detail: "Request failed" }; }
}


const MODULES = [
check_atlassian,
check_gravatar,
check_voxmedia,
check_wordpress,
check_aboutme,
check_amocrm,
check_axonaut,
check_hubspot,
check_insightly,
check_nimble,
check_nocrm,
check_nutshell,
check_pipedrive,
check_teamleader,
check_zoho,
check_buymeacoffee,
check_babeshows,
check_badeggsonline,
check_biosmods,
check_biotechnologyforums,
check_blackworldforum,
check_blitzortung,
check_bluegrassrivals,
check_cambridgemt,
check_chinaphonearena,
check_clashfarmer,
check_codeigniter,
check_cpaelites,
check_cpahero,
check_cracked_to,
check_demonforums,
check_freiberg,
check_koditv,
check_mybb,
check_nattyornot,
check_ndemiccreations,
check_nextpvr,
check_onlinesequencer,
check_thecardboard,
check_therianguide,
check_thevapingforum,
check_coroflot,
check_freelancer,
check_seoclerks,
check_diigo,
check_duolingo,
check_quora,
check_google,
check_laposte,
check_mail_ru,
check_protonmail,
check_yahoo,
check_ello,
check_flickr,
check_komoot,
check_rambler,
check_sporcle,
check_caringbridge,
check_sevencups,
check_blip,
check_lastfm,
check_smule,
check_soundcloud,
check_spotify,
check_tunefind,
check_rocketreach,
check_venmo,
check_anydo,
check_evernote,
check_eventbrite,
check_nike,
check_samsung,
check_codecademy,
check_codepen,
check_devrant,
check_github,
check_replit,
check_teamtreehouse,
check_vrbo,
check_amazon,
check_armurerieauxerre,
check_deliveroo,
check_dominosfr,
check_ebay,
check_envato,
check_garmin,
check_naturabuy,
check_vivino,
check_bitmoji,
check_crevado,
check_discord,
check_facebook,
check_fanpop,
check_imgur,
check_instagram,
check_myspace,
check_odnoklassniki,
check_parler,
check_patreon,
check_pinterest,
check_plurk,
check_snapchat,
check_strava,
check_taringa,
check_tellonym,
check_tumblr,
check_twitter,
check_vsco,
check_wattpad,
check_xing,
check_adobe,
check_archive,
check_docker,
check_firefox,
check_issuu,
check_lastpass,
check_office365,
check_bodybuilding,
check_blablacar
];


async function runModules(email) {
  const concurrency = 25;
  const results = [];
  let i = 0;
  async function worker() {
    while (i < MODULES.length) {
      const idx = i++;
      const fn = MODULES[idx];
      try {
        const r = await fn(email);
        if (r && r.status) results.push(r);
      } catch (e) {
        results.push({ name: fn.name.replace(/^check_/,''), domain: '', category: 'unknown', method: '', status: 'error', detail: 'Check failed' });
      }
    }
  }
  await Promise.all(Array.from({length: Math.min(concurrency, MODULES.length)}, worker));
  // stable sort by name
  results.sort((a,b)=>String(a.name).localeCompare(String(b.name)));
  return results;
}

async function handler(req, res) {
  Object.entries(getCorsHeaders(req)).forEach(([k, v]) => res.setHeader(k, v));
  res.setHeader("Cache-Control", "no-store");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return json(res, 405, { error: "Method not allowed" });

  const cookies = parseCookies(req);
  const rawToken = cookies["mono_session"] || String(req.headers["x-session-token"] || "").trim();
  const session = verifySessionToken(rawToken);
  if (!session.ok) return json(res, 401, { error: session.error || "Login required" });
  if (await isTokenBlacklisted(rawToken)) return json(res, 401, { error: "Session revoked — please log in again" });

  let userBlocked = false;
  for (let i = 1; i <= 50; i++) { const id = String(process.env[`BLACKLISTED_USER${i}`] || "").trim(); if (id === session.userId) { userBlocked = true; break; } }
  if (!userBlocked) { try { const bl = await kv.get(`mono:kv_blacklist:${session.userId}`); if (bl) userBlocked = true; } catch (_) {} }
  if (userBlocked) return json(res, 403, { error: "Your account is not allowed to use this service." });

  let body;
  try {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString();
    if (raw.length > 4096) return json(res, 413, { error: "Request body too large" });
    body = JSON.parse(raw || "{}");
  } catch (_) { return json(res, 400, { error: "Invalid JSON" }); }

  const email = sanitizeEmail(body.email);
  if (!email) return json(res, 400, { error: "Invalid email address" });

  const limited = await kvRateLimit(`rl:emailcheck:${session.userId}`, 6, 60);
  if (limited) return json(res, 429, { error: "Rate limit reached. Wait a moment." });

  const started = Date.now();
  const results = await runModules(email);
  const found = results.filter(r => r.status === "found").length;

  return json(res, 200, {
    email,
    checked: results.length,
    found,
    durationMs: Date.now() - started,
    results,
  });
};

module.exports = handler;
module.exports.config = { maxDuration: 60 };
