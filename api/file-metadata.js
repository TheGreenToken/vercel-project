"use strict";

// File Metadata Extractor (key-free). Accepts an uploaded file and extracts
// structural metadata: type sniffing (magic bytes), SHA-256 hash, image EXIF
// (GPS, camera, software, dates, author), and PDF document metadata
// (author, title, producer, page count). Session-gated, rate-limited,
// defensive OSINT — we only read metadata, never execute or render content.

const crypto = require("crypto");
const exifr = require("exifr");
const { kvRateLimit, getCorsHeaders } = require("../lib/middleware");
const { verifySessionToken, isTokenBlacklisted } = require("../lib/session");
const { appendLookup, makeEntry } = require("../lib/lookuplog");

const MAX_UPLOAD = 25 * 1024 * 1024; // 25 MB

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

// Multipart/form-data field parser (single file field). Uses latin1 strings
// so every byte maps 1:1 to a char (binary-safe). Returns { filename, mime, buffer } or null.
function parseMultipart(buf, boundary) {
  const str = buf.toString("latin1");
  const delim = "--" + boundary;
  let idx = str.indexOf(delim);
  if (idx === -1) return null;
  idx += delim.length;
  while (idx < str.length) {
    const next = str.indexOf(delim, idx);
    if (next === -1) break;
    const chunk = str.slice(idx, next);
    idx = next + delim.length;
    // chunk looks like: \r\n<headers>\r\n\r\n<body>\r\n
    let headerEnd = chunk.indexOf("\r\n\r\n");
    if (headerEnd === -1) continue;
    const header = chunk.slice(0, headerEnd);
    // body: drop leading CRLF and trailing CRLF
    let body = chunk.slice(headerEnd + 4);
    if (body.charCodeAt(0) === 0x0d && body.charCodeAt(1) === 0x0a) body = body.slice(2);
    if (body.charCodeAt(body.length - 2) === 0x0d && body.charCodeAt(body.length - 1) === 0x0a) body = body.slice(0, -2);

    const cd = /Content-Disposition: form-data;[^\r\n]*/i.exec(header);
    if (!cd) continue;
    const nameMatch = /name="([^"]+)"/i.exec(cd[0]);
    const fileMatch = /filename="([^"]*)"/i.exec(cd[0]);
    if (!fileMatch) continue; // skip non-file fields
    if (nameMatch && nameMatch[1] !== "file") continue;
    const mimeMatch = /Content-Type: ([^\r\n;]+)/i.exec(header);
    return {
      filename: fileMatch[1] || "upload",
      mime: mimeMatch ? mimeMatch[1].trim() : "application/octet-stream",
      buffer: Buffer.from(body, "latin1"),
    };
  }
  return null;
}

// Sniff file type from magic bytes — more reliable than the client mimetype.
function sniffType(buf) {
  if (!buf || buf.length < 4) return { kind: "unknown", ext: "" };
  if (buf[0] === 0xff && buf[1] === 0xd8) return { kind: "image", ext: "jpg" };
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return { kind: "image", ext: "png" };
  if (buf.slice(0, 3).toString("ascii") === "GIF") return { kind: "image", ext: "gif" };
  if (buf[0] === 0x42 && buf[1] === 0x4d) return { kind: "image", ext: "bmp" };
  if (buf.slice(0, 2).toString("ascii") === "RI" && buf.slice(8, 12).toString("ascii") === "WEBP") return { kind: "image", ext: "webp" };
  if (buf.slice(0, 4).toString("ascii") === "%PDF") return { kind: "pdf", ext: "pdf" };
  if (buf.slice(0, 4).toString("ascii") === "%!PS") return { kind: "image", ext: "ps" };
  if (buf.slice(0, 6).toString("ascii").includes("<?xml") || buf.slice(0, 5).toString("ascii") === "<?xml") return { kind: "xml", ext: "xml" };
  return { kind: "unknown", ext: "" };
}

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function humanSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(2) + " MB";
}

// Parse image EXIF. exifr is key-free and returns a flat object.
async function parseImageExif(buf) {
  try {
    const data = await exifr.parse(buf, {
      tiff: true,
      exif: true,
      gps: true,
      xmp: true,
      iptc: true,
      jfif: true,
      ifd0: true,
    });
    if (!data) return { ok: true, data: null };
    const lat = data.latitude != null ? data.latitude : null;
    const lon = data.longitude != null ? data.longitude : null;
    const out = {
      cameraMake: data.Make || data.maker || null,
      cameraModel: data.Model || data.model || null,
      lens: data.LensModel || null,
      software: data.Software || null,
      artist: data.Artist || data.ByLine || null,
      copyright: data.Copyright || null,
      description: data.ImageDescription || data.Description || null,
      dateTime: data.DateTimeOriginal || data.CreateDate || data.DateTime || null,
      dateTimeDigitized: data.DateTimeDigitized || null,
      orientation: data.Orientation || null,
      iso: data.ISO != null ? data.ISO : null,
      exposure: data.ExposureTime != null ? String(data.ExposureTime) : null,
      aperture: data.FNumber != null ? String(data.FNumber) : null,
      focalLength: data.FocalLength != null ? String(data.FocalLength) : null,
      flash: data.Flash != null ? String(data.Flash) : null,
      dimensions: data.body ? null : null,
      latitude: lat,
      longitude: lon,
      gpsAltitude: data.GPSAltitude != null ? String(data.GPSAltitude) : null,
      gpsMap: lat != null && lon != null,
      raw: Object.keys(data).length,
    };
    if (data.body && typeof data.body.width === "number") {
      out.dimensions = data.body.width + "×" + data.body.height;
    } else if (data.PixelXDimension || data.PixelYDimension) {
      out.dimensions = (data.PixelXDimension || "?") + "×" + (data.PixelYDimension || "?");
    }
    return { ok: true, data: out };
  } catch (e) {
    return { ok: false, detail: (e && e.message) || "EXIF parse failed" };
  }
}

// ---- PDF metadata parser (dependency-free, reads raw bytes) ----
// PDFs store document info in the trailer's /Info dictionary. We locate the
// trailer, resolve the /Info dict (inline or indirect object), and parse the
// standard string keys. Falls back to a document-wide scan if structure is odd.

// Unescape a PDF literal string ( ... ) — handles \( \) \\ \n \ddd octal.
function unescapePdfString(s) {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\\" && i + 1 < s.length) {
      const n = s[i + 1];
      if (n === "n") { out += "\n"; i++; }
      else if (n === "r") { out += "\r"; i++; }
      else if (n === "t") { out += "\t"; i++; }
      else if (n === "b") { out += "\b"; i++; }
      else if (n === "f") { out += "\f"; i++; }
      else if (n === "(") { out += "("; i++; }
      else if (n === ")") { out += ")"; i++; }
      else if (n === "\\") { out += "\\"; i++; }
      else if (/[0-7]/.test(n)) {
        // octal, up to 3 digits
        let oct = n;
        i++;
        for (let k = 0; k < 2 && i + 1 < s.length && /[0-7]/.test(s[i + 1]); k++) { i++; oct += s[i]; }
        out += String.fromCharCode(parseInt(oct, 8) & 0xff);
      } else {
        out += n; i++;
      }
    } else {
      out += c;
    }
  }
  return out;
}

// Read a balanced << ... >> dictionary starting at index of '<<'.
// Returns the inner content (between the outer << >>) or null.
function readDict(str, start) {
  let i = start;
  let depth = 0;
  let inStr = false, inHex = false;
  while (i < str.length) {
    const c = str[i];
    if (inStr) {
      if (c === "\\") { i += 2; continue; }
      if (c === ")") inStr = false;
      i++; continue;
    }
    if (inHex) {
      if (c === ">") inHex = false;
      i++; continue;
    }
    if (c === "(") { inStr = true; i++; continue; }
    if (c === "<" && str[i + 1] === "<") { depth++; i += 2; continue; }
    if (c === ">" && str[i + 1] === ">") { depth--; i += 2; if (depth === 0) return str.slice(start + 2, i - 2); continue; }
    i++;
  }
  return null;
}

// Parse /Key (value) pairs from a dict body.
function parseInfoKeys(dictBody, out) {
  if (!dictBody) return;
  const keys = [
    ["Title", "title"], ["Author", "author"], ["Subject", "subject"],
    ["Keywords", "keywords"], ["Creator", "creator"], ["Producer", "producer"],
    ["CreationDate", "creationDate"], ["ModDate", "modDate"],
  ];
  for (const [key, field] of keys) {
    const re = new RegExp("/" + key + "\\s*\\(([\\s\\S]*?)\\)", "i");
    const m = re.exec(dictBody);
    if (m && !out[field]) out[field] = unescapePdfString(m[1]);
  }
}

// Find the /Info dictionary. Tries trailer first, then a document-wide scan.
function findInfoDict(str) {
  // 1) trailer: find last 'trailer' keyword, read its dict, resolve /Info
  const tIdx = str.lastIndexOf("trailer");
  if (tIdx !== -1) {
    const braceIdx = str.indexOf("<<", tIdx);
    if (braceIdx !== -1) {
      const trailerDict = readDict(str, braceIdx);
      if (trailerDict) {
        const infoRef = /Info\s+(\d+)\s+0\s+R/.exec(trailerDict);
        if (infoRef) {
          // resolve indirect object N 0 obj << ... >> endobj
          const objRe = new RegExp(infoRef[1] + "\\s+0\\s+obj\\b[\\s\\S]*?<<");
          const om = objRe.exec(str);
          if (om) {
            const oIdx = om.index + om[0].length - 2;
            const body = readDict(str, oIdx);
            if (body) return body;
          }
        }
        const inlineInfo = /Info\s*<<([\s\S]*?)>>/.exec(trailerDict);
        if (inlineInfo) return inlineInfo[1];
      }
    }
  }
  // 2) document-wide: /Info << ... >>
  const inline = /Info\s*<<([\s\S]*?)>>/.exec(str);
  if (inline) return inline[1];
  // 3) document-wide: any object that looks like an info dict
  const objRe = /(\d+)\s+0\s+obj\s*<<([\s\S]*?)>>\s*endobj/g;
  let m;
  while ((m = objRe.exec(str)) !== null) {
    if (/Author|Title|Creator|Producer/.test(m[2])) return m[2];
  }
  return null;
}

// Count pages: count /Type /Page (not /Pages), or read /Count from /Pages.
function findPageCount(str) {
  // Count standalone /Type /Page occurrences (avoid matching /Pages)
  const pageMatches = str.match(/\/Type\s*\/Page(?!s)/g);
  if (pageMatches && pageMatches.length) return pageMatches.length;
  // fallback: /Count in a /Pages dict
  const countMatch = /\/Type\s*\/Pages[\s\S]*?\/Count\s+(\d+)/.exec(str);
  if (countMatch) return parseInt(countMatch[1], 10);
  return null;
}

function parsePdfMeta(buf) {
  try {
    const str = buf.toString("latin1");
    const out = {
      author: null, title: null, subject: null, keywords: null,
      creator: null, producer: null, creationDate: null, modDate: null,
      pageCount: null, pdfVersion: null, encryption: null, raw: 0,
    };
    const ver = /%PDF-(\d+\.\d+)/.exec(str);
    if (ver) out.pdfVersion = ver[1];
    if (/\/Encrypt\b/.test(str)) out.encryption = true;

    const infoDict = findInfoDict(str);
    parseInfoKeys(infoDict, out);

    out.pageCount = findPageCount(str);
    out.raw = Object.keys(out).filter(k => out[k] != null && k !== "raw").length;
    return { ok: true, data: out };
  } catch (e) {
    return { ok: false, detail: (e && e.message) || "PDF parse failed" };
  }
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

  const limited = await kvRateLimit(`rl:filemeta:${session.userId}`, 20, 60);
  if (limited) return json(res, 429, { error: "Rate limit reached. Wait a moment." });

  // Read raw body
  let raw;
  try {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    raw = Buffer.concat(chunks);
  } catch (_) {
    return json(res, 400, { error: "Could not read request body" });
  }
  if (raw.length > MAX_UPLOAD + 1024 * 1024) {
    return json(res, 413, { error: "File too large (max 25 MB)" });
  }

  const boundaryMatch = /boundary=([^;]+)/i.exec(String(req.headers["content-type"] || ""));
  const boundary = boundaryMatch ? boundaryMatch[1].replace(/["']/g, "") : "";
  const file = parseMultipart(raw, boundary);
  if (!file || !file.buffer || !file.buffer.length) {
    return json(res, 400, { error: "No file received. Please upload a file." });
  }

  const started = Date.now();
  const sniff = sniffType(file.buffer);
  const hash = sha256(file.buffer);

  let meta = null;
  let metaError = "";
  if (sniff.kind === "image") {
    const img = await parseImageExif(file.buffer);
    meta = img.ok ? img.data : null;
    if (!img.ok) metaError = img.detail;
  } else if (sniff.kind === "pdf") {
    const pdf = await parsePdfMeta(file.buffer);
    meta = pdf.ok ? pdf.data : null;
    if (!pdf.ok) metaError = pdf.detail;
  } else {
    metaError = "No metadata parser for this file type";
  }

  const durationMs = Date.now() - started;
  const status = meta ? "found" : "partial";

  await appendLookup(session.userId, makeEntry("file", (file.filename || "upload").slice(0, 120), status, durationMs)).catch(() => {});

  return json(res, 200, {
    status,
    filename: file.filename || "upload",
    mimeType: file.mime,
    sizeBytes: file.buffer.length,
    sizeHuman: humanSize(file.buffer.length),
    sha256: hash,
    fileType: sniff.kind,
    fileExt: sniff.ext,
    metadata: meta,
    metaError,
    durationMs,
  });
}

module.exports = handler;
module.exports.config = { maxDuration: 30 };
