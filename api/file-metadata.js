"use strict";

// File Metadata Extractor (key-free) — comprehensive file forensics.
// Accepts an uploaded file and extracts deep structural metadata:
//   - multiple hash fingerprints (MD5, SHA-1, SHA-256, SHA-384, SHA-512, CRC32)
//   - magic-byte type sniffing across images, documents, video, audio, archives
//   - image EXIF (camera, GPS, dates, technical) + embedded thumbnail
//   - PDF document metadata (dependency-free parser)
//   - Office documents (DOCX/XLSX/PPTX/ODT) via embedded core/app properties
//   - ZIP archive listing
//   - MP4/MOV video metadata (duration, dimensions, codec, creation date)
//   - MP3 ID3v2 tags and FLAC/OGG Vorbis comments
// Session-gated, rate-limited, defensive OSINT — we only read metadata,
// never execute or render file content.

const crypto = require("crypto");
const zlib = require("zlib");
const exifr = require("exifr");
const JSZip = require("jszip");
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

// ---- hashes ----
function computeHashes(buf) {
  return {
    md5: crypto.createHash("md5").update(buf).digest("hex"),
    sha1: crypto.createHash("sha1").update(buf).digest("hex"),
    sha256: crypto.createHash("sha256").update(buf).digest("hex"),
    sha384: crypto.createHash("sha384").update(buf).digest("hex"),
    sha512: crypto.createHash("sha512").update(buf).digest("hex"),
    crc32: crc32(buf),
  };
}
const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return ("00000000" + ((c ^ 0xffffffff) >>> 0).toString(16)).slice(-8);
}

// ---- multipart parser (latin1, byte-safe) ----
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
    let headerEnd = chunk.indexOf("\r\n\r\n");
    if (headerEnd === -1) continue;
    const header = chunk.slice(0, headerEnd);
    let body = chunk.slice(headerEnd + 4);
    if (body.charCodeAt(0) === 0x0d && body.charCodeAt(1) === 0x0a) body = body.slice(2);
    if (body.charCodeAt(body.length - 2) === 0x0d && body.charCodeAt(body.length - 1) === 0x0a) body = body.slice(0, -2);
    const cd = /Content-Disposition: form-data;[^\r\n]*/i.exec(header);
    if (!cd) continue;
    const nameMatch = /name="([^"]+)"/i.exec(cd[0]);
    const fileMatch = /filename="([^"]*)"/i.exec(cd[0]);
    if (!fileMatch) continue;
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

// ---- type sniffing (magic bytes) ----
function sniffType(buf) {
  if (!buf || buf.length < 4) return { kind: "unknown", ext: "" };
  const s = (o, n) => buf.slice(o, n).toString("latin1");
  // images
  if (buf[0] === 0xff && buf[1] === 0xd8) return { kind: "image", ext: "jpg" };
  if (buf[0] === 0x89 && s(1, 4) === "PNG") return { kind: "image", ext: "png" };
  if (s(0, 3) === "GIF") return { kind: "image", ext: "gif" };
  if (buf[0] === 0x42 && buf[1] === 0x4d) return { kind: "image", ext: "bmp" };
  if (s(0, 2) === "RI" && s(8, 12) === "WEBP") return { kind: "image", ext: "webp" };
  if (s(0, 4) === "II*\x00" || s(0, 4) === "MM\x00*") return { kind: "image", ext: "tif" };
  if (s(4, 8) === "ftypheic" || s(4, 8) === "ftypheix" || s(4, 8) === "ftypmif1") return { kind: "image", ext: "heic" };
  if (s(0, 4) === "<svg" || s(0, 5) === "<?xml") {
    // svg vs xml: check for <svg
    const head = buf.slice(0, 400).toString("latin1").toLowerCase();
    if (head.includes("<svg")) return { kind: "svg", ext: "svg" };
    return { kind: "xml", ext: "xml" };
  }
  if (s(0, 4) === "%PDF") return { kind: "pdf", ext: "pdf" };
  // office / epub (all ZIP-based): check PK + look for known entries
  if (buf[0] === 0x50 && buf[1] === 0x4b) {
    return sniffZip(buf);
  }
  // audio
  if (s(0, 3) === "ID3") return { kind: "audio", ext: "mp3" };
  if (s(0, 4) === "fLaC") return { kind: "audio", ext: "flac" };
  if (s(0, 4) === "OggS") return { kind: "audio", ext: "ogg" };
  if (s(4, 8) === "ftypM4A" || s(4, 8) === "ftypM4B") return { kind: "audio", ext: "m4a" };
  // video (ISO BMFF: ftyp box)
  if (s(4, 8) === "ftypisom" || s(4, 8) === "ftypmp42" || s(4, 8) === "ftypqt  " ||
      s(4, 8) === "ftypavif" || s(4, 8) === "ftypmsdh" || s(4, 8) === "ftyp3gp4" ||
      /^ftyp/.test(s(4, 8))) return { kind: "video", ext: "mp4" };
  // archives
  if (s(0, 6) === "Rar!\x1a\x07") return { kind: "archive", ext: "rar" };
  if (s(0, 6) === "7z\xbc\xaf\x27\x1c") return { kind: "archive", ext: "7z" };
  if (s(257, 262) === "ustar") return { kind: "archive", ext: "tar" };
  return { kind: "unknown", ext: "" };
}

// Distinguish ZIP-based formats by inspecting stored entry names.
function sniffZip(buf) {
  // Read the central directory file names (best-effort via local headers too).
  const str = buf.toString("latin1");
  const names = [];
  const re = /([^\/]{2,}\.(?:xml|rels|bin|vml|jpeg|jpg|png|gif|bin))/g;
  let m;
  // Detect specific office/epub markers from the raw bytes.
  const has = (needle) => str.includes(needle);
  if (has("word/") || has("[Content_Types].xml") && has("word")) return { kind: "office", ext: "docx" };
  if (has("xl/")) return { kind: "office", ext: "xlsx" };
  if (has("ppt/")) return { kind: "office", ext: "pptx" };
  if (has("mimetype") && has("META-INF/container.xml")) return { kind: "epub", ext: "epub" };
  if (has("content.xml") && has("styles.xml") && has("META-INF")) return { kind: "office", ext: "odt" };
  if (has("META-INF/manifest.xml") && has("java")) return { kind: "archive", ext: "jar" };
  return { kind: "archive", ext: "zip" };
}

function humanSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(2) + " MB";
}

// ---- image EXIF + thumbnail ----
async function parseImageExif(buf) {
  try {
    const data = await exifr.parse(buf, {
      tiff: true, exif: true, gps: true, xmp: true, iptc: true, jfif: true, ifd0: true,
    });
    if (!data) return { ok: true, data: null, thumbnail: null };
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
      dimensions: null,
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
    let thumbnail = null;
    try {
      const thumb = await exifr.thumbnail(buf);
      if (thumb && thumb.data && thumb.data.length) {
        thumbnail = "data:image/jpeg;base64," + thumb.data.toString("base64");
      }
    } catch (_) { /* thumbnail optional */ }
    return { ok: true, data: out, thumbnail };
  } catch (e) {
    return { ok: false, detail: (e && e.message) || "EXIF parse failed", thumbnail: null };
  }
}

// ---- PDF metadata (dependency-free) ----
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
        let oct = n; i++;
        for (let k = 0; k < 2 && i + 1 < s.length && /[0-7]/.test(s[i + 1]); k++) { i++; oct += s[i]; }
        out += String.fromCharCode(parseInt(oct, 8) & 0xff);
      } else { out += n; i++; }
    } else { out += c; }
  }
  return out;
}
function readDict(str, start) {
  let i = start, depth = 0, inStr = false, inHex = false;
  while (i < str.length) {
    const c = str[i];
    if (inStr) { if (c === "\\") { i += 2; continue; } if (c === ")") inStr = false; i++; continue; }
    if (inHex) { if (c === ">") inHex = false; i++; continue; }
    if (c === "(") { inStr = true; i++; continue; }
    if (c === "<" && str[i + 1] === "<") { depth++; i += 2; continue; }
    if (c === ">" && str[i + 1] === ">") { depth--; i += 2; if (depth === 0) return str.slice(start + 2, i - 2); continue; }
    i++;
  }
  return null;
}
function parseInfoKeys(dictBody, out, fullStr) {
  if (!dictBody) return;
  const keys = [["Title","title"],["Author","author"],["Subject","subject"],["Keywords","keywords"],["Creator","creator"],["Producer","producer"],["CreationDate","creationDate"],["ModDate","modDate"]];
  for (const [key, field] of keys) {
    if (out[field]) continue;
    // inline string: /Key (value)
    let m = new RegExp("/" + key + "\\s*\\(([\\s\\S]*?)\\)", "i").exec(dictBody);
    if (m) { out[field] = unescapePdfString(m[1]); continue; }
    // hex string: /Key <hex>
    m = new RegExp("/" + key + "\\s*<([0-9A-Fa-f]+)>", "i").exec(dictBody);
    if (m) { out[field] = hexToString(m[1]); continue; }
    // indirect reference: /Key N 0 R  -> resolve object N's string value
    m = new RegExp("/" + key + "\\s+(\\d+)\\s+0\\s+R", "i").exec(dictBody);
    if (m && fullStr) {
      const ref = resolveIndirectString(fullStr, parseInt(m[1], 10));
      if (ref != null) out[field] = ref;
    }
  }
}
function hexToString(hex) {
  let s = "";
  for (let i = 0; i + 1 < hex.length; i += 2) s += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  return s;
}
// Resolve an indirect object N 0 obj ... to its literal string value ( ... ).
function resolveIndirectString(fullStr, num) {
  const re = new RegExp(num + "\\s+0\\s+obj\\b([\\s\\S]*?)endobj", "i");
  const m = re.exec(fullStr);
  if (!m) return null;
  const body = m[1];
  const sm = /^\s*\(([\s\S]*)\)\s*$/.exec(body);
  if (sm) return unescapePdfString(sm[1]);
  const hm = /^\s*<([0-9A-Fa-f]+)>\s*$/.exec(body);
  if (hm) return hexToString(hm[1]);
  return null;
}
function findInfoDict(str) {
  const tIdx = str.lastIndexOf("trailer");
  if (tIdx !== -1) {
    const braceIdx = str.indexOf("<<", tIdx);
    if (braceIdx !== -1) {
      const trailerDict = readDict(str, braceIdx);
      if (trailerDict) {
        const infoRef = /Info\s+(\d+)\s+0\s+R/.exec(trailerDict);
        if (infoRef) {
          const objRe = new RegExp(infoRef[1] + "\\s+0\\s+obj\\b[\\s\\S]*?<<");
          const om = objRe.exec(str);
          if (om) { const oIdx = om.index + om[0].length - 2; const body = readDict(str, oIdx); if (body) return body; }
        }
        const inlineInfo = /Info\s*<<([\s\S]*?)>>/.exec(trailerDict);
        if (inlineInfo) return inlineInfo[1];
      }
    }
  }
  const inline = /Info\s*<<([\s\S]*?)>>/.exec(str);
  if (inline) return inline[1];
  const objRe = /(\d+)\s+0\s+obj\s*<<([\s\S]*?)>>\s*endobj/g;
  let m;
  while ((m = objRe.exec(str)) !== null) { if (/Author|Title|Creator|Producer/.test(m[2])) return m[2]; }
  return null;
}
function findPageCount(str) {
  const pageMatches = str.match(/\/Type\s*\/Page(?!s)/g);
  if (pageMatches && pageMatches.length) return pageMatches.length;
  const countMatch = /\/Type\s*\/Pages[\s\S]*?\/Count\s+(\d+)/.exec(str);
  if (countMatch) return parseInt(countMatch[1], 10);
  return null;
}
function parsePdfMeta(buf) {
  try {
    const str = buf.toString("latin1");
    const out = { author:null, title:null, subject:null, keywords:null, creator:null, producer:null, creationDate:null, modDate:null, pageCount:null, pdfVersion:null, encryption:null, raw:0 };
    const ver = /%PDF-(\d+\.\d+)/.exec(str);
    if (ver) out.pdfVersion = ver[1];
    if (/\/Encrypt\b/.test(str)) out.encryption = true;
    parseInfoKeys(findInfoDict(str), out, str);
    out.pageCount = findPageCount(str);
    out.raw = Object.keys(out).filter(k => out[k] != null && k !== "raw").length;
    return { ok: true, data: out };
  } catch (e) {
    return { ok: false, detail: (e && e.message) || "PDF parse failed" };
  }
}

// ---- Office / ZIP / EPUB (jszip) ----
async function parseZipFamily(buf, kind, ext) {
  try {
    const zip = await JSZip.loadAsync(buf);
    if (kind === "office" || kind === "epub") {
      const out = { author:null, title:null, subject:null, keywords:null, creator:null, producer:null, lastModifiedBy:null, created:null, modified:null, application:null, company:null, appName:null, format: ext };
      // core.xml (Dublin Core) — present in office & epub
      const core = zip.file(ext === "epub" ? "META-INF/core.xml" : "docProps/core.xml");
      if (core) {
        const xml = await core.async("string");
        out.title = pickXml(xml, "dc:title") || pickXml(xml, "title");
        out.author = pickXml(xml, "dc:creator") || pickXml(xml, "creator");
        out.subject = pickXml(xml, "dc:subject") || pickXml(xml, "subject");
        out.keywords = pickXml(xml, "cp:keywords") || pickXml(xml, "keywords");
        out.creator = pickXml(xml, "cp:lastModifiedBy") || pickXml(xml, "lastModifiedBy");
        out.created = pickXml(xml, "dcterms:created") || pickXml(xml, "created");
        out.modified = pickXml(xml, "dcterms:modified") || pickXml(xml, "modified");
      }
      // app.xml — office apps
      if (kind === "office") {
        const app = zip.file("docProps/app.xml");
        if (app) {
          const xml = await app.async("string");
          out.application = pickXml(xml, "Application") || pickXml(xml, "AppVersion");
          out.company = pickXml(xml, "Company");
          out.appName = pickXml(xml, "AppName");
        }
      }
      out.raw = Object.keys(out).filter(k => out[k] != null && k !== "raw").length;
      return { ok: true, data: out };
    }
    // generic archive: list contents
    const files = [];
    let totalUncompressed = 0;
    const entries = Object.values(zip.files);
    for (const f of entries) {
      if (f.dir) continue;
      totalUncompressed += (f._data ? f._data.uncompressedSize : 0) || 0;
      files.push({ name: f.name, size: (f._data ? f._data.uncompressedSize : 0) || 0 });
    }
    files.sort((a, b) => a.name.localeCompare(b.name));
    const out = { fileCount: files.length, totalUncompressed, totalUncompressedHuman: humanSize(totalUncompressed), files: files.slice(0, 200), truncated: files.length > 200 };
    return { ok: true, data: out };
  } catch (e) {
    return { ok: false, detail: (e && e.message) || "ZIP parse failed" };
  }
}
function pickXml(xml, tag) {
  // try namespaced then bare tag
  const re = new RegExp("<(?:[^>]*:)?" + tag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "[^>]*>([\\s\\S]*?)</(?:[^>]*:)?" + tag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ">", "i");
  const m = re.exec(xml);
  if (!m) return null;
  const v = m[1].trim();
  return v || null;
}

// ---- MP4 / MOV (ISO BMFF box parser) ----
function parseVideoMeta(buf) {
  try {
    const out = { duration:null, dimensions:null, width:null, height:null, videoCodec:null, audioCodec:null, creationDate:null, modifiedDate:null, timescale:null, raw:0 };
    // walk top-level boxes to find moov
    let p = 0;
    const boxes = [];
    while (p + 8 <= buf.length) {
      let size = buf.readUInt32BE(p);
      const type = buf.slice(p + 4, p + 8).toString("latin1");
      if (size === 1) { size = buf.readBigUInt64BE(p + 8); }
      if (size === 0) size = buf.length - p;
      if (size < 8 || p + size > buf.length) break;
      boxes.push({ type, start: p, size });
      if (type === "moov") { parseMoov(buf, p + 8, p + size, out); }
      p += size;
    }
    if (out.timescale && out.duration != null) {
      out.duration = (out.duration / out.timescale).toFixed(2) + "s";
    }
    if (out.dimensions == null && out.width && out.height) out.dimensions = out.width + "×" + out.height;
    out.raw = Object.keys(out).filter(k => out[k] != null && k !== "raw").length;
    return { ok: true, data: out };
  } catch (e) {
    return { ok: false, detail: (e && e.message) || "video parse failed" };
  }
}
// Recursively scan a box range for mvhd/tkhd/stsd/hdlr.
function parseMoov(buf, start, end, out) {
  let p = start;
  while (p + 8 <= end) {
    let size = buf.readUInt32BE(p);
    const type = buf.slice(p + 4, p + 8).toString("latin1");
    if (size === 1) { if (p + 16 > end) break; size = Number(buf.readBigUInt64BE(p + 8)); }
    if (size < 8 || p + size > end) break;
    if (type === "mvhd") {
      const ver = buf[p + 8];
      const base = p + 8 + (ver === 1 ? 20 : 12);
      out.timescale = buf.readUInt32BE(base);
      const duration = ver === 1 ? Number(buf.readBigUInt64BE(base + 4)) : buf.readUInt32BE(base + 4);
      out.duration = duration;
      // creation/modified: v0 at p+12/p+16 (4 bytes), v1 at p+12/p+20 (8 bytes)
      out.creationDate = readAppleTime(buf, p + 12, ver);
      out.modifiedDate = readAppleTime(buf, ver === 1 ? p + 20 : p + 16, ver);
    } else if (type === "tkhd") {
      // width/height are last 8 bytes of tkhd (16.16 fixed)
      const w = buf.readUInt32BE(p + size - 8);
      const h = buf.readUInt32BE(p + size - 4);
      out.width = Math.round(w / 65536);
      out.height = Math.round(h / 65536);
    } else if (type === "stsd") {
      // sample description (fullbox): skip size+type+version/flags, then entry count
      let q = p + 12;
      if (q + 4 <= p + size) {
        const entryCount = buf.readUInt32BE(q);
        q += 4;
        for (let i = 0; i < entryCount && q + 8 <= p + size; i++) {
          const entrySize = buf.readUInt32BE(q);
          const fourcc = buf.slice(q + 4, q + 8).toString("latin1");
          if (/^(avc|hvc|hev|mp4v|av01|vp09|avc1|hvc1)/.test(fourcc)) out.videoCodec = fourcc;
          else if (/^(mp4a|ac-3|ec-3|opus|alac)/.test(fourcc)) out.audioCodec = fourcc;
          q += entrySize;
        }
      }
    } else if (type === "moov" || type === "trak" || type === "mdia" || type === "minf" || type === "stbl") {
      parseMoov(buf, p + 8, p + size, out);
    }
    p += size;
  }
}
function readAppleTime(buf, off, ver) {
  // Apple epoch: seconds since 1904-01-01. v0 = 32-bit, v1 = 64-bit.
  try {
    const secs = ver === 1 ? Number(buf.readBigUInt64BE(off)) : buf.readUInt32BE(off);
    const appleEpoch = Date.UTC(1904, 0, 1);
    const ms = appleEpoch + secs * 1000;
    if (ms > 0 && ms < Date.now() + 86400000 * 365 * 50) return new Date(ms).toISOString();
  } catch (_) {}
  return null;
}

// ---- MP3 ID3v2 + FLAC/OGG Vorbis ----
function parseAudioMeta(buf, ext) {
  try {
    if (ext === "mp3") return parseId3v2(buf);
    return parseVorbis(buf, ext);
  } catch (e) {
    return { ok: false, detail: (e && e.message) || "audio parse failed" };
  }
}
function parseId3v2(buf) {
  const out = { format: "ID3v2", title:null, artist:null, album:null, year:null, genre:null, track:null, comment:null, raw:0 };
  if (buf.slice(0, 3).toString("latin1") !== "ID3") return { ok: true, data: out };
  const major = buf[3];
  const size = syncsafe(buf, 6);
  let p = 10;
  const end = 10 + size;
  const frames = { TIT2:"title", TPE1:"artist", TALB:"album", TYER:"year", TDRC:"year", TCON:"genre", TRCK:"track", COMM:"comment", TPE2:"albumArtist" };
  while (p + 10 <= end && p < buf.length) {
    const id = buf.slice(p, p + 4).toString("latin1");
    if (!/^[A-Z0-9]{4}$/.test(id)) break;
    const fsize = major === 2 ? buf.readUInt32BE(p + 4) : syncsafe(buf, p + 4);
    if (fsize <= 0 || p + 10 + fsize > buf.length) break;
    const field = frames[id];
    if (field && !out[field]) {
      let v = buf.slice(p + 10, p + 10 + fsize).toString("utf8").replace(/\0+$/, "").trim();
      if (field === "track") v = v.split("/").pop();
      out[field] = v || null;
    }
    p += 10 + fsize;
  }
  out.raw = Object.keys(out).filter(k => out[k] != null && k !== "raw").length;
  return { ok: true, data: out };
}
function syncsafe(buf, off) {
  return ((buf[off] & 0x7f) << 21) | ((buf[off + 1] & 0x7f) << 14) | ((buf[off + 2] & 0x7f) << 7) | (buf[off + 3] & 0x7f);
}
function parseVorbis(buf, ext) {
  const out = { format: ext === "flac" ? "FLAC" : "Vorbis", title:null, artist:null, album:null, year:null, genre:null, track:null, raw:0 };
  // FLAC: STREAMINFO block has metadata; seek to first metadata block
  if (ext === "flac") {
    if (buf.slice(0, 4).toString("latin1") !== "fLaC") return { ok: true, data: out };
    let p = 4;
    while (p + 4 <= buf.length) {
      const last = (buf[p] & 0x80) !== 0;
      const type = buf[p] & 0x7f;
      const len = (buf[p + 1] << 16) | (buf[p + 2] << 8) | buf[p + 3];
      p += 4;
      if (type === 0) { // STREAMINFO
        break;
      }
      if (type === 4) { // VORBIS_COMMENT
        const data = buf.slice(p, p + len);
        parseVorbisComments(data, out);
        return { ok: true, data: out };
      }
      p += len;
      if (last) break;
    }
    return { ok: true, data: out };
  }
  // OGG: find "vorbis" page
  let idx = buf.indexOf(Buffer.from("vorbis", "latin1"));
  if (idx !== -1) {
    parseVorbisComments(buf.slice(idx + 6, idx + 6 + 4096), out);
  }
  out.raw = Object.keys(out).filter(k => out[k] != null && k !== "raw").length;
  return { ok: true, data: out };
}
function parseVorbisComments(data, out) {
  let p = 0;
  const vendorLen = data.readUInt32LE(p); p += 4 + vendorLen;
  const count = data.readUInt32LE(p); p += 4;
  const map = { TITLE:"title", ARTIST:"artist", ALBUM:"album", DATE:"year", YEAR:"year", GENRE:"genre", TRACKNUMBER:"track", TRACKNUM:"track" };
  for (let i = 0; i < count && p + 4 <= data.length; i++) {
    const len = data.readUInt32LE(p); p += 4;
    const val = data.slice(p, p + len).toString("utf8").trim(); p += len;
    const key = val.split("=")[0].toUpperCase();
    if (map[key] && !out[map[key]]) out[map[key]] = val.split("=").slice(1).join("=").trim() || null;
  }
}

// ---- intelligence highlights ----
function buildHighlights(fileType, meta) {
  const h = [];
  if (!meta) return h;
  if (fileType === "image") {
    if (meta.gpsMap) h.push("GPS location embedded");
    if (meta.cameraMake || meta.cameraModel) h.push("Camera fingerprint");
    if (meta.software) h.push("Software fingerprint");
    if (meta.artist) h.push("Author identified");
    if (meta.dateTime) h.push("Capture date present");
  } else if (fileType === "pdf") {
    if (meta.author) h.push("Author identified");
    if (meta.creator || meta.producer) h.push("Creation tool fingerprint");
    if (meta.encryption) h.push("Encrypted document");
  } else if (fileType === "office" || fileType === "epub") {
    if (meta.author || meta.creator) h.push("Author identified");
    if (meta.created || meta.modified) h.push("Document timestamps");
    if (meta.application || meta.company) h.push("Application fingerprint");
  } else if (fileType === "video") {
    if (meta.creationDate) h.push("Creation timestamp");
    if (meta.videoCodec || meta.audioCodec) h.push("Codec fingerprint");
  } else if (fileType === "audio") {
    if (meta.artist) h.push("Artist identified");
    if (meta.title) h.push("Title metadata");
  } else if (fileType === "archive") {
    h.push("Archive container");
  }
  return h;
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
  if (!userBlocked) { try { const bl = await kvGet(`mono:kv_blacklist:${session.userId}`); if (bl) userBlocked = true; } catch (_) {} }
  if (userBlocked) return json(res, 403, { error: "Your account is not allowed to use this service." });

  const limited = await kvRateLimit(`rl:filemeta:${session.userId}`, 20, 60);
  if (limited) return json(res, 429, { error: "Rate limit reached. Wait a moment." });

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
  const hashes = computeHashes(file.buffer);

  let meta = null;
  let metaError = "";
  let thumbnail = null;

  if (sniff.kind === "image") {
    const img = await parseImageExif(file.buffer);
    meta = img.ok ? img.data : null;
    if (img.ok && img.thumbnail) thumbnail = img.thumbnail;
    if (!img.ok) metaError = img.detail;
  } else if (sniff.kind === "pdf") {
    const pdf = parsePdfMeta(file.buffer);
    meta = pdf.ok ? pdf.data : null;
    if (!pdf.ok) metaError = pdf.detail;
  } else if (sniff.kind === "office" || sniff.kind === "epub" || sniff.kind === "archive") {
    const zip = await parseZipFamily(file.buffer, sniff.kind, sniff.ext);
    meta = zip.ok ? zip.data : null;
    if (!zip.ok) metaError = zip.detail;
  } else if (sniff.kind === "video") {
    const vid = parseVideoMeta(file.buffer);
    meta = vid.ok ? vid.data : null;
    if (!vid.ok) metaError = vid.detail;
  } else if (sniff.kind === "audio") {
    const aud = parseAudioMeta(file.buffer, sniff.ext);
    meta = aud.ok ? aud.data : null;
    if (!aud.ok) metaError = aud.detail;
  } else {
    metaError = "No metadata parser for this file type";
  }

  const durationMs = Date.now() - started;
  const status = meta ? "found" : "partial";
  const highlights = buildHighlights(sniff.kind, meta);

  await appendLookup(session.userId, makeEntry("file", (file.filename || "upload").slice(0, 120), status, durationMs)).catch(() => {});

  return json(res, 200, {
    status,
    filename: file.filename || "upload",
    mimeType: file.mime,
    sizeBytes: file.buffer.length,
    sizeHuman: humanSize(file.buffer.length),
    hashes,
    fileType: sniff.kind,
    fileExt: sniff.ext,
    metadata: meta,
    metaError,
    thumbnail,
    highlights,
    durationMs,
  });
}

// local kv wrapper (avoids pulling the whole kv module's surface here)
async function kvGet(key) {
  const kv = require("../lib/kv");
  return kv.get(key);
}

module.exports = handler;
module.exports.config = { maxDuration: 30 };
