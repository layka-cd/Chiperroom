"use strict";
/**
 * Pratinjau tautan (judul, deskripsi, gambar) untuk CipherRoom.
 *
 * Cara kerja singkat:
 *  - Browser PENGIRIM meminta pratinjau ke endpoint ini saat dia menempel/mengetik tautan.
 *  - Hasilnya ikut dienkripsi di dalam pesan, jadi penerima tidak menghubungi situs tujuan.
 *  - Server hanya mengambil halaman bila pengirim memintanya. Isi pesan tetap tidak dibaca server.
 *
 * Dibuat hemat untuk Render free tier: batas ukuran, batas waktu, batas jumlah
 * permintaan bersamaan, rate limit per IP, dan cache kecil di RAM.
 *
 * Keamanan (SSRF): server tidak boleh bisa disuruh membuka alamat internal.
 *  - hanya http/https, port 80/443, tanpa user:password di URL
 *  - alamat IP privat / loopback / link-local diblokir, dicek saat koneksi dibuat
 *    (bukan hanya sebelum) sehingga tidak bisa dikelabui DNS rebinding
 *  - redirect diikuti manual (maks 3) dan setiap lompatan dicek ulang
 */

const dns = require("dns");
const net = require("net");
const http = require("http");
const https = require("https");
const zlib = require("zlib");

// Hanya untuk uji lokal. JANGAN aktifkan di produksi.
const DEV_ALLOW_LOCAL = process.env.PREVIEW_DEV_ALLOW_LOCAL === "1";

const MAX_HTML_BYTES = 300 * 1024;
const MAX_IMAGE_BYTES = 1200 * 1024;
const FETCH_TIMEOUT_MS = 5000;
const MAX_CONCURRENT = 4;
const RATE_WINDOW_MS = 60 * 1000;
const RATE_MAX = 24;            // permintaan per IP per menit (1 pratinjau = sampai 3 permintaan)
const CACHE_TTL_MS = 10 * 60 * 1000;
const CACHE_MAX = 100;

// ---------- Blokir alamat internal ----------
const blocked = new net.BlockList();
[
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 3]
].forEach(([a, p]) => blocked.addSubnet(a, p, "ipv4"));
[
  ["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8],
  ["64:ff9b::", 96], ["2002::", 16], ["2001:db8::", 32]
].forEach(([a, p]) => blocked.addSubnet(a, p, "ipv6"));

function isBlockedAddress(addr) {
  if (DEV_ALLOW_LOCAL) return false;
  const fam = net.isIP(addr);
  if (!fam) return true;
  return blocked.check(addr, fam === 6 ? "ipv6" : "ipv4");
}

function safeLookup(hostname, options, cb) {
  if (typeof options === "function") { cb = options; options = {}; }
  dns.lookup(hostname, { all: true }, (err, addrs) => {
    if (err) return cb(err);
    const ok = addrs.filter((a) => !isBlockedAddress(a.address));
    if (!ok.length) return cb(new Error("blocked_address"));
    if (options && options.all) return cb(null, ok);
    cb(null, ok[0].address, ok[0].family);
  });
}

// ---------- Fetch terbatas ----------
function fetchLimited(urlStr, opts, hops) {
  hops = hops || 0;
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (fn, v) => { if (!settled) { settled = true; clearTimeout(deadline); fn(v); } };
    const deadline = setTimeout(() => { if (req) req.destroy(); done(reject, new Error("timeout")); }, opts.totalMs || FETCH_TIMEOUT_MS);
    let req = null;

    let u;
    try { u = new URL(urlStr); } catch (e) { return done(reject, new Error("bad_url")); }
    if (u.protocol !== "http:" && u.protocol !== "https:") return done(reject, new Error("bad_protocol"));
    if (u.username || u.password) return done(reject, new Error("bad_url"));
    const port = u.port ? Number(u.port) : (u.protocol === "https:" ? 443 : 80);
    if (!DEV_ALLOW_LOCAL && port !== 80 && port !== 443) return done(reject, new Error("bad_port"));
    const host = u.hostname.replace(/^\[|\]$/g, "");
    if (net.isIP(host) && isBlockedAddress(host)) return done(reject, new Error("blocked_address"));

    const lib = u.protocol === "https:" ? https : http;
    req = lib.request(u, {
      method: "GET",
      lookup: safeLookup,
      timeout: opts.totalMs || FETCH_TIMEOUT_MS,
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; CipherRoomPreview/1.0; +link-preview)",
        "Accept": opts.accept,
        "Accept-Language": "id,en;q=0.8",
        "Accept-Encoding": "gzip, deflate, br"
      }
    }, (res) => {
      const status = res.statusCode || 0;
      if ([301, 302, 303, 307, 308].includes(status) && res.headers.location) {
        res.resume();
        if (hops >= 3) return done(reject, new Error("too_many_redirects"));
        let next;
        try { next = new URL(res.headers.location, u).toString(); } catch (e) { return done(reject, new Error("bad_redirect")); }
        clearTimeout(deadline);
        settled = true;
        return fetchLimited(next, opts, hops + 1).then(resolve, reject);
      }
      if (status < 200 || status >= 300) { res.resume(); return done(reject, new Error("bad_status")); }
      const ctype = String(res.headers["content-type"] || "").toLowerCase();
      if (opts.typeTest && !opts.typeTest.test(ctype)) { res.resume(); return done(reject, new Error("bad_type")); }
      const declared = Number(res.headers["content-length"]);
      if (!opts.truncate && Number.isFinite(declared) && declared > opts.maxBytes) { res.resume(); return done(reject, new Error("too_large")); }

      let stream = res;
      const enc = String(res.headers["content-encoding"] || "").toLowerCase();
      if (enc === "gzip") stream = res.pipe(zlib.createGunzip());
      else if (enc === "deflate") stream = res.pipe(zlib.createInflate());
      else if (enc === "br") stream = res.pipe(zlib.createBrotliDecompress());
      else if (enc && enc !== "identity") { res.resume(); return done(reject, new Error("bad_encoding")); }

      const chunks = [];
      let size = 0;
      const finish = () => done(resolve, { buffer: Buffer.concat(chunks), contentType: ctype, finalUrl: u.toString() });
      stream.on("data", (c) => {
        if (settled) return;
        size += c.length;
        if (size > opts.maxBytes) {
          if (opts.truncate) {
            chunks.push(c.subarray(0, c.length - (size - opts.maxBytes)));
            res.destroy(); stream.destroy(); finish();
          } else {
            res.destroy(); stream.destroy(); done(reject, new Error("too_large"));
          }
          return;
        }
        chunks.push(c);
      });
      stream.on("end", finish);
      stream.on("error", (e) => (opts.truncate && chunks.length ? finish() : done(reject, e)));
      res.on("error", (e) => done(reject, e));
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (e) => done(reject, e));
    req.end();
  });
}

// ---------- Baca metadata HTML ----------
const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", ndash: "–", mdash: "—", hellip: "…", rsquo: "’", lsquo: "‘", rdquo: "”", ldquo: "“" };
function decodeEntities(s) {
  return String(s)
    .replace(/&#(\d+);/g, (m, n) => { const c = Number(n); return c > 0 && c < 0x110000 ? String.fromCodePoint(c) : m; })
    .replace(/&#x([0-9a-f]+);/gi, (m, h) => { const c = parseInt(h, 16); return c > 0 && c < 0x110000 ? String.fromCodePoint(c) : m; })
    .replace(/&([a-z]+);/gi, (m, n) => (ENTITIES[n.toLowerCase()] !== undefined ? ENTITIES[n.toLowerCase()] : m));
}
function parseAttrs(str) {
  const out = {};
  const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/g;
  let m;
  while ((m = re.exec(str))) {
    const k = m[1].toLowerCase();
    if (!(k in out)) out[k] = m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4];
  }
  return out;
}
function decodeBody(buf, contentType) {
  let charset = (/charset=([\w-]+)/i.exec(contentType) || [])[1];
  if (!charset) charset = (/<meta[^>]+charset=["']?([\w-]+)/i.exec(buf.subarray(0, 2048).toString("latin1")) || [])[1];
  try { return new TextDecoder(charset || "utf-8").decode(buf); }
  catch (e) { return buf.toString("utf8"); }
}
const clean = (s, n) => decodeEntities(s || "").replace(/\s+/g, " ").trim().slice(0, n);
function absoluteHttp(value, base) {
  if (!value) return null;
  try {
    const u = new URL(decodeEntities(value).trim(), base);
    return u.protocol === "http:" || u.protocol === "https:" ? u.toString() : null;
  } catch (e) { return null; }
}

function parseMetadata(html, pageUrl) {
  const metas = {};
  const metaRe = /<meta\b([^>]*)>/gi;
  let m;
  while ((m = metaRe.exec(html))) {
    const a = parseAttrs(m[1]);
    const key = String(a.property || a.name || a.itemprop || "").toLowerCase();
    if (key && a.content !== undefined && !(key in metas)) metas[key] = a.content;
  }
  const titleTag = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  const icons = [];
  const linkRe = /<link\b([^>]*)>/gi;
  while ((m = linkRe.exec(html))) {
    const a = parseAttrs(m[1]);
    const rel = String(a.rel || "").toLowerCase();
    if (a.href && /\bicon\b/.test(rel)) icons.push({ rel, href: a.href });
  }
  const apple = icons.find((i) => i.rel.includes("apple-touch-icon"));
  const plain = icons.find((i) => !i.rel.includes("apple-touch-icon") && !/\.svg(\?|$)/i.test(i.href));
  const iconHref = (plain || apple || {}).href;

  const host = new URL(pageUrl).hostname.replace(/^www\./, "");
  return {
    domain: host,
    title: clean(metas["og:title"] || metas["twitter:title"] || (titleTag && titleTag[1]), 140),
    description: clean(metas["og:description"] || metas["twitter:description"] || metas["description"], 260),
    site: clean(metas["og:site_name"], 60),
    image: absoluteHttp(metas["og:image:secure_url"] || metas["og:image"] || metas["twitter:image"] || metas["twitter:image:src"], pageUrl),
    icon: absoluteHttp(iconHref, pageUrl) || absoluteHttp("/favicon.ico", pageUrl)
  };
}

// ---------- Rate limit, antrean, cache ----------
const hits = new Map();
function rateOk(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < RATE_WINDOW_MS);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length <= RATE_MAX;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, arr] of hits) if (!arr.some((t) => now - t < RATE_WINDOW_MS)) hits.delete(ip);
}, 5 * 60 * 1000).unref();

let inflight = 0;
const cache = new Map();
function cacheGet(k) {
  const e = cache.get(k);
  if (!e) return null;
  if (Date.now() - e.t > CACHE_TTL_MS) { cache.delete(k); return null; }
  return e.v;
}
function cacheSet(k, v) {
  cache.set(k, { t: Date.now(), v });
  while (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value);
}

// ---------- Route ----------
function guard(req, res) {
  const site = req.headers["sec-fetch-site"];
  if (site && site !== "same-origin") { res.status(403).json({ ok: false, error: "forbidden" }); return false; }
  if (!rateOk(req.ip)) { res.status(429).json({ ok: false, error: "rate_limited" }); return false; }
  if (inflight >= MAX_CONCURRENT) { res.status(429).json({ ok: false, error: "busy" }); return false; }
  return true;
}
function validUrlParam(v) {
  if (typeof v !== "string" || v.length > 800) return null;
  try { const u = new URL(v); return u.protocol === "http:" || u.protocol === "https:" ? u.toString() : null; }
  catch (e) { return null; }
}

function registerPreviewRoutes(app) {
  app.set("trust proxy", 1); // di belakang proxy Render, supaya req.ip adalah IP pengguna

  app.get("/api/preview", async (req, res) => {
    if (!guard(req, res)) return;
    const url = validUrlParam(req.query.url);
    if (!url) return res.status(400).json({ ok: false, error: "bad_url" });
    res.setHeader("Cache-Control", "no-store");
    const cached = cacheGet(url);
    if (cached) return res.json(cached);

    inflight++;
    try {
      const r = await fetchLimited(url, {
        accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
        typeTest: /^(text\/html|application\/xhtml\+xml)/,
        maxBytes: MAX_HTML_BYTES, truncate: true
      });
      const meta = parseMetadata(decodeBody(r.buffer, r.contentType), r.finalUrl);
      if (!meta.title && !meta.description && !meta.image) return res.json({ ok: false, error: "no_metadata" });
      const out = Object.assign({ ok: true, url: r.finalUrl }, meta);
      cacheSet(url, out);
      res.json(out);
    } catch (e) {
      res.status(502).json({ ok: false, error: "fetch_failed" });
    } finally {
      inflight--;
    }
  });

  // Gambar pratinjau diambil lewat server (browser tidak boleh membacanya langsung karena CORS),
  // lalu browser pengirim mengecilkannya sebelum dienkripsi dan dikirim.
  app.get("/api/preview-image", async (req, res) => {
    if (!guard(req, res)) return;
    const url = validUrlParam(req.query.u);
    if (!url) return res.status(400).json({ ok: false, error: "bad_url" });
    inflight++;
    try {
      const r = await fetchLimited(url, {
        accept: "image/avif,image/webp,image/png,image/jpeg,image/gif,image/x-icon,*/*;q=0.3",
        typeTest: /^image\/(jpeg|jpg|png|webp|gif|x-icon|vnd\.microsoft\.icon)/,
        maxBytes: MAX_IMAGE_BYTES, truncate: false
      });
      res.setHeader("Content-Type", r.contentType.split(";")[0]);
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("Content-Security-Policy", "default-src 'none'; sandbox");
      res.setHeader("Cache-Control", "private, max-age=600");
      res.end(r.buffer);
    } catch (e) {
      res.status(502).json({ ok: false, error: "fetch_failed" });
    } finally {
      inflight--;
    }
  });
}

module.exports = { registerPreviewRoutes, isBlockedAddress, parseMetadata };
