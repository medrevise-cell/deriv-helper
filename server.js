const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
// ---- app icon (PNG drawn in code), manifest and service worker so Chrome can install the toolkit as an app ----
const crcT = (() => { const t = []; for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
const crc = (b) => { let c = 0xffffffff; for (const x of b) c = crcT[(c ^ x) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
const chunk = (type, data) => {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type), data]);
  const sum = Buffer.alloc(4); sum.writeUInt32BE(crc(body));
  return Buffer.concat([len, body, sum]);
};
const makeIcon = (size) => {
  const row = size * 4 + 1, raw = Buffer.alloc(row * size);
  const bars = [[0.2, 0.5], [0.44, 0.34], [0.68, 0.2]];   // x start and top of each bar
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    const u = x / size, v = y / size;
    const white = v <= 0.78 && bars.some(([bx, top]) => u >= bx && u <= bx + 0.12 && v >= top);
    const o = y * row + 1 + x * 4;
    raw[o] = white ? 255 : 16; raw[o + 1] = white ? 255 : 58; raw[o + 2] = white ? 255 : 166; raw[o + 3] = 255;
  }
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4); ihdr[8] = 8; ihdr[9] = 6;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
};
const ICON192 = makeIcon(192), ICON512 = makeIcon(512);
const MANIFEST = JSON.stringify({
  name: 'Deriv Toolkit', short_name: 'Toolkit', start_url: '/', scope: '/', display: 'standalone',
  background_color: '#101820', theme_color: '#0a0f3a',
  icons: [
    { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any maskable' },
    { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any maskable' },
  ],
});
const SW = `self.addEventListener('install',e=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(clients.claim()));
self.addEventListener('fetch',e=>{
  const u=new URL(e.request.url);
  if(e.request.method!=='GET'||(u.pathname!=='/'&&u.pathname!=='/app'))return;
  e.respondWith(fetch(e.request).then(r=>{const c=r.clone();caches.open('toolkit').then(x=>x.put('/',c));return r}).catch(()=>caches.match('/')));
});`;
// Strip invisible characters (copy/paste can add them) from all settings.
const clean = (v) => String(v || '').replace(/[^\x20-\x7E]/g, '').trim();
const DERIV_TOKEN = clean(process.env.DERIV_TOKEN);
const DERIV_APP_ID = clean(process.env.DERIV_APP_ID);
const PROXY_KEY = clean(process.env.PROXY_KEY);
const ACCOUNT_ID = clean(process.env.ACCOUNT_ID);
const ALLOW_REAL = clean(process.env.ALLOW_REAL);
const PORT = process.env.PORT || 3000;
const API = clean(process.env.DERIV_API_BASE) || 'https://api.derivws.com/trading/v1/options';
const H = { Authorization: `Bearer ${DERIV_TOKEN}`, 'Deriv-App-ID': DERIV_APP_ID };
const SEC = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' };
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self' https: wss:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'x-key',
  'Access-Control-Allow-Methods': 'GET,OPTIONS',
};
const send = (res, code, obj) => {
  res.writeHead(code, { ...cors, ...SEC, 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
};
const text = (res, code, type, body) => {
  res.writeHead(code, { ...SEC, 'Content-Type': type });
  res.end(body);
};
const same = (a, b) => {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
// Slow down passcode guessing: 10 wrong tries per 10 minutes per visitor.
const fails = new Map();
// The visitor can fake the first X-Forwarded-For entry, so use the last one (added by the hosting proxy).
const who = (req) => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',').pop().trim();
// Plus a global limit that header tricks cannot get around: 30 wrong passcodes in 10 minutes from anyone.
let gfails = { n: 0, t: 0 };
const blocked = (ip) => {
  const f = fails.get(ip);
  return (f && f.n >= 10 && Date.now() - f.t < 600000) || (gfails.n >= 30 && Date.now() - gfails.t < 600000);
};
const fail = (ip) => {
  const f = fails.get(ip);
  fails.set(ip, f && Date.now() - f.t < 600000 ? { n: f.n + 1, t: f.t } : { n: 1, t: Date.now() });
  gfails = Date.now() - gfails.t < 600000 ? { n: gfails.n + 1, t: gfails.t } : { n: 1, t: Date.now() };
};
const info = (a) => {
  const id = String(a.account_id || a.id || a.loginid || a.accountId || '');
  const demo =
    /demo|virtual/i.test(String(a.account_type || a.type || '')) ||
    a.is_virtual === 1 || a.is_virtual === true || /^(DOT|VRT)/i.test(id);
  return { id, demo, currency: a.currency || 'USD', balance: a.balance };
};
const getAccounts = async () => {
  const r = await fetch(`${API}/accounts`, { headers: H });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) return { err: (j.errors && j.errors[0] && j.errors[0].message) || `Deriv said HTTP ${r.status}`, code: 502 };
  const list = Array.isArray(j.data) ? j.data : (j.data && (j.data.accounts || j.data.items)) || [];
  const accounts = list.map(info).filter((a) => a.id);
  if (!accounts.length) return { err: 'Could not read accounts', raw: JSON.stringify(j).slice(0, 200), code: 502 };
  return { accounts };
};
const servePage = (res) => {
  try {
    // Newest toolkit-vN.html wins, so updates never clash with old file names.
    const versions = fs.readdirSync(__dirname)
      .filter((f) => /^toolkit-v\d+\.html$/.test(f))
      .sort((x, y) => parseInt(y.slice(9)) - parseInt(x.slice(9)));
    const page = fs.readFileSync(path.join(__dirname, versions[0] || 'index.html'));
    res.writeHead(200, { ...SEC, 'Content-Security-Policy': CSP, 'Content-Type': 'text/html; charset=utf-8' });
    res.end(page);
  } catch (e) {
    send(res, 404, { error: 'No toolkit-vN.html or index.html found in the repository' });
  }
};

http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  const u = new URL(req.url, 'http://local');
  const route = u.pathname.replace(/\/$/, '') || '/';
  const host = req.headers.host || 'localhost';
  if (route === '/' || route === '/app') return servePage(res);
  if (route === '/manifest.webmanifest') return text(res, 200, 'application/manifest+json', MANIFEST);
  if (route === '/sw.js') { res.writeHead(200, { ...SEC, 'Content-Type': 'text/javascript', 'Service-Worker-Allowed': '/', 'Cache-Control': 'no-cache' }); return res.end(SW); }
  if (route === '/icon-192.png' || route === '/icon-512.png') { res.writeHead(200, { ...SEC, 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=86400' }); return res.end(route.includes('192') ? ICON192 : ICON512); }
  if (route === '/health') return send(res, 200, { ok: true, service: 'deriv-helper' });
  if (route === '/robots.txt')
    return text(res, 200, 'text/plain', `User-agent: *\nAllow: /\nDisallow: /otp\nDisallow: /accounts\nSitemap: https://${host}/sitemap.xml\n`);
  if (route === '/sitemap.xml')
    return text(res, 200, 'application/xml', `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://${host}/</loc></url></urlset>\n`);
  if (route !== '/otp' && route !== '/accounts') return send(res, 404, { error: 'Not found' });
  const ip = who(req);
  if (blocked(ip)) return send(res, 429, { error: 'Too many wrong passcodes. Try again in 10 minutes.' });
  if (PROXY_KEY.length < 10) return send(res, 500, { error: 'PROXY_KEY on Render is too short. Use at least 10 characters.' });
  if (!same(clean(req.headers['x-key']), PROXY_KEY)) {
    fail(ip);
    return send(res, 401, { error: 'Wrong passcode' });
  }
  if (!DERIV_TOKEN || !DERIV_APP_ID) return send(res, 500, { error: 'Helper is missing DERIV_TOKEN or DERIV_APP_ID' });
  try {
    const got = await getAccounts();
    if (got.err) return send(res, got.code, { error: got.err, raw: got.raw });
    if (route === '/accounts') return send(res, 200, { accounts: got.accounts, realAllowed: ALLOW_REAL === '1' });
    const want = clean(u.searchParams.get('account')) || ACCOUNT_ID;
    const pick = want ? got.accounts.find((a) => a.id === want) : got.accounts.find((a) => a.demo);
    if (!pick) return send(res, 404, { error: 'No matching account found' });
    if (!pick.demo && ALLOW_REAL !== '1') return send(res, 403, { error: 'Real accounts are blocked. Set ALLOW_REAL=1 on Render to allow.' });
    const or = await fetch(`${API}/accounts/${encodeURIComponent(pick.id)}/otp`, { method: 'POST', headers: H });
    const oj = await or.json().catch(() => ({}));
    const url = oj.data && oj.data.url;
    if (!or.ok || !url) return send(res, 502, { error: (oj.errors && oj.errors[0] && oj.errors[0].message) || `OTP failed (HTTP ${or.status})` });
    return send(res, 200, { url, id: pick.id, demo: pick.demo, currency: pick.currency, balance: pick.balance });
  } catch (e) {
    return send(res, 500, { error: String(e.message || e) });
  }
}).listen(PORT, () => console.log('deriv-helper listening on', PORT));
