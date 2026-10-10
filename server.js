const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
// Strip invisible characters (copy/paste can add them) from all settings.
const clean = (v) => String(v || '').replace(/[^\x20-\x7E]/g, '').trim();
const DERIV_TOKEN = clean(process.env.DERIV_TOKEN);
const DERIV_APP_ID = clean(process.env.DERIV_APP_ID);
const PROXY_KEY = clean(process.env.PROXY_KEY);
const ACCOUNT_ID = clean(process.env.ACCOUNT_ID);
const ALLOW_REAL = clean(process.env.ALLOW_REAL);
const PORT = process.env.PORT || 3000;
const API = 'https://api.derivws.com/trading/v1/options';
const H = { Authorization: `Bearer ${DERIV_TOKEN}`, 'Deriv-App-ID': DERIV_APP_ID };
const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'x-key',
  'Access-Control-Allow-Methods': 'GET,OPTIONS',
};
const send = (res, code, obj) => {
  res.writeHead(code, { ...cors, 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
};
const text = (res, code, type, body) => {
  res.writeHead(code, { 'Content-Type': type });
  res.end(body);
};
const same = (a, b) => {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
// Slow down passcode guessing: 10 wrong tries per 10 minutes per visitor.
const fails = new Map();
const who = (req) => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const blocked = (ip) => {
  const f = fails.get(ip);
  return f && f.n >= 10 && Date.now() - f.t < 600000;
};
const fail = (ip) => {
  const f = fails.get(ip);
  fails.set(ip, f && Date.now() - f.t < 600000 ? { n: f.n + 1, t: f.t } : { n: 1, t: Date.now() });
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
    text(res, 200, 'text/html; charset=utf-8', page);
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
  if (route === '/health') return send(res, 200, { ok: true, service: 'deriv-helper' });
  if (route === '/robots.txt')
    return text(res, 200, 'text/plain', `User-agent: *\nAllow: /\nDisallow: /otp\nDisallow: /accounts\nSitemap: https://${host}/sitemap.xml\n`);
  if (route === '/sitemap.xml')
    return text(res, 200, 'application/xml', `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://${host}/</loc></url></urlset>\n`);
  if (route !== '/otp' && route !== '/accounts') return send(res, 404, { error: 'Not found' });
  const ip = who(req);
  if (blocked(ip)) return send(res, 429, { error: 'Too many wrong passcodes. Try again in 10 minutes.' });
  if (!PROXY_KEY || !same(clean(req.headers['x-key']), PROXY_KEY)) {
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
