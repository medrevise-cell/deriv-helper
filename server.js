const http = require('http');
const fs = require('fs');
const path = require('path');
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

http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  const u = new URL(req.url, 'http://local');
  const route = u.pathname.replace(/\/$/, '') || '/';
  if (route === '/app') {
    try {
      const page = fs.readFileSync(path.join(__dirname, 'index.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(page);
    } catch (e) {
      return send(res, 404, { error: 'index.html not found in the repository' });
    }
  }
  if (route !== '/otp' && route !== '/accounts') return send(res, 200, { ok: true, service: 'deriv-helper' });
  if (!PROXY_KEY || clean(req.headers['x-key']) !== PROXY_KEY) return send(res, 401, { error: 'Wrong passcode' });
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
