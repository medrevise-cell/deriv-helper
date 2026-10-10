
const http = require('http');
const fs = require('fs');
const path = require('path');
const { DERIV_TOKEN, DERIV_APP_ID, PROXY_KEY, ACCOUNT_ID, ALLOW_REAL } = process.env;
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

http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  if (req.url === '/app' || req.url === '/app/') {
    try {
      const page = fs.readFileSync(path.join(__dirname, 'index.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(page);
    } catch (e) {
      return send(res, 404, { error: 'index.html not found in the repository' });
    }
  }
  if (!req.url.startsWith('/otp')) return send(res, 200, { ok: true, service: 'deriv-helper' });
  if (!PROXY_KEY || req.headers['x-key'] !== PROXY_KEY) return send(res, 401, { error: 'Wrong passcode' });
  if (!DERIV_TOKEN || !DERIV_APP_ID) return send(res, 500, { error: 'Helper is missing DERIV_TOKEN or DERIV_APP_ID' });
  try {
    const lr = await fetch(`${API}/accounts`, { headers: H });
    const lj = await lr.json().catch(() => ({}));
    if (!lr.ok) return send(res, 502, { error: (lj.errors && lj.errors[0] && lj.errors[0].message) || `Deriv said HTTP ${lr.status}` });
    const list = Array.isArray(lj.data) ? lj.data : (lj.data && (lj.data.accounts || lj.data.items)) || [];
    const accounts = list.map(info).filter((a) => a.id);
    if (!accounts.length) return send(res, 502, { error: 'Could not read accounts', raw: JSON.stringify(lj).slice(0, 200) });
    const pick = ACCOUNT_ID ? accounts.find((a) => a.id === ACCOUNT_ID) : accounts.find((a) => a.demo);
    if (!pick) return send(res, 404, { error: 'No matching demo account found' });
    if (!pick.demo && ALLOW_REAL !== '1') return send(res, 403, { error: 'Real accounts are blocked. Set ALLOW_REAL=1 to allow.' });
    const or = await fetch(`${API}/accounts/${encodeURIComponent(pick.id)}/otp`, { method: 'POST', headers: H });
    const oj = await or.json().catch(() => ({}));
    const url = oj.data && oj.data.url;
    if (!or.ok || !url) return send(res, 502, { error: (oj.errors && oj.errors[0] && oj.errors[0].message) || `OTP failed (HTTP ${or.status})` });
    return send(res, 200, { url, id: pick.id, demo: pick.demo, currency: pick.currency, balance: pick.balance });
  } catch (e) {
    return send(res, 500, { error: String(e.message || e) });
  }
}).listen(PORT, () => console.log('deriv-helper listening on', PORT));
