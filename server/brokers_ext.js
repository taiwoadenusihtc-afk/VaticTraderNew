'use strict';
/*
 * Additional broker adapters for VaticTrader.
 *
 * What this file does: plugs more brokers into the generic adapter framework in
 * server.js (connect, account read, health check, safe test order, disconnect).
 *
 *   API-key brokers   Binance, Kraken, Coinbase (Advanced Trade), Trading 212, IG
 *   OAuth brokers     Saxo, Charles Schwab, TradeStation  (need your own developer app)
 *   Gateway broker    Interactive Brokers (Client Portal Gateway you run yourself)
 *
 * What it does NOT do: automated live execution. Only Alpaca has that (see
 * supportsAutomatedExecution in server.js). These adapters connect, read the
 * account and validate an order, nothing more.
 *
 * Honesty note: these were written from each provider's public documentation and
 * tested only against local mock servers that implement the same signing and
 * response shapes. They have NOT been run against the real provider endpoints,
 * so expect to adjust a field name or header on first contact with a real account.
 * Start with demo/testnet environments wherever one exists.
 */
const crypto = require('crypto');
const https = require('https');

const TIMEOUT_MS = 15000;
const num = (v) => { const n = parseFloat(v); return isFinite(n) ? n : null; };
const str = (v) => (v === null || v === undefined ? null : String(v));

function fail(status, error, detail) { return { ok: false, status, error, detail }; }
function clip(s, n) { return String(s === undefined || s === null ? '' : s).slice(0, n || 300); }

async function http(url, opts) {
  const o = Object.assign({}, opts || {});
  o.signal = AbortSignal.timeout(TIMEOUT_MS);
  const res = await fetch(url, o);
  const text = await res.text().catch(() => '');
  let json = null; try { json = text ? JSON.parse(text) : null; } catch (e) { /* not json */ }
  return { status: res.status, ok: res.ok, json, text, headers: res.headers };
}

function summary(x) {
  return {
    accountNumber: str(x.accountNumber), status: str(x.status || 'ACTIVE'), currency: str(x.currency),
    cash: str(x.cash), buyingPower: str(x.buyingPower), portfolioValue: str(x.equity), equity: str(x.equity),
    lastEquity: null, tradingBlocked: !!x.tradingBlocked, mode: x.mode || 'live', note: x.note || null,
  };
}

module.exports = function registerExtraBrokers(ctx) {
  const { BrokerAdapters, pool, encryptSecret, decryptSecret, app, requireAuth, assertPublicHttpsUrl, APP_BASE_URL } = ctx;
  const env = process.env;

  // ------------------------------------------------------------------ Binance
  const BINANCE = { live: env.BINANCE_BASE_LIVE || 'https://api.binance.com', testnet: env.BINANCE_BASE_TESTNET || 'https://testnet.binance.vision' };
  const STABLES = new Set(['USDT', 'USDC', 'BUSD', 'FDUSD', 'TUSD', 'USD', 'DAI']);
  async function binanceSigned(base, key, secret, path, params, method) {
    const qs = new URLSearchParams(Object.assign({}, params || {}, { timestamp: String(Date.now()), recvWindow: '5000' })).toString();
    const sig = crypto.createHmac('sha256', secret).update(qs).digest('hex');
    return http(`${base}${path}?${qs}&signature=${sig}`, { method: method || 'GET', headers: { 'X-MBX-APIKEY': key } });
  }
  async function binanceSummary(base, key, secret, mode) {
    const r = await binanceSigned(base, key, secret, '/api/v3/account');
    if (!r.ok) return r;
    const bal = (r.json.balances || []).filter(b => num(b.free) + num(b.locked) > 0);
    let prices = {};
    try { const p = await http(`${base}/api/v3/ticker/price`); if (p.ok && Array.isArray(p.json)) p.json.forEach(t => { prices[t.symbol] = num(t.price); }); } catch (e) { /* equity falls back to stable balances */ }
    let equity = 0, cash = 0, unpriced = 0;
    bal.forEach(b => {
      const q = num(b.free) + num(b.locked);
      if (STABLES.has(b.asset)) { equity += q; if (b.asset === 'USDT' || b.asset === 'USDC' || b.asset === 'USD') cash += num(b.free); }
      else if (prices[b.asset + 'USDT']) equity += q * prices[b.asset + 'USDT'];
      else unpriced++;
    });
    return { ok: true, json: r.json, sum: summary({ accountNumber: 'Spot ' + (r.json.uid || '').toString().slice(-4), status: r.json.canTrade ? 'ACTIVE' : 'TRADING DISABLED', currency: 'USD', cash: cash.toFixed(2), buyingPower: cash.toFixed(2), equity: equity.toFixed(2), tradingBlocked: r.json.canTrade === false, mode, note: unpriced ? `${unpriced} asset${unpriced > 1 ? 's' : ''} ${unpriced > 1 ? "were" : "was"} not priced and ${unpriced > 1 ? "are" : "is"} left out of the equity figure.` : null }) };
  }
  BrokerAdapters.binance = {
    id: 'binance', name: 'Binance', requiredFields: ['apiKey', 'apiSecret'], supportsAutomatedExecution: false, canTestOrder: true,
    async connect(body) {
      const mode = body.environment === 'live' ? 'live' : 'testnet', base = BINANCE[mode];
      const r = await binanceSummary(base, body.apiKey, body.apiSecret, mode === 'live' ? 'live' : 'paper');
      if (!r.ok) {
        if (r.status === 401 || (r.json && [-2014, -2015, -1022].includes(r.json.code))) return fail(400, `Binance rejected these keys${mode === 'testnet' ? ' on the testnet' : ''}. Check the key, the secret and (for live keys) any IP restriction.`);
        return fail(502, 'Binance returned an unexpected error.', clip(r.text));
      }
      return { ok: true, credsForStorage: { primary: body.apiKey, secretPlain: body.apiSecret, baseUrl: base }, accountSummary: r.sum };
    },
    async fetchAccount(creds) {
      const mode = creds.baseUrl === BINANCE.live ? 'live' : 'paper';
      const r = await binanceSummary(creds.baseUrl, creds.primary, creds.secretPlain, mode);
      return r.ok ? { ok: true, accountSummary: r.sum } : fail(502, 'Could not fetch the account from Binance.');
    },
    async placeTestOrder(creds) {
      const r = await binanceSigned(creds.baseUrl, creds.primary, creds.secretPlain, '/api/v3/order/test', { symbol: 'BTCUSDT', side: 'BUY', type: 'MARKET', quoteOrderQty: '10' }, 'POST');
      if (!r.ok) return fail(400, (r.json && r.json.msg) || 'Binance rejected the test order.', r.json);
      return { ok: true, result: { order: { validated: true, executed: false, note: 'Binance accepted a 10 USDT BTCUSDT market order as valid. Nothing was placed.' } } };
    },
  };

  // ------------------------------------------------------------------- Kraken
  const KRAKEN_BASE = env.KRAKEN_BASE || 'https://api.kraken.com';
  let lastNonce = 0;
  async function krakenPrivate(base, key, secretB64, path, params) {
    const nonce = String(Math.max(Date.now() * 1000, lastNonce + 1)); lastNonce = Number(nonce);
    const post = new URLSearchParams(Object.assign({ nonce }, params || {})).toString();
    const sha = crypto.createHash('sha256').update(nonce + post).digest();
    let sign;
    try { sign = crypto.createHmac('sha512', Buffer.from(secretB64, 'base64')).update(Buffer.concat([Buffer.from(path), sha])).digest('base64'); }
    catch (e) { return { status: 0, ok: false, json: { error: ['EGeneral:Invalid secret'] }, text: '' }; }
    return http(base + path, { method: 'POST', headers: { 'API-Key': key, 'API-Sign': sign, 'Content-Type': 'application/x-www-form-urlencoded' }, body: post });
  }
  async function krakenSummary(base, key, secret) {
    const b = await krakenPrivate(base, key, secret, '/0/private/Balance');
    if (!b.ok || !b.json || (b.json.error && b.json.error.length)) return { ok: false, res: b };
    const tb = await krakenPrivate(base, key, secret, '/0/private/TradeBalance', { asset: 'ZUSD' });
    const t = tb.ok && tb.json && tb.json.result ? tb.json.result : {};
    const cash = num((b.json.result || {}).ZUSD) || 0;
    const equity = num(t.eb) !== null ? num(t.eb) : cash;
    return { ok: true, sum: summary({ accountNumber: 'Spot', status: 'ACTIVE', currency: 'USD', cash: cash.toFixed(2), buyingPower: (num(t.mf) !== null ? num(t.mf) : cash).toFixed(2), equity: (num(t.e) !== null ? num(t.e) : equity).toFixed(2), mode: 'live', note: 'Kraken has no spot sandbox, so this is your real account. Use a key limited to the permissions you need.' }) };
  }
  BrokerAdapters.kraken = {
    id: 'kraken', name: 'Kraken', requiredFields: ['apiKey', 'apiSecret'], supportsAutomatedExecution: false, canTestOrder: true,
    async connect(body) {
      const r = await krakenSummary(KRAKEN_BASE, body.apiKey, body.apiSecret);
      if (!r.ok) {
        const errs = (r.res.json && r.res.json.error) || [];
        if (errs.some(e => /Invalid key|Invalid signature|Permission denied|Invalid secret/i.test(e))) return fail(400, `Kraken rejected these keys (${errs[0]}). The key needs the "Query funds" permission, and the secret must be pasted exactly.`);
        return fail(502, 'Kraken returned an unexpected error.', clip(errs.join(', ') || r.res.text));
      }
      return { ok: true, credsForStorage: { primary: body.apiKey, secretPlain: body.apiSecret, baseUrl: KRAKEN_BASE }, accountSummary: r.sum };
    },
    async fetchAccount(creds) { const r = await krakenSummary(creds.baseUrl, creds.primary, creds.secretPlain); return r.ok ? { ok: true, accountSummary: r.sum } : fail(502, 'Could not fetch the account from Kraken.'); },
    async placeTestOrder(creds) {
      const r = await krakenPrivate(creds.baseUrl, creds.primary, creds.secretPlain, '/0/private/AddOrder', { pair: 'XBTUSD', type: 'buy', ordertype: 'market', volume: '0.0001', validate: 'true' });
      const errs = (r.json && r.json.error) || [];
      if (!r.ok || errs.length) return fail(400, errs[0] || 'Kraken rejected the test order. The key needs the "Create & modify orders" permission to validate one.', r.json);
      return { ok: true, result: { order: { validated: true, executed: false, note: 'Kraken validated the order (validate=true). Nothing was placed. ' + clip((r.json.result && r.json.result.descr && r.json.result.descr.order) || '') } } };
    },
  };

  // ----------------------------------------------------------------- Coinbase
  const COINBASE_BASE = env.COINBASE_BASE || 'https://api.coinbase.com';
  const b64u = (o) => (Buffer.isBuffer(o) ? o : Buffer.from(typeof o === 'string' ? o : JSON.stringify(o))).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  function coinbaseJwt(keyName, pem, method, host, path) {
    const now = Math.floor(Date.now() / 1000);
    const head = { alg: 'ES256', kid: keyName, nonce: crypto.randomBytes(16).toString('hex'), typ: 'JWT' };
    const pay = { sub: keyName, iss: 'cdp', nbf: now, exp: now + 120, uri: `${method} ${host}${path}` };
    const input = b64u(head) + '.' + b64u(pay);
    const sig = crypto.sign('sha256', Buffer.from(input), { key: pem, dsaEncoding: 'ieee-p1363' });
    return input + '.' + b64u(sig).replace(/=/g, '') ;
  }
  const normPem = (p) => String(p || '').replace(/\\n/g, '\n').trim();
  async function coinbaseCall(base, keyName, pem, method, path, body) {
    const host = new URL(base).host;
    let jwt; try { jwt = coinbaseJwt(keyName, normPem(pem), method, host, path); } catch (e) { return { status: 0, ok: false, json: null, text: 'bad private key', badKey: true }; }
    return http(base + path, { method, headers: { Authorization: 'Bearer ' + jwt, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  }
  async function coinbaseSummary(base, keyName, pem) {
    const a = await coinbaseCall(base, keyName, pem, 'GET', '/api/v3/brokerage/accounts');
    if (!a.ok) return { ok: false, res: a };
    const accts = (a.json && a.json.accounts) || [];
    let cash = 0; accts.forEach(x => { if (['USD', 'USDC'].includes(x.currency)) cash += num(x.available_balance && x.available_balance.value) || 0; });
    let equity = null;
    try {
      const pl = await coinbaseCall(base, keyName, pem, 'GET', '/api/v3/brokerage/portfolios');
      const pf = pl.ok && pl.json && pl.json.portfolios && pl.json.portfolios[0];
      if (pf) {
        const bd = await coinbaseCall(base, keyName, pem, 'GET', '/api/v3/brokerage/portfolios/' + encodeURIComponent(pf.uuid));
        const tot = bd.ok && bd.json && bd.json.breakdown && bd.json.breakdown.portfolio_balances && bd.json.breakdown.portfolio_balances.total_balance;
        if (tot) equity = num(tot.value);
      }
    } catch (e) { /* fall back below */ }
    return { ok: true, sum: summary({ accountNumber: accts.length + ' wallets', status: 'ACTIVE', currency: 'USD', cash: cash.toFixed(2), buyingPower: cash.toFixed(2), equity: (equity !== null ? equity : cash).toFixed(2), mode: 'live', note: equity === null ? 'Total portfolio value could not be read, so equity shows cash only.' : 'Coinbase has no paper trading, so this is your real account.' }) };
  }
  BrokerAdapters.coinbase = {
    id: 'coinbase', name: 'Coinbase', requiredFields: ['keyName', 'privateKey'], supportsAutomatedExecution: false, canTestOrder: true,
    async connect(body) {
      const r = await coinbaseSummary(COINBASE_BASE, body.keyName.trim(), body.privateKey);
      if (!r.ok) {
        if (r.res.badKey) return fail(400, 'That private key is not a valid EC private key. Paste the full key, including the BEGIN and END lines.');
        if (r.res.status === 401 || r.res.status === 403) return fail(400, 'Coinbase rejected this key. Use a Coinbase Developer Platform API key (Advanced Trade), and paste its full name and private key.');
        return fail(502, 'Coinbase returned an unexpected error.', clip(r.res.text));
      }
      return { ok: true, credsForStorage: { primary: body.keyName.trim(), secretPlain: normPem(body.privateKey), baseUrl: COINBASE_BASE }, accountSummary: r.sum };
    },
    async fetchAccount(creds) { const r = await coinbaseSummary(creds.baseUrl, creds.primary, creds.secretPlain); return r.ok ? { ok: true, accountSummary: r.sum } : fail(502, 'Could not fetch the account from Coinbase.'); },
    async placeTestOrder(creds) {
      const r = await coinbaseCall(creds.baseUrl, creds.primary, creds.secretPlain, 'POST', '/api/v3/brokerage/orders/preview', { product_id: 'BTC-USD', side: 'BUY', order_configuration: { market_market_ioc: { quote_size: '10' } } });
      if (!r.ok) return fail(400, (r.json && (r.json.message || r.json.error)) || 'Coinbase rejected the order preview.', r.json);
      const errs = (r.json && r.json.errs) || [];
      if (errs.length) return fail(400, 'Coinbase flagged the preview: ' + errs.join(', '), r.json);
      return { ok: true, result: { order: { validated: true, executed: false, note: 'Coinbase previewed a $10 BTC-USD market buy. Nothing was placed.' } } };
    },
  };

  // -------------------------------------------------------------- Trading 212
  const T212 = { demo: env.T212_BASE_DEMO || 'https://demo.trading212.com/api/v0', live: env.T212_BASE_LIVE || 'https://live.trading212.com/api/v0' };
  const t212Auth = (k, s) => 'Basic ' + Buffer.from(`${k}:${s}`).toString('base64');
  async function t212Summary(base, key, secret, mode) {
    const h = { Authorization: t212Auth(key, secret) };
    const c = await http(base + '/equity/account/cash', { headers: h });
    if (!c.ok) return { ok: false, res: c };
    const info = await http(base + '/equity/account/info', { headers: h });
    const i = info.ok && info.json ? info.json : {};
    return { ok: true, sum: summary({ accountNumber: i.id, status: 'ACTIVE', currency: i.currencyCode, cash: str(c.json.free), buyingPower: str(c.json.free), equity: str(c.json.total), mode: mode === 'live' ? 'live' : 'demo', note: 'Trading 212 API is in beta; some figures may differ from the app.' }) };
  }
  BrokerAdapters.trading212 = {
    id: 'trading212', name: 'Trading 212', requiredFields: ['apiKey', 'apiSecret'], supportsAutomatedExecution: false, canTestOrder: true,
    async connect(body) {
      const mode = body.environment === 'live' ? 'live' : 'demo', base = T212[mode];
      const r = await t212Summary(base, body.apiKey, body.apiSecret, mode);
      if (!r.ok) {
        if (r.res.status === 401 || r.res.status === 403) return fail(400, `Trading 212 rejected these credentials on the ${mode} environment. A demo key only works on the demo environment, and a live key only on live.`);
        if (r.res.status === 429) return fail(429, 'Trading 212 is rate limiting requests. Wait a few seconds and try again.');
        return fail(502, 'Trading 212 returned an unexpected error.', clip(r.res.text));
      }
      return { ok: true, credsForStorage: { primary: body.apiKey, secretPlain: body.apiSecret, baseUrl: base }, accountSummary: r.sum };
    },
    async fetchAccount(creds) { const r = await t212Summary(creds.baseUrl, creds.primary, creds.secretPlain, creds.baseUrl === T212.live ? 'live' : 'demo'); return r.ok ? { ok: true, accountSummary: r.sum } : fail(502, 'Could not fetch the account from Trading 212.'); },
    async placeTestOrder(creds) {
      if (creds.baseUrl === T212.live) return fail(400, 'Test orders are only sent to the Trading 212 demo environment. Trading 212 has no validate-only order, and VaticTrader will not place a real order as a test.');
      const r = await http(creds.baseUrl + '/equity/orders/market', { method: 'POST', headers: { Authorization: t212Auth(creds.primary, creds.secretPlain), 'Content-Type': 'application/json' }, body: JSON.stringify({ ticker: 'AAPL_US_EQ', quantity: 1 }) });
      if (!r.ok) return fail(400, (r.json && (r.json.message || r.json.code)) || 'Trading 212 rejected the demo order.', r.json);
      return { ok: true, result: { order: r.json || { placed: true } } };
    },
  };

  // ----------------------------------------------------------------------- IG
  const IG = { demo: env.IG_BASE_DEMO || 'https://demo-api.ig.com/gateway/deal', live: env.IG_BASE_LIVE || 'https://api.ig.com/gateway/deal' };
  async function igLogin(base, apiKey, identifier, password) {
    return http(base + '/session', { method: 'POST', headers: { 'X-IG-API-KEY': apiKey, Version: '2', 'Content-Type': 'application/json; charset=UTF-8', Accept: 'application/json; charset=UTF-8' }, body: JSON.stringify({ identifier, password }) });
  }
  function igSummary(r, mode) {
    const j = r.json || {}, a = j.accountInfo || {};
    const equity = (num(a.balance) || 0) + (num(a.profitLoss) || 0);
    return summary({ accountNumber: j.currentAccountId, status: 'ACTIVE', currency: j.currencyIsoCode, cash: str(a.available), buyingPower: str(a.available), equity: equity.toFixed(2), mode: mode === 'live' ? 'live' : 'demo', note: 'IG trades CFDs and spread bets, which carry a high risk of losing money quickly.' });
  }
  BrokerAdapters.ig = {
    id: 'ig', name: 'IG', requiredFields: ['apiKey', 'username', 'password'], supportsAutomatedExecution: false, canTestOrder: false,
    async connect(body) {
      const mode = body.environment === 'live' ? 'live' : 'demo', base = IG[mode];
      const r = await igLogin(base, body.apiKey, body.username, body.password);
      if (!r.ok) {
        const code = r.json && r.json.errorCode;
        if (r.status === 401 || r.status === 403 || /invalid|disabled|api-key/i.test(code || '')) return fail(400, `IG rejected these details${code ? ' (' + code + ')' : ''}. Check the API key, username and password, and that they belong to the ${mode} environment.`);
        return fail(502, 'IG returned an unexpected error.', clip(r.text));
      }
      return { ok: true, credsForStorage: { primary: body.apiKey, secretPlain: JSON.stringify({ u: body.username, p: body.password }), baseUrl: base }, accountSummary: igSummary(r, mode) };
    },
    async fetchAccount(creds) {
      let c; try { c = JSON.parse(creds.secretPlain); } catch (e) { return fail(500, 'Stored IG credentials are unreadable. Disconnect and connect again.'); }
      const r = await igLogin(creds.baseUrl, creds.primary, c.u, c.p);
      return r.ok ? { ok: true, accountSummary: igSummary(r, creds.baseUrl === IG.live ? 'live' : 'demo') } : fail(502, 'Could not fetch the account from IG.');
    },
    async placeTestOrder() { return fail(501, 'IG has no validate-only order endpoint, and VaticTrader will not place a real order as a test. Try an order from IG\'s own demo platform instead.'); },
  };

  // -------------------------------------------------- Interactive Brokers (gateway)
  function gwRequest(gwUrl, path, method, allowSelfSigned) {
    return new Promise((resolve, reject) => {
      const u = new URL(gwUrl.replace(/\/+$/, '') + '/v1/api' + path);
      const req = https.request({ hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, method, rejectUnauthorized: !allowSelfSigned, timeout: TIMEOUT_MS, headers: { 'User-Agent': 'VaticTrader', Accept: 'application/json' } }, (res) => {
        let d = ''; res.on('data', c => { d += c; if (d.length > 2e6) req.destroy(); }); res.on('end', () => { let j = null; try { j = JSON.parse(d); } catch (e) { /* not json */ } resolve({ status: res.statusCode, ok: res.statusCode >= 200 && res.statusCode < 300, json: j, text: d }); });
      });
      req.on('timeout', () => req.destroy(new Error('timeout'))); req.on('error', reject); req.end();
    });
  }
  async function ibkrSummary(gw, selfSigned) {
    let pu; try { pu = new URL(gw); } catch (e) { throw Object.assign(new Error('That address is not a valid URL.'), { status: 400 }); }
    if (pu.protocol !== 'https:') throw Object.assign(new Error('The gateway address must start with https://.'), { status: 400 });
    await assertPublicHttpsUrl(gw);
    const st = await gwRequest(gw, '/iserver/auth/status', 'POST', selfSigned);
    if (!st.ok) return { ok: false, res: st };
    if (!st.json || !st.json.authenticated) return { ok: false, notAuthed: true, res: st };
    const ac = await gwRequest(gw, '/portfolio/accounts', 'GET', selfSigned);
    const id = ac.ok && Array.isArray(ac.json) && ac.json[0] && ac.json[0].id;
    if (!id) return { ok: false, res: ac };
    const sm = await gwRequest(gw, `/portfolio/${encodeURIComponent(id)}/summary`, 'GET', selfSigned);
    const g = (k) => sm.json && sm.json[k] && num(sm.json[k].amount);
    return { ok: true, sum: summary({ accountNumber: id, status: 'ACTIVE', currency: (sm.json && sm.json.netliquidation && sm.json.netliquidation.currency) || null, cash: str(g('totalcashvalue')), buyingPower: str(g('buyingpower') !== null ? g('buyingpower') : g('availablefunds')), equity: str(g('netliquidation')), mode: /^DU/.test(id) ? 'paper' : 'live', note: 'Reads through your own Client Portal Gateway. It must stay logged in and reachable from this server.' }) };
  }
  BrokerAdapters.ibkr = {
    id: 'ibkr', name: 'Interactive Brokers', requiredFields: ['gatewayUrl'], supportsAutomatedExecution: false, canTestOrder: false,
    async connect(body) {
      let gw = String(body.gatewayUrl || '').trim().replace(/\/+$/, '').replace(/\/v1\/api$/, '');
      const self = body.allowSelfSigned === true || body.allowSelfSigned === 'true' || body.allowSelfSigned === 'on';
      try {
        const r = await ibkrSummary(gw, self);
        if (!r.ok) {
          if (r.notAuthed) return fail(400, 'The gateway is reachable but not logged in. Sign in to the Client Portal Gateway in a browser, then try again.');
          return fail(502, 'The gateway did not return account data.', clip(r.res && r.res.text));
        }
        return { ok: true, credsForStorage: { primary: gw, secretPlain: JSON.stringify({ self }), baseUrl: gw }, accountSummary: r.sum };
      } catch (e) {
        if (e.status) return fail(e.status, e.message);
        return fail(502, /self[- ]signed|certificate|CERT/i.test(e.message) ? 'The gateway uses a self-signed certificate. Tick "Allow self-signed certificate" if you trust it.' : 'Could not reach the gateway: ' + clip(e.message, 120));
      }
    },
    async fetchAccount(creds) {
      let self = false; try { self = !!JSON.parse(creds.secretPlain).self; } catch (e) { /* default */ }
      try { const r = await ibkrSummary(creds.baseUrl, self); return r.ok ? { ok: true, accountSummary: r.sum } : fail(502, 'The IBKR gateway is not logged in or not reachable.'); }
      catch (e) { return fail(502, 'Could not reach the IBKR gateway.'); }
    },
    async placeTestOrder() { return fail(501, 'IBKR orders need interactive confirmation inside the gateway, so no test order is sent from here.'); },
  };

  // ------------------------------------------------------------------- OAuth
  // Each OAuth broker needs a developer app registered with the provider. The redirect
  // URI to register is  APP_BASE_URL + /api/oauth/callback/<broker>.
  const OAUTH = {
    saxo: {
      name: 'Saxo Bank', idEnv: 'SAXO_APP_KEY', secretEnv: 'SAXO_APP_SECRET', sandbox: (env.SAXO_ENV || 'sim') !== 'live',
      authUrl: () => env.SAXO_AUTH_URL || ((env.SAXO_ENV || 'sim') === 'live' ? 'https://live.logonvalidation.net/authorize' : 'https://sim.logonvalidation.net/authorize'),
      tokenUrl: () => env.SAXO_TOKEN_URL || ((env.SAXO_ENV || 'sim') === 'live' ? 'https://live.logonvalidation.net/token' : 'https://sim.logonvalidation.net/token'),
      apiBase: () => env.SAXO_API_BASE || ((env.SAXO_ENV || 'sim') === 'live' ? 'https://gateway.saxobank.com/openapi' : 'https://gateway.saxobank.com/sim/openapi'),
      authExtra: () => ({}), tokenAuth: 'body',
    },
    schwab: {
      name: 'Charles Schwab', idEnv: 'SCHWAB_APP_KEY', secretEnv: 'SCHWAB_APP_SECRET', sandbox: false,
      authUrl: () => env.SCHWAB_AUTH_URL || 'https://api.schwabapi.com/v1/oauth/authorize',
      tokenUrl: () => env.SCHWAB_TOKEN_URL || 'https://api.schwabapi.com/v1/oauth/token',
      apiBase: () => env.SCHWAB_API_BASE || 'https://api.schwabapi.com/trader/v1',
      authExtra: () => ({}), tokenAuth: 'basic',
    },
    tradestation: {
      name: 'TradeStation', idEnv: 'TRADESTATION_APP_KEY', secretEnv: 'TRADESTATION_APP_SECRET', sandbox: (env.TRADESTATION_ENV || 'sim') !== 'live',
      authUrl: () => env.TRADESTATION_AUTH_URL || 'https://signin.tradestation.com/authorize',
      tokenUrl: () => env.TRADESTATION_TOKEN_URL || 'https://signin.tradestation.com/oauth/token',
      apiBase: () => env.TRADESTATION_API_BASE || ((env.TRADESTATION_ENV || 'sim') === 'live' ? 'https://api.tradestation.com/v3' : 'https://sim-api.tradestation.com/v3'),
      authExtra: () => ({ audience: 'https://api.tradestation.com', scope: 'openid offline_access profile MarketData ReadAccount Trade' }), tokenAuth: 'body',
    },
  };
  const redirectUri = (id) => `${APP_BASE_URL}/api/oauth/callback/${id}`;
  const oauthConfigured = (id) => !!(env[OAUTH[id].idEnv] && env[OAUTH[id].secretEnv] && APP_BASE_URL);
  const oauthNeeds = (id) => [OAUTH[id].idEnv, OAUTH[id].secretEnv].filter(k => !env[k]).concat(APP_BASE_URL ? [] : ['APP_BASE_URL']);

  function signState(obj) {
    const body = b64u(Object.assign({ n: crypto.randomBytes(8).toString('hex'), exp: Date.now() + 10 * 60000 }, obj));
    const mac = crypto.createHmac('sha256', Buffer.from(env.ENCRYPTION_KEY || 'k', 'utf8')).update(body).digest('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    return body + '.' + mac;
  }
  function readState(s) {
    const [body, mac] = String(s || '').split('.');
    if (!body || !mac) return null;
    const want = crypto.createHmac('sha256', Buffer.from(env.ENCRYPTION_KEY || 'k', 'utf8')).update(body).digest('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    if (want.length !== mac.length || !crypto.timingSafeEqual(Buffer.from(want), Buffer.from(mac))) return null;
    try { const o = JSON.parse(Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()); return o.exp > Date.now() ? o : null; } catch (e) { return null; }
  }
  async function tokenRequest(id, form) {
    const cfg = OAUTH[id], cid = env[cfg.idEnv], sec = env[cfg.secretEnv];
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
    const f = Object.assign({}, form);
    if (cfg.tokenAuth === 'basic') headers.Authorization = 'Basic ' + Buffer.from(`${cid}:${sec}`).toString('base64'); else { f.client_id = cid; f.client_secret = sec; }
    return http(cfg.tokenUrl(), { method: 'POST', headers, body: new URLSearchParams(f).toString() });
  }
  function pack(tok, prev) { return { access: tok.access_token, refresh: tok.refresh_token || (prev && prev.refresh) || null, exp: Date.now() + (num(tok.expires_in) || 1200) * 1000 }; }
  async function accessToken(id, creds) {
    let t; try { t = JSON.parse(creds.secretPlain); } catch (e) { return { err: 'Stored sign-in is unreadable. Disconnect and sign in again.' }; }
    if (t.exp - 60000 > Date.now()) return { token: t.access };
    if (!t.refresh) return { err: `${OAUTH[id].name} sign-in expired. Sign in again.` };
    const r = await tokenRequest(id, { grant_type: 'refresh_token', refresh_token: t.refresh });
    if (!r.ok || !r.json || !r.json.access_token) return { err: `${OAUTH[id].name} sign-in expired. Sign in again.` };
    const np = pack(r.json, t);
    if (creds.username) await pool.query('UPDATE broker_credentials SET api_secret_enc=$3 WHERE username=$1 AND broker=$2', [creds.username, id, encryptSecret(JSON.stringify(np))]);
    return { token: np.access };
  }
  const bearer = (t) => ({ Authorization: 'Bearer ' + t, Accept: 'application/json' });

  const oauthAccount = {
    async saxo(base, tok, mode) {
      const [b, a] = await Promise.all([http(base + '/port/v1/balances/me', { headers: bearer(tok) }), http(base + '/port/v1/accounts/me', { headers: bearer(tok) })]);
      if (!b.ok) return { ok: false, res: b };
      const acc = a.ok && a.json && a.json.Data && a.json.Data[0];
      const j = b.json || {};
      return { ok: true, sum: summary({ accountNumber: acc && (acc.AccountId || acc.AccountKey), status: 'ACTIVE', currency: j.Currency, cash: str(j.CashBalance), buyingPower: str(j.MarginAvailableForTrading !== undefined ? j.MarginAvailableForTrading : j.CashBalance), equity: str(j.TotalValue), mode, accountKey: acc && acc.AccountKey }), accountKey: acc && acc.AccountKey };
    },
    async schwab(base, tok) {
      const r = await http(base + '/accounts', { headers: bearer(tok) });
      if (!r.ok) return { ok: false, res: r };
      const s = Array.isArray(r.json) && r.json[0] && r.json[0].securitiesAccount;
      if (!s) return { ok: false, res: r };
      const c = s.currentBalances || {};
      return { ok: true, sum: summary({ accountNumber: s.accountNumber, status: 'ACTIVE', currency: 'USD', cash: str(c.cashBalance), buyingPower: str(c.buyingPower !== undefined ? c.buyingPower : c.availableFunds), equity: str(c.liquidationValue), mode: 'live', note: 'Schwab has no paper environment, so this is your real account.' }) };
    },
    async tradestation(base, tok, mode) {
      const a = await http(base + '/brokerage/accounts', { headers: bearer(tok) });
      if (!a.ok) return { ok: false, res: a };
      const acc = a.json && a.json.Accounts && a.json.Accounts[0];
      if (!acc) return { ok: false, res: a };
      const b = await http(base + '/brokerage/accounts/' + encodeURIComponent(acc.AccountID) + '/balances', { headers: bearer(tok) });
      const bal = b.ok && b.json && b.json.Balances && b.json.Balances[0] || {};
      return { ok: true, sum: summary({ accountNumber: acc.AccountID, status: acc.Status || 'ACTIVE', currency: acc.Currency, cash: str(bal.CashBalance), buyingPower: str(bal.BuyingPower), equity: str(bal.Equity), mode }), accountId: acc.AccountID };
    },
  };

  Object.keys(OAUTH).forEach((id) => {
    const cfg = OAUTH[id];
    const mode = cfg.sandbox ? 'paper' : 'live';
    BrokerAdapters[id] = {
      id, name: cfg.name, oauth: true, requiredFields: [], supportsAutomatedExecution: false, canTestOrder: id === 'saxo' || id === 'tradestation',
      async connect() { return fail(400, `${cfg.name} connects through a sign-in window. Use the Sign in button.`); },
      async fetchAccount(creds) {
        const t = await accessToken(id, creds);
        if (t.err) return fail(401, t.err);
        const r = await oauthAccount[id](cfg.apiBase(), t.token, mode);
        return r.ok ? { ok: true, accountSummary: r.sum } : fail(502, `Could not fetch the account from ${cfg.name}.`);
      },
      async placeTestOrder(creds) {
        const t = await accessToken(id, creds);
        if (t.err) return fail(401, t.err);
        const acct = await oauthAccount[id](cfg.apiBase(), t.token, mode);
        if (!acct.ok) return fail(502, `Could not read the ${cfg.name} account.`);
        if (id === 'saxo') {
          const r = await http(cfg.apiBase() + '/trade/v2/orders/precheck', { method: 'POST', headers: Object.assign({ 'Content-Type': 'application/json' }, bearer(t.token)), body: JSON.stringify({ AccountKey: acct.accountKey, Amount: 1000, AssetType: 'FxSpot', BuySell: 'Buy', OrderType: 'Market', Uic: 21, ManualOrder: true, OrderDuration: { DurationType: 'DayOrder' } }) });
          if (!r.ok) return fail(400, (r.json && r.json.Message) || 'Saxo rejected the order precheck.', r.json);
          return { ok: true, result: { order: { validated: true, executed: false, note: 'Saxo prechecked a 1,000 EUR/USD market order. Nothing was placed.' } } };
        }
        const r = await http(cfg.apiBase() + '/orderexecution/orderconfirm', { method: 'POST', headers: Object.assign({ 'Content-Type': 'application/json' }, bearer(t.token)), body: JSON.stringify({ AccountID: acct.accountId, Symbol: 'AAPL', Quantity: '1', OrderType: 'Market', TradeAction: 'BUY', TimeInForce: { Duration: 'DAY' }, Route: 'Intelligent' }) });
        if (!r.ok) return fail(400, (r.json && (r.json.Message || r.json.error)) || 'TradeStation rejected the order confirmation.', r.json);
        return { ok: true, result: { order: { validated: true, executed: false, note: 'TradeStation confirmed a 1-share AAPL market order. Nothing was placed.' } } };
      },
    };
  });


  // ------------------------------------------------- Alpaca "Sign in with Alpaca"
  // Alpaca Connect (OAuth). Optional: users can still paste their own API keys. Needs a
  // registered Alpaca app (Client ID + Secret) and the redirect URI
  //   APP_BASE_URL + /api/oauth/callback/alpaca
  // whitelisted in that app. The token is stored like an API key with api_key_id='oauth'.
  const ALP = {
    idEnv: 'ALPACA_APP_KEY', secretEnv: 'ALPACA_APP_SECRET',
    authUrl: env.ALPACA_AUTH_URL || 'https://app.alpaca.markets/oauth/authorize',
    tokenUrl: env.ALPACA_TOKEN_URL || 'https://api.alpaca.markets/oauth/token',
    base: { paper: (env.ALPACA_PAPER_BASE || 'https://paper-api.alpaca.markets').replace(/\/$/, ''), live: (env.ALPACA_LIVE_BASE || 'https://api.alpaca.markets').replace(/\/$/, '') },
  };
  const alpConfigured = () => !!(env[ALP.idEnv] && env[ALP.secretEnv] && APP_BASE_URL);
  const alpNeeds = () => [ALP.idEnv, ALP.secretEnv].filter(k => !env[k]).concat(APP_BASE_URL ? [] : ['APP_BASE_URL']);
  app.get('/api/broker/alpaca/oauth/start', requireAuth, (req, res) => {
    if (!alpConfigured()) return res.status(503).json({ error: `Sign in with Alpaca is not set up on this server yet. Whoever runs this VaticTrader needs to set ${alpNeeds().join(', ')}.`, needs: alpNeeds(), redirectUri: APP_BASE_URL ? redirectUri('alpaca') : null });
    const mode = req.query.mode === 'live' ? 'live' : 'paper';
    const q = { response_type: 'code', client_id: env[ALP.idEnv], redirect_uri: redirectUri('alpaca'), state: signState({ u: req.username, b: 'alpaca', m: mode }), scope: 'account:write trading data', env: mode };
    res.json({ url: ALP.authUrl + '?' + new URLSearchParams(q).toString(), redirectUri: redirectUri('alpaca'), sandbox: mode === 'paper' });
  });
  app.get('/api/oauth/callback/alpaca', async (req, res) => {
    const back = (q) => res.redirect('/?' + new URLSearchParams(q).toString() + '#broker');
    if (req.query.error) return back({ broker_error: 'alpaca', why: clip(req.query.error_description || req.query.error, 120) });
    const st = readState(req.query.state);
    if (!st || st.b !== 'alpaca' || !req.query.code || !alpConfigured()) return back({ broker_error: 'alpaca', why: 'The sign-in expired or was not started here. Try again.' });
    try {
      const mode = st.m === 'live' ? 'live' : 'paper';
      const r = await http(ALP.tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
        body: new URLSearchParams({ grant_type: 'authorization_code', code: String(req.query.code), client_id: env[ALP.idEnv], client_secret: env[ALP.secretEnv], redirect_uri: redirectUri('alpaca') }).toString() });
      if (!r.ok || !r.json || !r.json.access_token) return back({ broker_error: 'alpaca', why: 'Alpaca did not accept the sign-in code.' });
      const token = String(r.json.access_token), base = ALP.base[mode];
      const a = await http(base + '/v2/account', { headers: { Authorization: 'Bearer ' + token, Accept: 'application/json' } });
      if (!a.ok) return back({ broker_error: 'alpaca', why: `Signed in, but Alpaca would not return a ${mode} account. Check that you approved a ${mode} account.` });
      await pool.query(
        `INSERT INTO broker_credentials (username, broker, api_key_id, api_secret_enc, base_url, connected_at) VALUES ($1,$2,$3,$4,$5,now())
         ON CONFLICT (username, broker) DO UPDATE SET api_key_id=EXCLUDED.api_key_id, api_secret_enc=EXCLUDED.api_secret_enc, base_url=EXCLUDED.base_url, connected_at=now()`,
        [st.u, 'alpaca', 'oauth', encryptSecret(token), base]);
      back({ broker_connected: 'alpaca' });
    } catch (e) {
      console.error('alpaca oauth callback error:', e.message);
      back({ broker_error: 'alpaca', why: 'Could not complete the sign-in. Try again.' });
    }
  });

  app.get('/api/broker/:id/oauth/start', requireAuth, (req, res) => {
    const id = req.params.id, cfg = OAUTH[id];
    if (!cfg) return res.status(404).json({ error: 'That broker does not use a sign-in window.' });
    if (!oauthConfigured(id)) return res.status(503).json({ error: `${cfg.name} sign-in is not set up on this server yet. Whoever runs this VaticTrader needs to register a ${cfg.name} developer app and set ${oauthNeeds(id).join(', ')}.`, needs: oauthNeeds(id), redirectUri: APP_BASE_URL ? redirectUri(id) : null });
    const q = Object.assign({ response_type: 'code', client_id: env[cfg.idEnv], redirect_uri: redirectUri(id), state: signState({ u: req.username, b: id }) }, cfg.authExtra());
    res.json({ url: cfg.authUrl() + '?' + new URLSearchParams(q).toString(), redirectUri: redirectUri(id), sandbox: cfg.sandbox });
  });

  app.get('/api/oauth/callback/:id', async (req, res) => {
    const id = req.params.id, cfg = OAUTH[id];
    const back = (q) => res.redirect('/?' + new URLSearchParams(q).toString() + '#broker');
    if (!cfg) return res.status(404).send('Unknown broker');
    if (req.query.error) return back({ broker_error: id, why: clip(req.query.error_description || req.query.error, 120) });
    const st = readState(req.query.state);
    if (!st || st.b !== id || !req.query.code) return back({ broker_error: id, why: 'The sign-in expired or was not started here. Try again.' });
    try {
      let code = String(req.query.code); try { code = decodeURIComponent(code); } catch (e) { /* keep raw */ }
      const r = await tokenRequest(id, { grant_type: 'authorization_code', code, redirect_uri: redirectUri(id) });
      if (!r.ok || !r.json || !r.json.access_token) return back({ broker_error: id, why: `${cfg.name} did not accept the sign-in code.` });
      const tok = pack(r.json);
      const acct = await oauthAccount[id](cfg.apiBase(), tok.access, cfg.sandbox ? 'paper' : 'live');
      if (!acct.ok) return back({ broker_error: id, why: `Signed in, but ${cfg.name} would not return account data.` });
      await pool.query(
        `INSERT INTO broker_credentials (username, broker, api_key_id, api_secret_enc, base_url, connected_at) VALUES ($1,$2,$3,$4,$5,now())
         ON CONFLICT (username, broker) DO UPDATE SET api_key_id=EXCLUDED.api_key_id, api_secret_enc=EXCLUDED.api_secret_enc, base_url=EXCLUDED.base_url, connected_at=now()`,
        [st.u, id, 'oauth', encryptSecret(JSON.stringify(tok)), cfg.apiBase()]);
      back({ broker_connected: id });
    } catch (e) {
      console.error(`${id} oauth callback error:`, e.message);
      back({ broker_error: id, why: 'Could not complete the sign-in. Try again.' });
    }
  });

  // What this server can do right now, so the app can say so instead of failing at click time.
  const KINDS = { binance: 'keys', kraken: 'keys', coinbase: 'keys', trading212: 'keys', ig: 'keys', ibkr: 'gateway', saxo: 'oauth', schwab: 'oauth', tradestation: 'oauth' };
  app.get('/api/brokers/capabilities', requireAuth, (req, res) => {
    const out = {};
    Object.keys(KINDS).forEach((id) => {
      const a = BrokerAdapters[id];
      out[id] = { kind: KINDS[id], configured: KINDS[id] === 'oauth' ? oauthConfigured(id) : true, needs: KINDS[id] === 'oauth' ? oauthNeeds(id) : [], redirectUri: KINDS[id] === 'oauth' && APP_BASE_URL ? redirectUri(id) : null, canTestOrder: !!a.canTestOrder, automatedExecution: false };
    });
    out.alpaca = { kind: 'keys', configured: true, needs: [], canTestOrder: true, automatedExecution: true, oauth: { configured: alpConfigured(), needs: alpNeeds(), redirectUri: APP_BASE_URL ? redirectUri('alpaca') : null } };
    out.etoro = { kind: 'keys', configured: true, needs: [], canTestOrder: true, automatedExecution: false };
    res.json({ brokers: out });
  });
};
