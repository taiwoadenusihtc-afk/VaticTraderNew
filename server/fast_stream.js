'use strict';
/*
 * Fast mode: streaming price feed for live deployments.
 *
 * One Alpaca market-data WebSocket per user (each user brings their own Alpaca
 * keys, and Alpaca's free tier allows one data connection per account, so the
 * app never shares a connection between users or uses a platform key).
 *
 * This module only receives trades and hands them to `onTrade`. All trading
 * decisions, risk limits and order placement stay in server.js (the same code
 * path the slow poller uses), so Fast mode cannot do anything the normal
 * engine cannot.
 *
 * Alpaca data stream protocol (v2): connect -> [{"T":"success","msg":"connected"}],
 * send {"action":"auth","key","secret"} -> [{"T":"success","msg":"authenticated"}],
 * send {"action":"subscribe","trades":[...]} -> [{"T":"subscription",...}],
 * trades arrive as {"T":"t","S":"AAPL","p":123.45,"s":100,"t":"<RFC3339>"}.
 * Errors arrive as {"T":"error","code":N,"msg":"..."} (402 auth failed,
 * 406 connection limit exceeded, 404 auth timeout, 405 symbol limit exceeded).
 */

let WS = null;
let WS_KIND = null;
try { WS = require('ws'); WS_KIND = 'ws'; } catch (e) {
  if (typeof globalThis.WebSocket === 'function') { WS = globalThis.WebSocket; WS_KIND = 'global'; }
}

function createStreamManager(opts) {
  const pool = opts.pool;
  const decryptSecret = opts.decryptSecret;
  const onTrade = opts.onTrade;
  const feed = opts.feed || 'iex';
  const baseUrl = (opts.baseUrl || 'wss://stream.data.alpaca.markets/v2').replace(/\/+$/, '');
  const refreshMs = opts.refreshMs || 10000;
  const maxSymbols = opts.maxSymbols || 30; // Alpaca free tier limit
  const log = opts.log || (() => {});
  const users = new Map(); // username -> conn
  let refreshTimer = null, stopped = false;

  function newConn(username) {
    return { username, ws: null, state: 'idle', want: new Map(), subscribed: new Set(), attempt: 0, retryTimer: null,
      lastTradeAt: 0, trades: 0, error: null, overLimit: [], pingTimer: null, gotPong: true, connectedAt: 0 };
  }

  function send(c, obj) { try { c.ws.send(JSON.stringify(obj)); } catch (e) { /* closed; reconnect logic handles it */ } }

  function syncSubscriptions(c) {
    if (c.state !== 'authenticated') return;
    const want = new Set(c.want.keys());
    const add = [...want].filter(s => !c.subscribed.has(s));
    const del = [...c.subscribed].filter(s => !want.has(s));
    if (add.length) { send(c, { action: 'subscribe', trades: add }); add.forEach(s => c.subscribed.add(s)); }
    if (del.length) { send(c, { action: 'unsubscribe', trades: del }); del.forEach(s => c.subscribed.delete(s)); }
  }

  function scheduleReconnect(c, minDelayMs) {
    if (stopped || c.retryTimer || !users.has(c.username)) return;
    c.attempt++;
    const delay = Math.max(minDelayMs || 0, Math.min(60000, 1000 * Math.pow(2, Math.min(c.attempt, 6))));
    c.retryTimer = setTimeout(() => { c.retryTimer = null; connect(c); }, delay);
    if (c.retryTimer.unref) c.retryTimer.unref();
  }

  function teardownSocket(c) {
    if (c.pingTimer) { clearInterval(c.pingTimer); c.pingTimer = null; }
    const w = c.ws; c.ws = null;
    c.subscribed = new Set();
    if (w) { try { w.onclose = w.onerror = w.onmessage = w.onopen = null; if (WS_KIND === 'ws' && w.removeAllListeners) { w.removeAllListeners(); w.on('error', () => {}); } w.close(); if (w.terminate) w.terminate(); } catch (e) { /* ignore */ } }
  }

  async function connect(c) {
    if (stopped || !users.has(c.username) || c.ws) return;
    if (!WS) { c.state = 'unavailable'; c.error = 'This server has no WebSocket support. Add the "ws" package to enable Fast mode.'; return; }
    let creds;
    try {
      const r = await pool.query('SELECT api_key_id, api_secret_enc FROM broker_credentials WHERE username=$1 AND broker=$2', [c.username, 'alpaca']);
      if (!r.rows.length) { c.state = 'error'; c.error = 'Alpaca is not connected.'; return; }
      creds = { key: r.rows[0].api_key_id, secret: decryptSecret(r.rows[0].api_secret_enc) };
    } catch (e) { c.state = 'error'; c.error = 'Could not read your Alpaca keys.'; scheduleReconnect(c, 30000); return; }
    c.state = 'connecting'; c.error = null;
    let w;
    try { w = new WS(`${baseUrl}/${feed}`); } catch (e) { c.state = 'error'; c.error = 'Could not open the price stream.'; scheduleReconnect(c); return; }
    c.ws = w; c.gotPong = true;
    const onMsg = (raw) => {
      let msgs;
      try { msgs = JSON.parse(typeof raw === 'string' ? raw : (raw && raw.data !== undefined ? String(raw.data) : String(raw))); } catch (e) { return; }
      if (!Array.isArray(msgs)) msgs = [msgs];
      for (const m of msgs) {
        if (!m) continue;
        if (m.T === 't') {
          const p = Number(m.p);
          if (!(p > 0)) continue;
          c.lastTradeAt = Date.now(); c.trades++;
          const ids = c.want.get(m.S);
          if (ids) for (const id of ids) { try { onTrade(id, c.username, m.S, p, m.t); } catch (e) { log('onTrade error', e.message); } }
        } else if (m.T === 'success' && m.msg === 'connected') {
          send(c, { action: 'auth', key: creds.key, secret: creds.secret });
        } else if (m.T === 'success' && m.msg === 'authenticated') {
          c.state = 'authenticated'; c.attempt = 0; c.connectedAt = Date.now(); syncSubscriptions(c);
        } else if (m.T === 'error') {
          c.error = `${m.code}: ${m.msg}`;
          if (m.code === 402 || m.code === 401) { c.state = 'error'; c.error = 'Alpaca rejected your keys for the data stream (' + m.msg + '). Check them under Brokers.'; teardownSocket(c); scheduleReconnect(c, 300000); }
          else if (m.code === 406) { c.state = 'error'; c.error = 'Alpaca allows one data connection per account and one is already open elsewhere (another app, a script or a second browser tab of a tool). Close it and Fast mode will reconnect.'; teardownSocket(c); scheduleReconnect(c, 60000); }
          else if (m.code === 405) { c.state = 'error'; c.error = 'Too many symbols for your Alpaca data plan.'; }
          else if (m.code === 404) { teardownSocket(c); scheduleReconnect(c); }
          log('stream error', c.username, m.code, m.msg);
        }
      }
    };
    const onClose = () => {
      if (c.ws !== w) return;
      teardownSocket(c);
      if (c.state !== 'error') c.state = 'reconnecting';
      scheduleReconnect(c);
    };
    if (WS_KIND === 'ws') {
      w.on('message', (d) => onMsg(d.toString()));
      w.on('close', onClose);
      w.on('error', (e) => { c.error = 'Stream error: ' + (e && e.message ? e.message : 'unknown'); });
      w.on('pong', () => { c.gotPong = true; });
      c.pingTimer = setInterval(() => {
        if (!c.ws) return;
        if (!c.gotPong) { log('stream pong timeout', c.username); try { c.ws.terminate(); } catch (e) { /* ignore */ } return; }
        c.gotPong = false; try { c.ws.ping(); } catch (e) { /* ignore */ }
      }, 20000);
      if (c.pingTimer.unref) c.pingTimer.unref();
    } else {
      w.onmessage = (ev) => onMsg(ev.data);
      w.onclose = onClose;
      w.onerror = () => { c.error = 'Stream error'; };
    }
  }

  async function refresh() {
    if (stopped) return;
    let rows;
    try {
      const r = await pool.query(`SELECT id, username, symbol, status FROM live_deployments WHERE fast_mode=TRUE AND status IN ('watching','open') AND broker='alpaca'`);
      rows = r.rows;
    } catch (e) { log('fast refresh error', e.message); return; }
    const byUser = new Map();
    for (const d of rows) {
      if (!byUser.has(d.username)) byUser.set(d.username, []);
      byUser.get(d.username).push(d);
    }
    for (const [username, deps] of byUser) {
      let c = users.get(username);
      if (!c) { c = newConn(username); users.set(username, c); }
      // Open positions take priority for the symbol limit.
      deps.sort((a, b) => (a.status === 'open' ? 0 : 1) - (b.status === 'open' ? 0 : 1));
      const want = new Map(); c.overLimit = [];
      for (const d of deps) {
        const sym = String(d.symbol).toUpperCase();
        if (!want.has(sym)) { if (want.size >= maxSymbols) { c.overLimit.push(sym); continue; } want.set(sym, []); }
        want.get(sym).push(d.id);
      }
      c.want = want;
      if (c.state === 'authenticated') syncSubscriptions(c);
      else if (!c.ws && !c.retryTimer && c.state !== 'unavailable') connect(c);
    }
    for (const [username, c] of users) {
      if (!byUser.has(username)) { if (c.retryTimer) clearTimeout(c.retryTimer); teardownSocket(c); users.delete(username); }
    }
  }

  function start() { if (refreshTimer) return; refreshTimer = setInterval(() => { refresh(); }, refreshMs); if (refreshTimer.unref) refreshTimer.unref(); refresh(); }
  function stop() { stopped = true; if (refreshTimer) clearInterval(refreshTimer); for (const c of users.values()) { if (c.retryTimer) clearTimeout(c.retryTimer); teardownSocket(c); } users.clear(); }
  function status(username) {
    const c = users.get(username);
    const base = { available: !!WS, feed, maxSymbols };
    if (!c) return { ...base, state: 'off', symbols: [], trades: 0, lastTradeAt: null, error: WS ? null : 'This server has no WebSocket support.' };
    return { ...base, state: c.state, symbols: [...c.want.keys()], overLimit: c.overLimit, trades: c.trades, lastTradeAt: c.lastTradeAt || null, error: c.error };
  }
  return { start, stop, refresh, status, _users: users };
}

module.exports = { createStreamManager, hasWebSocket: () => !!WS };
