const { spawn } = require('child_process');
const { Pool } = require('pg');
const B = 'http://127.0.0.1:3300', M = 'http://127.0.0.1:9101';
const sleep = ms => new Promise(r => setTimeout(r, ms));
let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  PASS', m); } else { fail++; console.log('  FAIL', m); } };
async function api(path, o = {}, tok) { const r = await fetch(B + path, { method: o.method || 'GET', headers: { 'Content-Type': 'application/json', ...(tok ? { Authorization: 'Bearer ' + tok } : {}) }, body: o.body ? JSON.stringify(o.body) : undefined }); let j = null; try { j = await r.json(); } catch (e) {} return { s: r.status, j }; }
const mock = (p, b) => fetch(M + p, { method: b ? 'POST' : 'GET', body: b ? JSON.stringify(b) : undefined }).then(r => r.json());
const tick = (price) => mock('/ctl/price', { sym: 'TEST', price });
(async () => {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: false });
  await pool.query('DELETE FROM live_trade_log').catch(() => {});
  const procs = [];
  const m = spawn('node', ['test/mock_alpaca.js'], { stdio: 'inherit' }); procs.push(m);
  const env = { ...process.env, PORT: '3300', ALPACA_BASE_URL: M, ALPACA_DATA_BASE_URL: M, ALPACA_STREAM_URL: 'ws://127.0.0.1:9102/v2', FAST_REFRESH_MS: '1000', LIVE_TICK_INTERVAL_MS: '3600000', PGSSLMODE: 'disable', ENCRYPTION_KEY: 'test-key-123' };
  const sv = spawn('node', ['server.js'], { env, stdio: ['ignore', 'pipe', 'pipe'] }); procs.push(sv);
  let log = ''; sv.stdout.on('data', d => log += d); sv.stderr.on('data', d => log += d);
  const done = async (code) => { procs.forEach(p => p.kill()); await pool.end().catch(() => {}); console.log(`\n${pass} passed, ${fail} failed`); if (fail) console.log('--- server log tail ---\n' + log.slice(-2500)); process.exit(code || (fail ? 1 : 0)); };
  try {
    for (let i = 0; i < 40; i++) { try { const r = await fetch(B + '/api/health'); if (r) break; } catch (e) {} await sleep(500); }
    await sleep(1500);
    const uname = 'fast' + Date.now().toString(36);
    const reg = await api('/api/auth/register', { method: 'POST', body: { username: uname, password: 'secret123' } });
    ok(reg.s === 200 && reg.j.token, 'register user'); const tok = reg.j.token;
    const con = await api('/api/broker/alpaca/connect', { method: 'POST', body: { apiKeyId: 'KEY1', apiSecretKey: 'SECRET1' } }, tok);
    ok(con.s === 200 && con.j.connected, 'connect own Alpaca keys (mock)');
    const raw = await pool.query('SELECT api_secret_enc FROM broker_credentials WHERE username=$1', [uname]);
    ok(raw.rows[0] && !String(raw.rows[0].api_secret_enc).includes('SECRET1'), 'secret is encrypted at rest');
    await pool.query(`INSERT INTO user_settings (username, disclosure_ack_at, disclosure_version) VALUES ($1, now(), '2026-10') ON CONFLICT (username) DO UPDATE SET disclosure_ack_at=now(), disclosure_version='2026-10'`, [uname]);
    const dep = (extra) => api('/api/live/deploy', { method: 'POST', body: { strategyId: 's1', strategyName: 'Fast RSI', symbol: 'TEST', timeframe: '1m', direction: 'long', entryConditions: [{ indicator: 'rsi', operator: 'is above', value: '70', logic: 'AND' }], takeProfit: 5, stopLoss: 5, positionSizePct: 10, trailingStopPct: 1, fastMode: true, ...extra } }, tok);
    const d1 = await dep();
    ok(d1.s === 200, 'deploy with fastMode');
    const st = await api('/api/live/status', {}, tok); ok(st.j.deployments[0].fast_mode === true, 'status reports fast_mode');
    await sleep(3500);
    let fs = await api('/api/fast/status', {}, tok);
    ok(fs.j.state === 'authenticated' && fs.j.symbols.includes('TEST'), 'stream authenticated and subscribed to TEST (' + fs.j.state + ')');
    // A: tick that does not satisfy the rule
    await tick(100); await sleep(1300);
    let ms = await mock('/ctl/state'); ok(ms.orders.length === 0, 'no order on a non-signal tick');
    ok(ms.barsReqs.length > 0 && ms.barsReqs[0].sort === 'desc' && !!ms.barsReqs[0].start, 'bars requested with start + sort=desc');
    // B: single spike that reverts before confirmation -> no order
    await tick(110); await sleep(100); await tick(100); await sleep(1300);
    ms = await mock('/ctl/state'); ok(ms.orders.length === 0, 'one-tick spike that reverts is NOT traded (confirmation guard)');
    // C: sustained signal across two evaluations -> order
    await tick(110); await sleep(1200); await tick(110.2); await sleep(1500);
    ms = await mock('/ctl/state'); ok(ms.orders.length === 1, 'sustained signal places exactly one order (got ' + ms.orders.length + ')');
    const o = ms.orders[0]; ok(o && o.order_class === 'bracket' && o.take_profit && o.stop_loss, 'order is a bracket with TP and SL');
    let d = (await pool.query(`SELECT status, entry_price, trail_peak FROM live_deployments WHERE username=$1`, [uname])).rows[0];
    ok(d.status === 'open', 'deployment is open'); 
    // D: more ticks right away must not create a second order
    for (const p of [110.4, 110.6, 110.8]) { await tick(p); await sleep(150); }
    await sleep(1200); ms = await mock('/ctl/state'); ok(ms.orders.length === 1, 'no duplicate orders on further ticks');
    // E: trailing stop on streamed ticks: peak 113 then fall to 111.5 (>1% below 113 => trigger 111.87)
    await tick(112); await sleep(1100); await tick(113); await sleep(1100);
    d = (await pool.query(`SELECT trail_peak FROM live_deployments WHERE username=$1`, [uname])).rows[0]; ok(Math.abs(parseFloat(d.trail_peak) - 113) < 0.01, 'trail peak follows the stream (' + d.trail_peak + ')');
    await tick(111.5); await sleep(1500);
    ms = await mock('/ctl/state'); ok(ms.closed.length === 1, 'trailing stop closed the position at the broker (bracket legs were holding the shares)'); ok(ms.delLog && ms.delLog.length >= 2, 'bracket legs were cancelled to release shares (' + (ms.delLog||[]).length + ')');
    d = (await pool.query(`SELECT status FROM live_deployments WHERE username=$1`, [uname])).rows[0]; ok(d.status === 'closed', 'deployment closed');
    const tl = (await pool.query(`SELECT close_reason, status FROM live_trade_log WHERE username=$1`, [uname])).rows[0]; ok(tl && tl.close_reason === 'trailing_stop', 'trade log reason = trailing_stop');
    // F: reconnect after the socket drops
    await api('/api/live/deploy', { method: 'POST', body: { strategyId: 's1', strategyName: 'Fast RSI', symbol: 'TEST', timeframe: '1m', direction: 'long', entryConditions: [{ indicator: 'rsi', operator: 'is above', value: '70', logic: 'AND' }], takeProfit: 5, stopLoss: 5, positionSizePct: 10, fastMode: true } }, tok);
    await sleep(1500); await mock('/ctl/drop', {}); await sleep(300);
    fs = await api('/api/fast/status', {}, tok); ok(fs.j.state !== 'authenticated', 'state leaves authenticated after drop (' + fs.j.state + ')');
    await sleep(4500); fs = await api('/api/fast/status', {}, tok); ok(fs.j.state === 'authenticated', 'reconnects and re-authenticates (' + fs.j.state + ')');
    // G: non-fast deployment is not streamed
    await api('/api/live/deploy', { method: 'POST', body: { strategyId: 's1', strategyName: 'Slow', symbol: 'TEST', timeframe: '1m', direction: 'long', entryConditions: [{ indicator: 'rsi', operator: 'is above', value: '70', logic: 'AND' }], takeProfit: 5, stopLoss: 5, positionSizePct: 10, fastMode: false } }, tok);
    await sleep(2500); fs = await api('/api/fast/status', {}, tok); ok(fs.j.state === 'off', 'turning Fast mode off closes the stream (' + fs.j.state + ')');
    // H: second user hits Alpaca's one-connection limit
    const u2 = 'fast2' + Date.now().toString(36);
    const r2 = await api('/api/auth/register', { method: 'POST', body: { username: u2, password: 'secret123' } }); const t2 = r2.j.token;
    await api('/api/broker/alpaca/connect', { method: 'POST', body: { apiKeyId: 'KEY2', apiSecretKey: 'S2' } }, t2);
    await pool.query(`INSERT INTO user_settings (username, disclosure_ack_at, disclosure_version) VALUES ($1, now(), '2026-10') ON CONFLICT (username) DO UPDATE SET disclosure_ack_at=now(), disclosure_version='2026-10'`, [u2]);
    await mock('/ctl/limit', { key: 'KEY2' });
    await api('/api/live/deploy', { method: 'POST', body: { strategyId: 'x', strategyName: 'X', symbol: 'TEST', timeframe: '1m', direction: 'long', entryConditions: [{ indicator: 'rsi', operator: 'is above', value: '70', logic: 'AND' }], takeProfit: 5, stopLoss: 5, positionSizePct: 10, fastMode: true } }, t2);
    await sleep(3000); const f2 = await api('/api/fast/status', {}, t2);
    ok(f2.j.state === 'error' && /one data connection/.test(f2.j.error || ''), 'connection-limit error is surfaced to the user (' + f2.j.state + ')');
    ok(f2.s === 200 && (await api('/api/fast/status', {}, tok)).j.state === 'off', 'users are isolated');
    await done(0);
  } catch (e) { console.log('TEST ERROR', e); fail++; await done(1); }
})();
