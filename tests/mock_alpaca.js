// Local mock of Alpaca REST + data WebSocket. Synthetic prices only. Not the real service.
const http = require('http');
const { WebSocketServer } = require('ws');
const S = { price: { TEST: 100 }, positions: {}, orders: [], closed: [], seq: 1, barsReqs: [], sockets: new Set(), authLog: [], rejectKeys: new Set(), limitKeys: new Set() };
function bars(sym) {
  // flat zig-zag history so RSI is mid-range until a tick pushes it
  const out = []; const now = Date.now();
  for (let i = 0; i < 200; i++) { const c = 100 + (i % 2 ? 0.5 : -0.5); out.push({ t: new Date(now - (200 - i) * 60000).toISOString(), o: c, h: c + 0.3, l: c - 0.3, c, v: 1000 }); }
  const last = out[out.length - 1], px = S.price[sym]; if (px && px !== 100) { last.c = px; last.h = Math.max(last.h, px); last.l = Math.min(last.l, px); }
  return out;
}
const srv = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x'); const p = u.pathname;
  let body = ''; req.on('data', d => body += d); req.on('end', () => {
    const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
    const key = req.headers['apca-api-key-id'];
    if (p.startsWith('/ctl/')) {
      if (p === '/ctl/state') return send(200, { orders: S.orders, closed: S.closed, positions: S.positions, barsReqs: S.barsReqs, authLog: S.authLog });
      if (p === '/ctl/price') { const j = JSON.parse(body); S.price[j.sym] = j.price; for (const w of S.sockets) if (w.subs && w.subs.has(j.sym) && w.authed) w.send(JSON.stringify([{ T: 't', S: j.sym, p: j.price, s: 100, t: new Date().toISOString() }])); return send(200, { ok: true, n: S.sockets.size }); }
      if (p === '/ctl/drop') { for (const w of S.sockets) w.terminate(); return send(200, { ok: true }); }
      if (p === '/ctl/limit') { const j = JSON.parse(body); S.limitKeys.add(j.key); return send(200, {}); }
      if (p === '/ctl/reset') { S.orders = []; S.closed = []; S.positions = {}; return send(200, {}); }
    }
    if (p === '/v2/account') return send(200, { account_number: 'MOCK1', status: 'ACTIVE', currency: 'USD', cash: '100000', buying_power: '200000', portfolio_value: '100000', equity: '100000', last_equity: '100000', trading_blocked: false, multiplier: '2' });
    let m;
    if ((m = p.match(/^\/v2\/stocks\/([^/]+)\/bars$/))) {
      S.barsReqs.push(Object.fromEntries(u.searchParams));
      let b = bars(m[1]); if (u.searchParams.get('sort') === 'desc') b = b.reverse();
      return send(200, { bars: b.slice(0, parseInt(u.searchParams.get('limit') || '1000', 10)) });
    }
    if (p === '/v2/orders' && req.method === 'POST') {
      const o = JSON.parse(body); const id = 'ord-' + (S.seq++); const px = S.price[o.symbol];
      S.orders.push({ id, ...o, fill: px }); S.positions[o.symbol] = { symbol: o.symbol, qty: o.qty, side: o.side, avg_entry_price: String(px), current_price: String(px) };
      return send(200, { id, status: 'accepted' });
    }
    if (p === '/v2/orders') return send(200, S.closed);
    if ((m = p.match(/^\/v2\/positions\/([^/]+)$/))) {
      const sym = m[1];
      if (req.method === 'DELETE') { if (!S.positions[sym]) return send(404, { message: 'position does not exist' }); const id = 'ord-' + (S.seq++); S.closed.unshift({ id, status: 'filled', filled_avg_price: String(S.price[sym]), symbol: sym }); delete S.positions[sym]; return send(200, { id }); }
      if (!S.positions[sym]) return send(404, { message: 'position does not exist' });
      S.positions[sym].current_price = String(S.price[sym]); return send(200, S.positions[sym]);
    }
    send(404, { message: 'mock: no route ' + p });
  });
});
const wss = new WebSocketServer({ port: 9102 });
wss.on('connection', (ws, req) => {
  S.sockets.add(ws); ws.subs = new Set(); ws.authed = false;
  ws.on('close', () => S.sockets.delete(ws));
  ws.send(JSON.stringify([{ T: 'success', msg: 'connected' }]));
  ws.on('message', (d) => {
    const m = JSON.parse(d.toString());
    if (m.action === 'auth') {
      S.authLog.push(m.key);
      if (m.key === 'BADKEY') return ws.send(JSON.stringify([{ T: 'error', code: 402, msg: 'auth failed' }]));
      if (S.limitKeys.has(m.key)) return ws.send(JSON.stringify([{ T: 'error', code: 406, msg: 'connection limit exceeded' }]));
      ws.authed = true; ws.send(JSON.stringify([{ T: 'success', msg: 'authenticated' }]));
    } else if (m.action === 'subscribe') { (m.trades || []).forEach(s => ws.subs.add(s)); ws.send(JSON.stringify([{ T: 'subscription', trades: [...ws.subs] }])); }
    else if (m.action === 'unsubscribe') { (m.trades || []).forEach(s => ws.subs.delete(s)); }
  });
  ws.send = ((o) => (...a) => o(...a))(ws.send.bind(ws));
});
srv.listen(9101, () => console.log('mock up'));
