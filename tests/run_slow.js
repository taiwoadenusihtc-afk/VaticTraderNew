const { spawn } = require('child_process'); const { Pool } = require('pg');
const B='http://127.0.0.1:3300', M='http://127.0.0.1:9101'; const sleep=ms=>new Promise(r=>setTimeout(r,ms));
let pass=0,fail=0; const ok=(c,m)=>{c?pass++:fail++;console.log(c?'  PASS':'  FAIL',m)};
async function api(p,o={},t){const r=await fetch(B+p,{method:o.method||'GET',headers:{'Content-Type':'application/json',...(t?{Authorization:'Bearer '+t}:{})},body:o.body?JSON.stringify(o.body):undefined});let j=null;try{j=await r.json()}catch(e){}return{s:r.status,j}}
const mock=(p,b)=>fetch(M+p,{method:b?'POST':'GET',body:b?JSON.stringify(b):undefined}).then(r=>r.json());
(async()=>{
 const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:false});
 const procs=[spawn('node',['test/mock_alpaca.js'],{stdio:'inherit'})];
 const env={...process.env,PORT:'3300',ALPACA_BASE_URL:M,ALPACA_DATA_BASE_URL:M,ALPACA_STREAM_URL:'ws://127.0.0.1:9102/v2',LIVE_TICK_INTERVAL_MS:'2000',PGSSLMODE:'disable',ENCRYPTION_KEY:'test-key-123'};
 const sv=spawn('node',['server.js'],{env,stdio:['ignore','pipe','pipe']});procs.push(sv);let log='';sv.stdout.on('data',d=>log+=d);sv.stderr.on('data',d=>log+=d);
 const done=async()=>{procs.forEach(p=>p.kill());await pool.end().catch(()=>{});console.log(`\n${pass} passed, ${fail} failed`);if(fail)console.log(log.slice(-2000));process.exit(fail?1:0)};
 try{
  await sleep(5000);
  const u='slow'+Date.now().toString(36);const t=(await api('/api/auth/register',{method:'POST',body:{username:u,password:'secret123'}})).j.token;
  await api('/api/broker/alpaca/connect',{method:'POST',body:{apiKeyId:'KEY1',apiSecretKey:'S'}},t);
  await pool.query(`INSERT INTO user_settings (username,disclosure_ack_at,disclosure_version) VALUES ($1,now(),'2026-10') ON CONFLICT (username) DO UPDATE SET disclosure_ack_at=now(),disclosure_version='2026-10'`,[u]);
  await mock('/ctl/price',{sym:'TEST',price:100});
  const body={strategyId:'s',strategyName:'Slow',symbol:'TEST',timeframe:'1m',direction:'long',entryConditions:[{indicator:'rsi',operator:'is above',value:'70',logic:'AND'}],takeProfit:5,stopLoss:5,positionSizePct:10,trailingStopPct:1};
  ok((await api('/api/live/deploy',{method:'POST',body},t)).s===200,'deploy (no fast mode)');
  await sleep(3500);let ms=await mock('/ctl/state');ok(ms.orders.length===0,'poller: no order without signal');
  await mock('/ctl/price',{sym:'TEST',price:110});await sleep(4500);ms=await mock('/ctl/state');console.log(JSON.stringify(ms.orders.map(o=>[o.id,o.fill,o.qty])),JSON.stringify(ms.positions));ok(ms.orders.length===1,'poller: order placed on signal (got '+ms.orders.length+')');
  await sleep(3000);ms=await mock('/ctl/state');ok(ms.orders.length===1,'poller: no duplicate order');
  await mock('/ctl/price',{sym:'TEST',price:112});await sleep(2500);await mock('/ctl/price',{sym:'TEST',price:110});await sleep(2600);
  ms=await mock('/ctl/state');ok(ms.closed.length===1,'poller: trailing stop closes via broker position price');
  const fs=await api('/api/fast/status',{},t);ok(fs.j.state==='off','no stream opened for non-fast user');
 }catch(e){console.log('ERR',e);fail++}
 await done();
})();
