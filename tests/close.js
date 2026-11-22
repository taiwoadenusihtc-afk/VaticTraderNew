const { spawn } = require('child_process'); const { Pool } = require('pg');
const B='http://127.0.0.1:3301', M='http://127.0.0.1:9101'; const sleep=ms=>new Promise(r=>setTimeout(r,ms));
let pass=0,fail=0; const ok=(c,m)=>{c?pass++:fail++; console.log(c?'  PASS':'  FAIL',m)};
async function api(path,o={},tok){const r=await fetch(B+path,{method:o.method||'GET',headers:{'Content-Type':'application/json',...(tok?{Authorization:'Bearer '+tok}:{})},body:o.body?JSON.stringify(o.body):undefined});return {s:r.status,j:await r.json().catch(()=>({}))};}
const mock=(p,b)=>fetch(M+p,{method:b?'POST':'GET',body:b?JSON.stringify(b):undefined}).then(r=>r.json());
(async()=>{
 const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:false});
 const procs=[]; procs.push(spawn('node',['test/mock_alpaca.js'],{stdio:'inherit'}));
 const env={...process.env,PORT:'3301',ALPACA_BASE_URL:M,ALPACA_DATA_BASE_URL:M,LIVE_TICK_INTERVAL_MS:'3600000',FAST_MODE_ENABLED:'0'};
 const sv=spawn('node',['server.js'],{env,stdio:['ignore','pipe','pipe']}); procs.push(sv); let log=''; sv.stdout.on('data',d=>log+=d); sv.stderr.on('data',d=>log+=d);
 try{
  for(let i=0;i<40;i++){try{await fetch(B+'/api/health');break}catch(e){await sleep(500)}} await sleep(1500);
  const u='cl'+Date.now().toString(36);
  const t=(await api('/api/auth/register',{method:'POST',body:{username:u,password:'secret123'}})).j.token;
  await api('/api/broker/alpaca/connect',{method:'POST',body:{apiKeyId:'K',apiSecretKey:'S'}},t);
  const mk=async(id)=>{ await pool.query(`INSERT INTO live_deployments (username,strategy_id,strategy_name,symbol,timeframe,direction,status,broker,qty,entry_price,entry_order_id,entry_conditions,take_profit_pct,stop_loss_pct,position_size_pct) VALUES ($1,$2,'T','TEST','1m','long','open','alpaca',10,100,'e1','[]',2,1,10) ON CONFLICT DO NOTHING`,[u,id]); };
  await mk('c1');
  await mock('/ctl/seedpos',{sym:'TEST'});
  let r=await api('/api/live/close/c1',{method:'POST'},t);
  ok(r.s===200&&r.j.ok,'manual close succeeds although bracket orders hold the shares ('+r.s+' '+JSON.stringify(r.j).slice(0,120)+')');
  let st=await mock('/ctl/state'); ok(!st.positions.TEST,'position gone at broker'); ok(st.delLog.length>=1,'open orders cancelled first');
  const d=(await pool.query(`SELECT status FROM live_deployments WHERE username=$1 AND strategy_id='c1'`,[u])).rows[0]; ok(d.status==='closed','deployment closed');
  // still-failing case
  await mock('/ctl/stuck',{on:true}); await mock('/ctl/seedpos',{sym:'TEST'}); await pool.query(`UPDATE live_deployments SET status='open' WHERE username=$1`,[u]);
  r=await api('/api/live/close/c1',{method:'POST'},t);
  ok(r.s===422&&/insufficient qty/.test(r.j.error||'')&&/unprotected/.test(r.j.error||''),'rejection shows Alpaca message + unprotected warning ('+r.s+' '+(r.j.error||'').slice(0,140)+')');
  const d2=(await pool.query(`SELECT status,last_error FROM live_deployments WHERE username=$1`,[u])).rows[0]; ok(d2.status==='open'&&/Close failed/.test(d2.last_error||''),'deployment stays open with last_error recorded');
  await mock('/ctl/stuck',{on:false});
  r=await api('/api/portfolio/close-position',{method:'POST',body:{symbol:'TEST'}},t);
  ok(r.s===200&&r.j.ok,'portfolio close works after stuck cleared ('+r.s+' '+JSON.stringify(r.j).slice(0,100)+')');
 }catch(e){fail++;console.log('ERR',e.message)}
 procs.forEach(p=>p.kill()); await pool.end().catch(()=>{}); console.log(`\n${pass} passed, ${fail} failed`); if(fail)console.log(log.slice(-1500)); process.exit(fail?1:0);
})();
