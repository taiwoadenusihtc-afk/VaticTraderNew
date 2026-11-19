const M=require('/tmp/claude-0/pbmath.js');let pass=0,fail=0;const ok=(c,m)=>{c?pass++:fail++;console.log(c?'  PASS':'  FAIL',m)};
// 1 projection
let w=M.pbProject([0.9,0.5,-0.2,0.1],0.4);ok(Math.abs(w.reduce((a,b)=>a+b,0)-1)<1e-6&&w.every(x=>x>=-1e-9&&x<=0.4+1e-9),'projection: sums to 1, within [0,cap]: '+w.map(x=>x.toFixed(3)));
// synthetic market: seeded rng
let seed=7;const rnd=()=>{seed=(seed*1664525+1013904223)%4294967296;return seed/4294967296};const gauss=()=>{let u=0,v=0;while(!u)u=rnd();v=rnd();return Math.sqrt(-2*Math.log(u))*Math.cos(2*Math.PI*v)};
function series(drift,vol,n,common,beta){const c=[100];for(let i=1;i<n;i++)c.push(c[i-1]*(1+drift+beta*common[i]+vol*gauss()));return c}
const n=900,common=[0];for(let i=1;i<n;i++)common.push(0.008*gauss());
const closes=[series(0.0006,0.004,n,common,1),series(0.0001,0.012,n,common,1),series(0.0003,0.006,n,common,0.5),series(0.0000,0.003,n,common,0),series(0.0005,0.015,n,common,1.2),series(0.0002,0.009,n,common,0.8)];
const P={lookback:60,rebalDays:5,costBps:10,maxHold:3,maxW:0.5,objective:'sharpe',halfLife:20};
let t0=Date.now();const wf=M.pbWalkForward(closes,P);console.log('  walk-forward ms',Date.now()-t0,'rebalances',wf.rebalances);
ok(wf.curve.length===wf.curveEW.length&&wf.curve.length>400&&wf.curve.every(isFinite),'curves finite and equal length ('+wf.curve.length+')');
ok(wf.avgHoldings<=3.01&&wf.avgHoldings>=1,'never holds more than K assets (avg '+wf.avgHoldings.toFixed(2)+')');
ok(wf.avgTurnover>0&&wf.avgTurnover<2,'turnover sane ('+wf.avgTurnover.toFixed(2)+')');
// no look-ahead: change FUTURE prices only -> earlier curve must be identical
const c2=closes.map(c=>c.slice());for(let i=0;i<c2.length;i++)for(let t=600;t<n;t++)c2[i][t]*=1+0.5*Math.sin(t+i);
const wf2=M.pbWalkForward(c2,P);let same=true;for(let k=0;k<400;k++){if(Math.abs(wf.curve[k]-wf2.curve[k])>1e-9){same=false;break}}ok(same,'no look-ahead: altering prices after day 600 leaves the first 400 curve points unchanged');
// costs reduce result
const wfc=M.pbWalkForward(closes,{...P,costBps:200});ok(wfc.stats.ret<wf.stats.ret,'higher costs lower the result ('+wf.stats.ret.toFixed(3)+' -> '+wfc.stats.ret.toFixed(3)+')');
// minvol gives lower vol than sharpe objective
const wmv=M.pbWalkForward(closes,{...P,objective:'minvol'});ok(wmv.stats.vol<=wf.stats.vol+1e-9,'min-risk goal gives lower or equal volatility ('+wmv.stats.vol.toFixed(3)+' vs '+wf.stats.vol.toFixed(3)+')');
// now + shares
const nw=M.pbNow(closes,P,null);ok(Math.abs(nw.w.reduce((a,b)=>a+b,0)-1)<1e-6&&nw.w.filter(x=>x>0.005).length<=3&&Math.max(...nw.w)<=0.5+1e-6,'current allocation sums to 1, <=3 assets, <= cap: '+nw.w.map(x=>x.toFixed(2)));
const prices=closes.map(c=>c[c.length-1]);const sh=M.pbShares(nw.w,prices,10000);const spent=sh.shares.reduce((a,s,i)=>a+s*prices[i],0);ok(sh.shares.every(Number.isInteger)&&spent<=10000+1e-9&&Math.abs(spent+sh.cash-10000)<1e-6,'whole shares, spend <= capital, cash reconciles (cash $'+sh.cash.toFixed(2)+')');
const tiny=M.pbShares([1,0],[500,10],100);ok(tiny.shares[0]===0&&Math.abs(tiny.cash-100)<1e-9,'cannot afford one share -> stays in cash');
console.log(`\n${pass} passed, ${fail} failed`);process.exit(fail?1:0);
