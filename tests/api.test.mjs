import { test } from 'node:test';
import assert from 'node:assert/strict';
import { localD1 } from '../scripts/lib/local-d1.mjs';
import worker from '../src/worker.js';
const enc = new TextEncoder();
const digest=async s=>Buffer.from(await crypto.subtle.digest('SHA-256',enc.encode(s))).toString('hex');
function fixture(){
  const {DB,sqlite}=localD1();
  const env={DB,SERVER_SECRET:'synthetic-server-secret-for-tests-000000',SETUP_TOKEN:'synthetic-setup-token-for-tests-000000',ASSETS:{async fetch(){return new Response('<script>const test=1;</script>',{headers:{'Content-Type':'text/html'}});}}};
  let ip=1;
  async function call(path,method='GET',data,headers={}){
    const response=await worker.fetch(new Request('https://vault.example'+path,{method,headers:{'CF-Connecting-IP':'192.0.2.'+ip,...(data?{'Content-Type':'application/json'}:{}),...headers},...(data?{body:JSON.stringify(data)}:{})}),env);
    const result=response.headers.get('content-type').includes('json')?await response.json():await response.text();
    return{status:response.status,headers:response.headers,data:result};
  }
  const nextIp=()=>ip++;
  const reg=(name='admin',seed='a')=>({username:name,enc_salt:seed.repeat(32),auth_key:seed.repeat(64),key_check_iv:'b'.repeat(24),key_check:'c'.repeat(64)});
  async function setup(){const b=reg();assert.equal((await call('/api/setup','POST',{...b,setup_token:env.SETUP_TOKEN})).status,201);return b;}
  async function login(b=reg(),remember=false){const r=await call('/api/login','POST',{username:b.username,auth_key:b.auth_key,remember});assert.equal(r.status,200);return{'Cookie':r.headers.get('set-cookie').split(';')[0]};}
  return{call,env,sqlite,reg,setup,login,nextIp};
}
test('setup guard, one-time initialization and schema never stores auth keys',async()=>{
  const f=fixture();assert.equal((await f.call('/api/status')).data.setup_required,true);
  assert.equal((await f.call('/api/setup','POST',{...f.reg(),setup_token:'wrong'})).status,403);
  const b=await f.setup();const duplicate=await f.call('/api/setup','POST',{...f.reg('attacker'),setup_token:f.env.SETUP_TOKEN});assert.equal(duplicate.status,409);
  assert.equal((await f.call('/api/status')).data.setup_required,false);
  const user=f.sqlite.prepare('SELECT * FROM users').get();assert.equal(user.auth_verifier,await digest(b.auth_key));assert.notEqual(user.auth_verifier,b.auth_key);
});
test('constant response shape, generic bad login, five attempts then lock, secure cookies',async()=>{
  const f=fixture();await f.setup();
  const known=await f.call('/api/challenge','POST',{username:'admin'}),unknown=await f.call('/api/challenge','POST',{username:'nobody'});
  assert.deepEqual(Object.keys(known.data),Object.keys(unknown.data));assert.equal(known.data.enc_salt.length,unknown.data.enc_salt.length);
  for(let i=0;i<5;i++)assert.equal((await f.call('/api/login','POST',{username:i%2?'nobody':'admin',auth_key:'f'.repeat(64)})).status,401);
  assert.equal((await f.call('/api/login','POST',f.reg())).status,429);
  f.nextIp();const r=await f.call('/api/login','POST',{...f.reg(),remember:true});const c=r.headers.get('set-cookie');
  for(const attr of ['__Host-vault=','HttpOnly','Secure','SameSite=Strict','Path=/','Max-Age=2592000'])assert.ok(c.includes(attr));
  f.nextIp();const session=await f.call('/api/login','POST',f.reg());assert.ok(!session.headers.get('set-cookie').includes('Max-Age'));
});
test('tenant isolation, sub-user admin denial, delete own account denial and cascading revocation',async()=>{
  const f=fixture();await f.setup();const admin=await f.login(),alice=f.reg('alice','d');
  const user=await f.call('/api/users','POST',alice,admin);assert.equal(user.status,201);
  const a=await f.login(alice);const row={id:'1'.repeat(32),iv:'2'.repeat(24),ciphertext:'3'.repeat(64)};
  assert.equal((await f.call('/api/entries','POST',row,a)).status,201);
  assert.equal((await f.call('/api/entries','GET',undefined,admin)).data.entries.length,0);
  assert.equal((await f.call('/api/entries/'+row.id,'DELETE',undefined,admin)).status,404);
  for(const method of ['GET','POST','DELETE'])assert.equal((await f.call('/api/users'+(method==='DELETE'?'/'+user.data.id:''),method,method==='POST'?f.reg('other'):undefined,a)).status,403);
  const me=await f.call('/api/me','GET',undefined,admin);assert.equal((await f.call('/api/users/'+me.data.id,'DELETE',undefined,admin)).status,403);
  assert.equal((await f.call('/api/users/'+user.data.id,'DELETE',undefined,admin)).status,200);
  assert.equal((await f.call('/api/me','GET',undefined,a)).status,401);assert.equal(f.sqlite.prepare('SELECT count(*) AS n FROM entries').get().n,0);
});
test('Agent capabilities enforced by server including cookie/bearer type separation',async()=>{
  const f=fixture();await f.setup();const cookie=await f.login();
  const token=await f.call('/api/tokens','POST',{days:7,can_add:false},cookie);assert.equal(token.status,201);
  const headers={Authorization:'Bearer '+token.data.token};
  assert.equal((await f.call('/api/me','GET',undefined,headers)).data.access,'agent');
  assert.equal((await f.call('/api/entries','GET',undefined,headers)).status,200);
  assert.equal((await f.call('/api/entries','POST',{id:'1'.repeat(32),iv:'2'.repeat(24),ciphertext:'3'.repeat(64)},headers)).status,403);
  for(const path of ['/api/entries/'+'1'.repeat(32),'/api/users/'+'1'.repeat(32),'/api/tokens/'+token.data.token.split('.')[0]])assert.equal((await f.call(path,'DELETE',undefined,headers)).status,403);
  for(const path of ['/api/users','/api/tokens'])for(const method of ['GET','POST'])assert.equal((await f.call(path,method,method==='POST'?{days:1}:undefined,headers)).status,403);
  const forgedCookie={Cookie:'__Host-vault='+token.data.token};assert.equal((await f.call('/api/me','GET',undefined,forgedCookie)).status,401);
  assert.equal((await f.call('/api/me','GET',undefined,{Authorization:'Bearer '+cookie.Cookie.split('=')[1]})).status,401);
  const writer=await f.call('/api/tokens','POST',{days:1,can_add:true},cookie),write={Authorization:'Bearer '+writer.data.token};
  assert.equal((await f.call('/api/entries','POST',{id:'1'.repeat(32),iv:'2'.repeat(24),ciphertext:'3'.repeat(64)},write)).status,201);
  assert.equal((await f.call('/api/entries/'+'1'.repeat(32),'DELETE',undefined,write)).status,403);
  assert.equal((await f.call('/api/tokens/'+token.data.token.split('.')[0],'DELETE',undefined,cookie)).status,200);
  assert.equal((await f.call('/api/entries','GET',undefined,headers)).status,401);
  assert.equal((await f.call('/api/logout','POST',{},write)).status,200);assert.equal((await f.call('/api/me','GET',undefined,write)).status,401);
});
test('CSRF, body bounds, invalid ciphertext, session tampering and no credential logging paths',async()=>{
  const f=fixture();await f.setup();const cookie=await f.login();
  assert.equal((await f.call('/api/logout','POST',{}, {...cookie,Origin:'https://attacker.example'})).status,403);
  assert.equal((await f.call('/api/logout','POST',{}, {...cookie,'Sec-Fetch-Site':'cross-site'})).status,403);
  assert.equal((await f.call('/api/login','POST',{x:'x'.repeat(18000)})).status,413);
  assert.equal((await f.call('/api/login','POST',undefined,{'Content-Type':'text/plain'})).status,415);
  assert.equal((await f.call('/api/entries','POST',{iv:'x',ciphertext:'x'},cookie)).status,400);
  const forged={Cookie:cookie.Cookie.slice(0,-1)+(cookie.Cookie.endsWith('f')?'0':'f')};assert.equal((await f.call('/api/me','GET',undefined,forged)).status,401);
  const r=await f.call('/');assert.equal(r.headers.get('x-frame-options'),'DENY');assert.ok(r.headers.get('content-security-policy').includes("script-src 'sha256-"));assert.ok(!r.headers.get('content-security-policy').includes("script-src 'unsafe-inline'"));
  assert.equal((await f.call('/api/logout','POST',{},cookie)).status,200);assert.equal((await f.call('/api/me','GET',undefined,cookie)).status,401);
});
test('expired sessions and old rate rows are pruned by the daily scheduled handler',async()=>{
  const f=fixture();await f.setup();await f.login();f.sqlite.exec('UPDATE sessions SET expires_at=1');
  f.sqlite.exec("INSERT INTO rate_limits VALUES('old',99,1,1)");await worker.scheduled({},f.env);
  assert.equal(f.sqlite.prepare('SELECT count(*) AS n FROM sessions').get().n,0);assert.equal(f.sqlite.prepare("SELECT count(*) AS n FROM rate_limits WHERE key='old'").get().n,0);
});
test('simultaneous token minting cannot bypass the ten-token cap',async()=>{
  const f=fixture();await f.setup();const cookie=await f.login();
  const results=await Promise.all(Array.from({length:16},()=>f.call('/api/tokens','POST',{days:1},cookie)));
  assert.equal(results.filter(r=>r.status===201).length,10);assert.equal(results.filter(r=>r.status===409).length,6);
  assert.equal(f.sqlite.prepare("SELECT count(*) AS n FROM sessions WHERE kind='agent'").get().n,10);
});
