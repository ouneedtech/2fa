// Node 22+ SDK and CLI. No packages, no password, no delete operation.
import { pathToFileURL } from 'node:url';
const enc = new TextEncoder(), dec = new TextDecoder();
const hex = b => Buffer.from(b).toString('hex');
function unhex(s, length) {
  if (typeof s !== 'string' || !/^[a-f0-9]+$/.test(s) || s.length%2 || (length && s.length !== length)) throw Error('Invalid hex');
  return Buffer.from(s,'hex');
}
export class VaultAgent {
  constructor(grant, { allowLocalhost = false } = {}) {
    const base = new URL(grant.api_base);
    if (base.username || base.password || base.search || base.hash || base.pathname !== '/' || (base.protocol !== 'https:' && !(allowLocalhost && base.protocol === 'http:' && ['localhost','127.0.0.1'].includes(base.hostname)))) throw Error('Use an HTTPS origin; local HTTP requires allowLocalhost.');
    if (grant.version !== 1 || typeof grant.token !== 'string' || grant.token.length > 256) throw Error('Invalid grant');
    this.base = base.origin; this.token = grant.token;
    this.key = crypto.subtle.importKey('raw',unhex(grant.enc_key,64),'AES-GCM',false,['encrypt','decrypt']);
  }
  async request(path, method = 'GET', data) {
    const response = await fetch(this.base+path, { method, redirect:'error', signal:AbortSignal.timeout(20000), headers:{ Authorization:`Bearer ${this.token}`, ...(data?{'Content-Type':'application/json'}:{}) }, ...(data?{body:JSON.stringify(data)}:{}) });
    const result = await response.json();
    if (!response.ok) throw Object.assign(Error(result.error || `HTTP ${response.status}`),{status:response.status});
    return result;
  }
  async me() { return this.request('/api/me'); }
  async list() {
    const { entries } = await this.request('/api/entries'); const result = [];
    for (const row of entries) {
      const value = JSON.parse(dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:unhex(row.iv,24),additionalData:enc.encode(`still:entry:v1:${row.id}`)},await this.key,unhex(row.ciphertext))));
      result.push({id:row.id,...validate(value)});
    }
    return result;
  }
  async codes() {
    const time = Date.now(), result = [];
    for (const entry of await this.list()) result.push({id:entry.id,label:entry.label,issuer:entry.issuer,code:await otp(entry,time),remaining:entry.period-Math.floor(time/1000)%entry.period});
    return result;
  }
  async add(entry) {
    const value=validate(entry),id=hex(crypto.getRandomValues(new Uint8Array(16))),iv=crypto.getRandomValues(new Uint8Array(12));
    const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:enc.encode(`still:entry:v1:${id}`)},await this.key,enc.encode(JSON.stringify(value)));
    return this.request('/api/entries','POST',{id,iv:hex(iv),ciphertext:hex(ciphertext)});
  }
  async revokeSelf() { return this.request('/api/logout','POST',{}); }
}
export function base32(value) {
  const s=String(value).replace(/\s/g,'').toUpperCase();
  if(!/^[A-Z2-7]+={0,6}$/.test(s))throw Error('Invalid Base32');
  const raw=s.replace(/=+$/,'');if(![0,2,4,5,7].includes(raw.length%8)||(s.includes('=')&&s.length-raw.length!==(8-raw.length%8)%8))throw Error('Invalid Base32');
  let bits=0,v=0;const bytes=[];
  for(const c of raw){v=(v<<5)|'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c);bits+=5;if(bits>=8){bits-=8;bytes.push((v>>>bits)&255);v&=(1<<bits)-1;}}
  if(v||bytes.length<10||bytes.length>256)throw Error('Invalid Base32');return new Uint8Array(bytes);
}
export function validate(entry) {
  const label=String(entry.label||'').trim(),issuer=String(entry.issuer||'').trim(),digits=Number(entry.digits??6),period=Number(entry.period??30),algorithm=entry.algorithm||'SHA1';
  if(!label||label.length>100||issuer.length>100||![6,8].includes(digits)||![30,60].includes(period)||!['SHA1','SHA256','SHA512'].includes(algorithm))throw Error('Invalid entry');
  base32(entry.secret);return{label,issuer,secret:String(entry.secret).replace(/\s|=/g,'').toUpperCase(),digits,period,algorithm};
}
export async function otp(entry,time=Date.now()) {
  const key=await crypto.subtle.importKey('raw',base32(entry.secret),{name:'HMAC',hash:entry.algorithm.replace('SHA','SHA-')},false,['sign']);
  const buffer=new ArrayBuffer(8);new DataView(buffer).setBigUint64(0,BigInt(Math.floor(time/1000/entry.period)));
  const mac=new Uint8Array(await crypto.subtle.sign('HMAC',key,buffer)),o=mac[mac.length-1]&15;
  const n=((mac[o]&127)<<24)|(mac[o+1]<<16)|(mac[o+2]<<8)|mac[o+3];return String(n%10**entry.digits).padStart(entry.digits,'0');
}
async function main() {
  let source='';for await(const chunk of process.stdin){source+=chunk;if(source.length>100000)throw Error('Input too large');}
  const input=JSON.parse(source), agent=new VaultAgent(input.grant,{allowLocalhost:process.argv.includes('--allow-localhost')});
  const command=process.argv[2]||'codes';
  const result=command==='codes'?await agent.codes():command==='me'?await agent.me():command==='add'?await agent.add(input.entry):command==='revoke-self'?await agent.revokeSelf():null;
  if(result===null)throw Error('Commands: codes | me | add | revoke-self');
  process.stdout.write(JSON.stringify(result,null,2)+'\n');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(error=>{console.error(`Agent request failed: ${error.message}`);process.exitCode=1;});
