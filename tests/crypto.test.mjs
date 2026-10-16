import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { otp, validate } from '../scripts/agent.mjs';
const html = readFileSync(new URL('../public/index.html',import.meta.url),'utf8');
const code = html.match(/<script id="crypto">([\s\S]*?)<\/script>/)[1];
const context = vm.createContext({crypto,TextEncoder,TextDecoder,URL});
vm.runInContext(code,context);
const C = vm.runInContext('VaultCrypto',context);
const base = {label:'RFC',issuer:'test',digits:8,period:30,algorithm:'SHA1',secret:'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'};
test('browser and Agent agree with every RFC 6238 SHA1/SHA256/SHA512 vector', async()=>{
  const secrets = {
    SHA1:base.secret,
    SHA256:'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA',
    SHA512:'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA'
  };
  const vectors = [[59,'94287082','46119246','90693936'],[1111111109,'07081804','68084774','25091201'],[1111111111,'14050471','67062674','99943326'],[1234567890,'89005924','91819424','93441116'],[2000000000,'69279037','90698825','38618901'],[20000000000,'65353130','77737706','47863826']];
  for(const [time,...codes] of vectors)for(const [i,algorithm]of ['SHA1','SHA256','SHA512'].entries()){
    const entry={...base,algorithm,secret:secrets[algorithm]};
    assert.equal(await C.otp(entry,time*1000),codes[i]);assert.equal(await otp(entry,time*1000),codes[i]);
  }
});
test('PBKDF2 key split, AES-GCM roundtrip, wrong keys and row substitution',async()=>{
  const d=await C.derive('A-very-long-test-passphrase!','00'.repeat(16));
  assert.equal(d.auth_key.length,64);
  const row=await C.encrypt(d.key,base,'row:1');
  assert.equal((await C.decrypt(d.key,row,'row:1')).secret,base.secret);
  await assert.rejects(C.decrypt(d.key,row,'row:2'));
  const other=await C.derive('A-different-password!','00'.repeat(16));
  await assert.rejects(C.decrypt(other.key,row,'row:1'));
  await assert.rejects(C.decrypt(d.key,{...row,ciphertext:'ff'+row.ciphertext.slice(2)},'row:1'));
  assert.notEqual(row.iv,(await C.encrypt(d.key,base,'row:1')).iv);
});
test('strict Base32, URI fallback and plaintext length/algorithm validation',()=>{
  assert.equal(C.base32('jbsw y3dp ehpk 3pxp').secret,'JBSWY3DPEHPK3PXP');
  for(const value of ['abc!','A','AAAAAAAA','MZXW6===','JBSWY3DPEHPK3PXQ='])assert.throws(()=>C.base32(value));
  const entry=C.parseUri('otpauth://totp/Example:alice%40example.com?secret=JBSWY3DPEHPK3PXP&algorithm=UNKNOWN&digits=7&period=15&ignore=x');
  assert.equal(entry.label,'alice@example.com');assert.equal(entry.issuer,'Example');assert.equal(entry.algorithm,'SHA1');assert.equal(entry.digits,6);assert.equal(entry.period,30);
  assert.throws(()=>C.parseUri('otpauth://hotp/X?secret=JBSWY3DPEHPK3PXP'));
  assert.throws(()=>validate({...base,label:''}));assert.throws(()=>validate({...base,algorithm:'MD5'}));
});
