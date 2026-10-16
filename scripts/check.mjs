import fs from 'node:fs';
import vm from 'node:vm';
import { gzipSync } from 'node:zlib';
const html=fs.readFileSync(new URL('../public/index.html',import.meta.url),'utf8');
// All four translations share one row per message: [zh-CN, en, ko, zh-TW].
// Missing translations must fail CI rather than silently display a different language.
if(/<script\b[^>]*\bsrc\s*=/i.test(html))throw Error('External scripts are not allowed.');
const app=html.match(/<script id="app">([\s\S]*?)<\/script>/)[1];
const table=app.match(/const [\w$]+=(\{[\s\S]*?\}),[\w$]+=Object\.fromEntries/);
if(!table)throw Error('Translation table not found.');
const messages=vm.runInNewContext('('+table[1]+')');
for(const[key,values]of Object.entries(messages))if(!Array.isArray(values)||values.length!==4||values.some(value=>typeof value!=='string'||!value.trim()))throw Error('Missing translation: '+key);
console.log(`${Object.keys(messages).length} messages have all four translations.`);
for(const script of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g))new vm.Script(script[1]);
const total=Buffer.byteLength(html);
console.log(`HTML: ${total} bytes; gzip: ${gzipSync(html).length} bytes`);
if(total>=60000)throw Error('The standalone HTML exceeds its 60 KB budget.');
console.log('Inline scripts parse successfully.');
