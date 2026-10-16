// Local, memory-only integration preview. No Cloudflare credentials are read.
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { Readable } from 'node:stream';
import worker from '../src/worker.js';
import { localD1 } from './lib/local-d1.mjs';
const { DB } = localD1();
const env = {
  DB,
  SERVER_SECRET: 'local-preview-only-server-secret-00000000',
  SETUP_TOKEN: 'local-preview-only-setup-token-000000000',
  ASSETS: { async fetch() { return new Response(await readFile(new URL('../public/index.html', import.meta.url)), { headers: { 'Content-Type': 'text/html; charset=utf-8' } }); } }
};
const server = http.createServer(async (req, res) => {
  try {
    const url = `http://127.0.0.1:${server.address().port}${req.url}`;
    const request = new Request(url, { method: req.method, headers: req.headers, ...(['GET','HEAD'].includes(req.method) ? {} : { body: Readable.toWeb(req), duplex: 'half' }) });
    const response = await worker.fetch(request, env);
    res.writeHead(response.status, Object.fromEntries(response.headers));
    if (req.method === 'HEAD') return res.end();
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch { res.writeHead(500); res.end('Preview error'); }
});
server.listen(Number(process.env.PORT || 8788), '127.0.0.1', () => {
  console.log(`Local preview: http://127.0.0.1:${server.address().port}`);
  console.log('Memory-only synthetic environment; resets on restart. Setup token: local-preview-only-setup-token-000000000');
});
