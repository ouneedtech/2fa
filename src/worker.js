const enc = new TextEncoder();
const hex = bytes => [...new Uint8Array(bytes)].map(x => x.toString(16).padStart(2, '0')).join('');
const unhex = s => Uint8Array.from(s.match(/../g) || [], x => parseInt(x, 16));
const random = (n = 32) => hex(crypto.getRandomValues(new Uint8Array(n)));
const now = () => Math.floor(Date.now() / 1000);
const validHex = (s, min, max = min) => typeof s === 'string' && s.length >= min && s.length <= max && s.length % 2 === 0 && /^[a-f0-9]+$/.test(s);
const fail = (status, code) => { throw Object.assign(new Error(code), { status, code }); };
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers } });
const digest = async s => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
async function hmac(secret, value) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, enc.encode(value)));
}
// Fixed length inputs; Web Crypto performs the MAC comparison.
async function equal(a, b) {
  const key = await crypto.subtle.importKey('raw', new Uint8Array(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  const tag = await crypto.subtle.sign('HMAC', key, enc.encode(a));
  return crypto.subtle.verify('HMAC', key, tag, enc.encode(b));
}
async function body(request) {
  if (!request.headers.get('content-type')?.toLowerCase().startsWith('application/json')) fail(415, 'json_required');
  if (Number(request.headers.get('content-length')) > 16384) fail(413, 'too_large');
  const reader = request.body?.getReader();
  if (!reader) fail(400, 'invalid');
  const parts = []; let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > 16384) { await reader.cancel(); fail(413, 'too_large'); }
    parts.push(value);
  }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.length; }
  try { const data = JSON.parse(new TextDecoder().decode(bytes)); if (!data || typeof data !== 'object' || Array.isArray(data)) fail(400, 'invalid'); return data; }
  catch { fail(400, 'invalid'); }
}
function username(s) {
  if (typeof s !== 'string' || !/^[a-zA-Z0-9_.-]{3,48}$/.test(s)) fail(400, 'username_invalid');
  return s.toLowerCase();
}
function registration(b) {
  const name = username(b.username);
  if (!validHex(b.enc_salt, 32) || !validHex(b.auth_key, 64) || !validHex(b.key_check_iv, 24) || !validHex(b.key_check, 64, 512)) fail(400, 'invalid');
  return [random(16), name, b.enc_salt, b.auth_key, b.key_check_iv, b.key_check];
}
const publicUser = row => ({ id: row.id, username: row.username, is_admin: Boolean(row.is_admin), enc_salt: row.enc_salt, key_check_iv: row.key_check_iv, key_check: row.key_check });
function cookie(token, persistent = false, clear = false) {
  return `__Host-vault=${clear ? '' : token}; Path=/; HttpOnly; Secure; SameSite=Strict${clear ? '; Max-Age=0' : persistent ? '; Max-Age=2592000' : ''}`;
}
async function createSession(env, userId, kind, days, canAdd = false) {
  const id = random(); const expires = now() + Math.floor(days * 86400);
  const inserted = await env.DB.prepare(`INSERT INTO sessions(id,user_id,kind,can_add,expires_at,created_at)
    SELECT ?,?,?,?,?,? WHERE ?!='agent' OR
    (SELECT COUNT(*) FROM sessions WHERE user_id=? AND kind='agent' AND expires_at>?)<10`).bind(id, userId, kind, +canAdd, expires, now(), kind, userId, now()).run();
  if (!inserted.meta.changes) fail(409, 'token_limit');
  const payload = `${id}.${expires}.${kind}`;
  return { token: `${payload}.${await hmac(env.SERVER_SECRET, payload)}`, expires_at: expires };
}
async function session(request, env) {
  const authorization = request.headers.get('authorization');
  const bearer = authorization !== null;
  const token = bearer ? authorization.match(/^Bearer (\S+)$/)?.[1] : request.headers.get('cookie')?.match(/(?:^|;\s*)__Host-vault=([^;]+)/)?.[1];
  if (!token || token.length > 256) fail(401, 'unauthorized');
  const [id, expires, kind, signature, extra] = token.split('.');
  if (extra || !validHex(id, 64) || !validHex(signature, 64) || !/^\d{10}$/.test(expires) || +expires <= now() || kind !== (bearer ? 'agent' : 'browser')) fail(401, 'unauthorized');
  if (!await equal(await hmac(env.SERVER_SECRET, `${id}.${expires}.${kind}`), signature)) fail(401, 'unauthorized');
  const row = await env.DB.prepare('SELECT u.*,s.id AS session_id,s.kind,s.can_add,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>? AND s.kind=?').bind(id, now(), kind).first();
  if (!row || row.expires_at !== +expires) fail(401, 'unauthorized');
  return row;
}
const browserOnly = user => { if (user.kind !== 'browser') fail(403, 'agent_forbidden'); };
const adminOnly = user => { browserOnly(user); if (!user.is_admin) fail(403, 'forbidden'); };
// Reserve attempts atomically, including concurrent requests. A fifth reservation locks
// further attempts for five minutes. Successful authentication clears this IP bucket.
async function rate(request, env, bucket, limit) {
  const t = now(); const ip = request.headers.get('cf-connecting-ip') || 'local';
  const key = await hmac(env.SERVER_SECRET, `${bucket}:${ip}`);
  const row = await env.DB.prepare(`INSERT INTO rate_limits(key,attempts,window_start,blocked_until) VALUES(?,1,?,0)
    ON CONFLICT(key) DO UPDATE SET
    attempts=CASE WHEN blocked_until<=? AND window_start<=? THEN 1 ELSE attempts+1 END,
    window_start=CASE WHEN blocked_until<=? AND window_start<=? THEN ? ELSE window_start END,
    blocked_until=CASE WHEN blocked_until>? THEN blocked_until WHEN window_start<=? THEN 0 WHEN attempts+1>=? THEN ? ELSE 0 END
    RETURNING attempts,blocked_until`).bind(key, t, t, t-300, t, t-300, t, t, t-300, limit, t+300).first();
  if (row.attempts > limit) fail(429, 'rate_limited');
  return key;
}
async function route(request, env) {
  const url = new URL(request.url); const path = url.pathname; const method = request.method;
  if (url.protocol !== 'https:' && !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)) fail(400, 'https_required');
  if (!path.startsWith('/api/')) {
    if (!['GET', 'HEAD'].includes(method)) fail(405, 'method_not_allowed');
    if (path !== '/' && path !== '/index.html') fail(404, 'not_found');
    return env.ASSETS.fetch(request);
  }
  if (!env.DB || typeof env.SERVER_SECRET !== 'string' || env.SERVER_SECRET.length < 32) fail(503, 'not_configured');
  // Non-browser clients omit Origin. Browsers must be same origin; no CORS headers.
  const origin = request.headers.get('origin');
  if ((origin && origin !== url.origin) || request.headers.get('sec-fetch-site') === 'cross-site') fail(403, 'origin_forbidden');
  if (method === 'GET' && path === '/api/status') {
    const row = await env.DB.prepare('SELECT id FROM users LIMIT 1').first();
    return json({ setup_required: !row });
  }
  if (method === 'POST' && path === '/api/setup') {
    await rate(request, env, 'setup', 5);
    const b = await body(request);
    if (!env.SETUP_TOKEN || env.SETUP_TOKEN.length < 32) fail(503, 'setup_not_configured');
    if (typeof b.setup_token !== 'string' || b.setup_token.length > 256 || !await equal(b.setup_token, env.SETUP_TOKEN)) fail(403, 'setup_denied');
    const [id, name, salt, auth, iv, check] = registration(b);
    const result = await env.DB.prepare(`INSERT INTO users(id,username,is_admin,enc_salt,auth_verifier,key_check_iv,key_check,created_at)
      SELECT ?,?,1,?,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM users)`).bind(id, name, salt, await digest(auth), iv, check, now()).run();
    if (!result.meta.changes) fail(409, 'setup_complete');
    return json({ ok: true }, 201);
  }
  if (method === 'POST' && path === '/api/challenge') {
    await rate(request, env, 'challenge', 40);
    const b = await body(request); const name = username(b.username);
    const user = await env.DB.prepare('SELECT enc_salt FROM users WHERE username=?').bind(name).first();
    // Stable fake salts make unknown names indistinguishable in the response shape.
    return json({ enc_salt: user?.enc_salt || (await hmac(env.SERVER_SECRET, `salt:${name}`)).slice(0,32), iterations: 600000 });
  }
  if (method === 'POST' && path === '/api/login') {
    const rateKey = await rate(request, env, 'login', 5);
    const b = await body(request); const name = username(b.username);
    if (!validHex(b.auth_key, 64)) fail(400, 'invalid');
    const user = await env.DB.prepare('SELECT * FROM users WHERE username=?').bind(name).first();
    const verifier = user?.auth_verifier || await digest(await hmac(env.SERVER_SECRET, `dummy:${name}`));
    const matches = await equal(await digest(b.auth_key), verifier);
    if (!user || !matches) fail(401, 'format_error');
    // Verify the supplied credential even if an unrelated cookie already exists.
    await env.DB.prepare('DELETE FROM rate_limits WHERE key=?').bind(rateKey).run();
    const { token } = await createSession(env, user.id, 'browser', b.remember === true ? 30 : 1);
    return json(publicUser(user), 200, { 'Set-Cookie': cookie(token, b.remember === true) });
  }
  const user = await session(request, env);
  if (method === 'GET' && path === '/api/me') return json({ ...publicUser(user), access: user.kind, can_add: user.kind === 'browser' || !!user.can_add });
  if (method === 'POST' && path === '/api/logout') {
    await body(request);
    await env.DB.prepare('DELETE FROM sessions WHERE id=?').bind(user.session_id).run();
    return json({ ok: true }, 200, user.kind === 'browser' ? { 'Set-Cookie': cookie('', false, true) } : {});
  }
  if (method === 'GET' && path === '/api/entries') {
    const rows = await env.DB.prepare('SELECT id,iv,ciphertext,created_at FROM entries WHERE user_id=? ORDER BY created_at,id').bind(user.id).all();
    return json({ entries: rows.results });
  }
  if (method === 'POST' && path === '/api/entries') {
    if (user.kind === 'agent' && !user.can_add) fail(403, 'agent_read_only');
    const b = await body(request);
    if (!validHex(b.id, 32) || !validHex(b.iv, 24) || !validHex(b.ciphertext, 34, 8192)) fail(400, 'invalid');
    const result = await env.DB.prepare(`INSERT INTO entries(id,user_id,iv,ciphertext,created_at)
      SELECT ?,?,?,?,? WHERE (SELECT COUNT(*) FROM entries WHERE user_id=?) < 1000
      ON CONFLICT(id) DO NOTHING`).bind(b.id, user.id, b.iv, b.ciphertext, now(), user.id).run();
    if (!result.meta.changes) fail(409, 'entry_conflict');
    return json({ id: b.id }, 201);
  }
  if (method === 'DELETE' && /^\/api\/entries\/[a-f0-9]{32}$/.test(path)) {
    browserOnly(user);
    const result = await env.DB.prepare('DELETE FROM entries WHERE id=? AND user_id=?').bind(path.split('/').pop(), user.id).run();
    if (!result.meta.changes) fail(404, 'not_found');
    return json({ ok: true });
  }
  if (path === '/api/tokens' || path.startsWith('/api/tokens/')) {
    browserOnly(user);
    if (path === '/api/tokens' && method === 'GET') {
      const rows = await env.DB.prepare("SELECT id,can_add,created_at,expires_at FROM sessions WHERE user_id=? AND kind='agent' AND expires_at>? ORDER BY created_at DESC").bind(user.id, now()).all();
      return json({ tokens: rows.results });
    }
    if (path === '/api/tokens' && method === 'POST') {
      const b = await body(request);
      if (!Number.isInteger(b.days) || b.days < 1 || b.days > 30) fail(400, 'invalid');
      return json(await createSession(env, user.id, 'agent', b.days, b.can_add === true), 201);
    }
    if (method === 'DELETE' && /^\/api\/tokens\/[a-f0-9]{64}$/.test(path)) {
      await env.DB.prepare("DELETE FROM sessions WHERE id=? AND user_id=? AND kind='agent'").bind(path.split('/').pop(), user.id).run();
      return json({ ok: true });
    }
  }
  if (path === '/api/users' || path.startsWith('/api/users/')) {
    adminOnly(user);
    if (path === '/api/users' && method === 'GET') {
      const rows = await env.DB.prepare('SELECT id,username,is_admin,created_at FROM users ORDER BY created_at,id').all();
      return json({ users: rows.results });
    }
    if (path === '/api/users' && method === 'POST') {
      const b = await body(request); const [id,name,salt,auth,iv,check] = registration(b);
      const result = await env.DB.prepare(`INSERT INTO users(id,username,is_admin,enc_salt,auth_verifier,key_check_iv,key_check,created_at)
        SELECT ?,?,0,?,?,?,?,? WHERE (SELECT COUNT(*) FROM users)<100 ON CONFLICT(username) DO NOTHING`).bind(id,name,salt,await digest(auth),iv,check,now()).run();
      if (!result.meta.changes) fail(409, 'user_conflict');
      return json({ id }, 201);
    }
    if (method === 'DELETE' && /^\/api\/users\/[a-f0-9]{32}$/.test(path)) {
      const id = path.split('/').pop();
      if (id === user.id) fail(403, 'cannot_delete_self');
      const result = await env.DB.prepare('DELETE FROM users WHERE id=? AND is_admin=0').bind(id).run();
      if (!result.meta.changes) fail(404, 'not_found');
      return json({ ok: true });
    }
  }
  fail(404, 'not_found');
}
function secure(response, api = true) {
  const headers = new Headers(response.headers);
  headers.set('Cache-Control', 'no-store');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Strict-Transport-Security', 'max-age=31536000');
  // Inline script hashes are generated from the delivered HTML, without a build.
  if (api) headers.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
  return new Response(response.body, { status: response.status, headers });
}
export default {
  async fetch(request, env) {
    try {
      let response = await route(request, env);
      if (response.headers.get('content-type')?.includes('text/html')) {
        const html = await response.text(); const hashes = [];
        for (const match of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)) {
          const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(match[1])));
          hashes.push(`'sha256-${btoa(String.fromCharCode(...bytes))}'`);
        }
        const headers = new Headers(response.headers);
        headers.set('Content-Security-Policy', `default-src 'none'; script-src ${hashes.join(' ')}; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'`);
        response = new Response(html, { status: response.status, headers });
        return secure(response, false);
      }
      return secure(response);
    } catch (error) {
      // Never log request bodies, credentials, database errors or secret values.
      return secure(json({ error: error.code || 'internal_error' }, error.status || 500, error.status === 429 ? { 'Retry-After': '300' } : {}));
    }
  },
  async scheduled(_event, env) {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM sessions WHERE expires_at<=?').bind(now()),
      env.DB.prepare('DELETE FROM rate_limits WHERE window_start<? AND blocked_until<?').bind(now()-600, now())
    ]);
  }
};
