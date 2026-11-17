// Rooftop Runner accounts: a Cloudflare Worker backed by one KV namespace.
// Setup: create a KV namespace, then bind it to this Worker under the variable name ACCOUNTS.
//
// POST /signup {name, password}          -> {token, name, level, best}
// POST /login  {name, password}          -> {token, name, level, best}
// POST /me     {token}                   -> {name, level, best}
// POST /save   {token, level, best}      -> {level, best}   (only ever moves progress forward)
// POST /logout {token}                   -> {ok}
//
// Passwords are never stored: only a salted PBKDF2 hash. Five wrong passwords lock a name for 10 minutes.

const MAX_LEVEL_INDEX = 11;          // 12 levels, indexed 0-11
const SESSION_TTL = 60 * 60 * 24 * 365; // stay signed in for a year
const LOCK_AFTER = 5, LOCK_SECONDS = 600;
const SIGNUPS_PER_HOUR = 30;          // per network address
const ITER = 100000;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...CORS } });
}
const fail = (error, status = 400) => json({ error }, status);

function cleanName(raw) {
  const name = String(raw || '').trim().replace(/\s+/g, ' ');
  if (name.length < 2 || name.length > 16) return null;
  if (!/^[A-Za-z0-9 ]+$/.test(name)) return null;
  return name;
}
function cleanPassword(raw) {
  const pw = String(raw || '');
  return pw.length >= 4 && pw.length <= 30 ? pw : null;
}
const userKey = name => 'user:' + name.toLowerCase();
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const unhex = s => new Uint8Array(s.match(/../g).map(h => parseInt(h, 16)));

async function hashPassword(pw, saltHex) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unhex(saltHex), iterations: ITER }, key, 256);
  return hex(bits);
}
function sameText(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
async function newSession(env, key) {
  const token = hex(crypto.getRandomValues(new Uint8Array(32)));
  await env.ACCOUNTS.put('sess:' + token, key, { expirationTtl: SESSION_TTL });
  return token;
}
async function userFromToken(env, token) {
  if (!/^[0-9a-f]{64}$/.test(String(token || ''))) return null;
  const key = await env.ACCOUNTS.get('sess:' + token);
  if (!key) return null;
  const user = await env.ACCOUNTS.get(key, 'json');
  return user ? { key, user } : null;
}
const clampLevel = n => Math.max(0, Math.min(MAX_LEVEL_INDEX, Math.floor(Number(n) || 0)));
const clampBest = n => Math.max(0, Math.min(1e7, Math.floor(Number(n) || 0)));

async function signup(body, env, req) {
  const name = cleanName(body.name), pw = cleanPassword(body.password);
  if (!name) return fail('Names need 2-16 letters or numbers.');
  if (!pw) return fail('Passwords need at least 4 characters.');
  const ip = req.headers.get('CF-Connecting-IP') || 'unknown', ipKey = 'ip:' + ip;
  const count = parseInt((await env.ACCOUNTS.get(ipKey)) || '0', 10);
  if (count >= SIGNUPS_PER_HOUR) return fail('Too many new players right now. Try again later.', 429);
  const key = userKey(name);
  if (await env.ACCOUNTS.get(key)) return fail('That name is taken. Try adding a number.', 409);
  const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
  const user = { name, salt, hash: await hashPassword(pw, salt), level: 0, best: 0, created: Date.now() };
  await env.ACCOUNTS.put(key, JSON.stringify(user));
  await env.ACCOUNTS.put(ipKey, String(count + 1), { expirationTtl: 3600 });
  return json({ token: await newSession(env, key), name, level: 0, best: 0 });
}

async function login(body, env) {
  const name = cleanName(body.name), pw = String(body.password || '');
  if (!name || !pw) return fail('Wrong name or password.', 401);
  const key = userKey(name), failKey = 'fail:' + key;
  const fails = parseInt((await env.ACCOUNTS.get(failKey)) || '0', 10);
  if (fails >= LOCK_AFTER) return fail('Too many tries. Wait 10 minutes.', 429);
  const user = await env.ACCOUNTS.get(key, 'json');
  if (!user || !sameText(await hashPassword(pw, user.salt), user.hash)) {
    await env.ACCOUNTS.put(failKey, String(fails + 1), { expirationTtl: LOCK_SECONDS });
    return fail('Wrong name or password.', 401);
  }
  if (fails) await env.ACCOUNTS.delete(failKey);
  return json({ token: await newSession(env, key), name: user.name, level: user.level, best: user.best });
}

async function me(body, env) {
  const s = await userFromToken(env, body.token);
  if (!s) return fail('Please sign in again.', 401);
  return json({ name: s.user.name, level: s.user.level, best: s.user.best });
}

async function save(body, env) {
  const s = await userFromToken(env, body.token);
  if (!s) return fail('Please sign in again.', 401);
  const level = Math.max(s.user.level, clampLevel(body.level));
  const best = Math.max(s.user.best, clampBest(body.best));
  if (level !== s.user.level || best !== s.user.best) {
    s.user.level = level; s.user.best = best; s.user.updated = Date.now();
    await env.ACCOUNTS.put(s.key, JSON.stringify(s.user));
  }
  return json({ level, best });
}

async function logout(body, env) {
  if (/^[0-9a-f]{64}$/.test(String(body.token || ''))) await env.ACCOUNTS.delete('sess:' + body.token);
  return json({ ok: true });
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });
    if (!env.ACCOUNTS) return fail('Server not set up: bind a KV namespace as ACCOUNTS.', 500);
    if (req.method !== 'POST') return json({ ok: true, service: 'rooftop-runner-accounts' });
    let body;
    try { body = await req.json(); } catch (e) { return fail('Bad request.'); }
    const path = new URL(req.url).pathname.replace(/\/+$/, '');
    try {
      if (path === '/signup') return await signup(body, env, req);
      if (path === '/login') return await login(body, env);
      if (path === '/me') return await me(body, env);
      if (path === '/save') return await save(body, env);
      if (path === '/logout') return await logout(body, env);
      return fail('Not found.', 404);
    } catch (e) {
      return fail('Server error. Try again.', 500);
    }
  },
};
