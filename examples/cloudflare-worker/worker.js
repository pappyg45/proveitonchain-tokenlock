// TOKENLOCK in front of any site on Cloudflare (Workers). No dependencies. Same decisions as the Node and PHP adapters:
// canonical, case-insensitive path matching; path + method + environment sent with every check; strict answers only
// (allowed === true for exactly this request); fail closed when the API can't answer; JSON 401/403 for API requests.
// Set secrets: wrangler secret put TOKENLOCK_SECRET_KEY ; set TOKENLOCK_SITE_KEY (and TOKENLOCK_ENVIRONMENT) in [vars].
const COOKIE = 'tokenlock_pass';
const PROTECT = ['/members']; // prefixes: '/members' locks /members and everything under it (any case). Or set TOKENLOCK_PROTECT="/members,/admin"

const API_PATHS = ['/members/api']; // always JSON 401/403 here; Accept: application/json also gets JSON
const SIGN_IN = '/signin';
const FORBIDDEN = ['route_not_allowed', 'method_not_allowed', 'environment_not_allowed', 'bad_path', 'resource_mismatch'];
const DENIED = [...FORBIDDEN, 'key_revoked', 'key_expired', 'pending_approval', 'not_registered', 'org_not_approved', 'org_required', 'entitlement_revoked', 'not_allowed', 'lookup_failed'];

// TOKENLOCK path rules v1.1 (same as canonicalPath() in the SDK and the PHP drop-in). null = reject with 400.
// Ambiguous forms (';', '.' and '..' segments, encoded dots) are rejected, not resolved.
export function canonicalPath(raw) {
  let s = String(raw ?? '');
  if (!s || s.length > 2048) return null;
  s = s.split(/[?#]/)[0];
  if (/[\u0000-\u001f\u007f\\;]/.test(s) || /%(2f|5c|00|25|2e|3b)/i.test(s)) return null;
  try { s = decodeURIComponent(s); } catch { return null; }
  if (!s.startsWith('/') || /[\u0000-\u001f\u007f\\;]/.test(s)) return null;
  const out = [];
  for (const seg of s.split('/')) {
    if (seg === '.' || seg === '..') return null;
    if (seg !== '') out.push(seg);
  }
  return '/' + out.join('/');
}
const under = (p, list) => { const q = p.toLowerCase(); return list.some((b) => { b = b.toLowerCase().replace(/\/+$/, ''); return q === b || q.startsWith(b + '/'); }); };
// The path exactly as sent: new URL() would resolve dot segments first and hide what the client asked for.
const rawPath = (u) => (String(u).match(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*([^?#]*)/i) || [])[1] || '/';

/**
 * Strict check for one request, the same rules and deny codes as the SDK's strict mode. Returns { ok:true, v } |
 * { ok:false, v, code }; throws when the API can't answer. Authorization denials keep the server's reason
 * (route_not_allowed, key_revoked, …); only a malformed answer is 'incomplete_answer'.
 */
export async function verify(pass, env, resource) {
  if (!pass || !/^pp1\.[\w-]+\.[\w-]+$/.test(pass) || pass.length > 4000) return { ok: false, code: 'bad_pass' };
  const r = await fetch((env.TOKENLOCK_API || 'https://proveitonchain.com') + '/api/v1/gate/verify', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + env.TOKENLOCK_SECRET_KEY, 'x-tokenlock-sdk': 'cf-worker/0.3.0' }, body: JSON.stringify({ pass, ...(resource || {}) }) });
  if (r.status >= 500) throw new Error('tokenlock_unavailable');
  const v = await r.json().catch(() => null);
  return { ...strictCheck(v, resource), v };
}
export function strictCheck(v, resource) {
  const no = (code) => ({ ok: false, code: v && v.valid === false && v.code ? v.code : code });
  if (!v || typeof v !== 'object') return no('bad_answer');
  const a = v.access;
  if (v.valid !== true) return no(v.code || (a && a.reason) || 'bad_pass');
  if (typeof v.address !== 'string' || !v.address || typeof v.site_id !== 'string' || !v.site_id) return no('incomplete_answer');
  if (!(Date.parse(v.expires_at || '') > Date.now())) return no('expired');
  if (a !== undefined && (!a || a.mode !== 'registered_keys' || a.allowed !== true)) return no((a && a.reason) || 'not_allowed');
  if (resource) {
    if (v.allowed !== true) return no((a && a.reason) || 'not_allowed');
    const e = v.resource || (a && a.resource);
    if (!e) return no('incomplete_answer');
    const ep = typeof e.path === 'string' ? e.path.toLowerCase() : e.path ?? null;
    if ((resource.path ?? null) !== ep || (resource.method ?? null) !== (e.method ?? null) || (resource.environment ?? null) !== (e.environment ?? null)) return no('resource_mismatch');
  } else if (v.allowed === false) return no('not_allowed');
  return { ok: true };
}
const readCookie = (req, name) => (req.headers.get('cookie') || '').split(/;\s*/).map((c) => c.split('=')).find(([k]) => k === name)?.[1] || null;
const cookie = (v, age) => `${COOKIE}=${v}; Path=/; Max-Age=${age}; HttpOnly; Secure; SameSite=Lax`;
// Same-site "next" only (same rules as safeNext() in the SDK). Used on the server and, via TL_SAFE_NEXT, in the browser sign-in page.
export function safeNext(v) {
  if (typeof v !== 'string' || !v || v.length > 2000) return '/';
  let d = v;
  for (let i = 0; i < 4; i++) {
    if (d[0] !== '/' || d[1] === '/' || d[1] === '\\' || /[\u0000-\u001f\u007f-\u009f\\\u2028\u2029]/.test(d)) return '/';
    if (!/%[0-9a-f]{2}/i.test(d)) return v;
    let n;
    try { n = decodeURIComponent(d); } catch { return '/'; }
    if (n === d) return v;
    d = n;
  }
  return '/';
}
const TL_SAFE_NEXT = 'const tlSafeNext=' + safeNext.toString() + ';';
const json = (body, status, extra = {}) => Response.json(body, { status, headers: { 'cache-control': 'no-store', ...extra } });

const SIGNIN_HTML = (siteKey, api) => `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in</title>
<main style="max-width:480px;margin:80px auto;font-family:system-ui;text-align:center"><h1>Members only</h1>
<script src="${api}/gate.js" data-site-key="${siteKey}"></script>
<button id="go">Sign in with your Token</button></main>
<script>go.onclick=async()=>{const{pass}=await ProveItGate.signIn();const r=await fetch('/api/tokenlock/session',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({pass})});if(r.ok)location.assign(tlSafeNext(new URLSearchParams(location.search).get('next')||'/members'));};${TL_SAFE_NEXT}</script>`;

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = canonicalPath(rawPath(req.url));
    if (path === null) return json({ error: 'Not a valid path.', code: 'bad_path', reason: 'Not a valid path.' }, 400);
    if (path === SIGN_IN) return new Response(SIGNIN_HTML(env.TOKENLOCK_SITE_KEY, env.TOKENLOCK_API || 'https://proveitonchain.com'), { headers: { 'content-type': 'text/html; charset=utf-8' } });
    if (path === '/api/tokenlock/session' && req.method === 'POST') {
      if (req.headers.get('origin') !== url.origin) return new Response('Wrong site', { status: 403 });
      const { pass } = await req.json().catch(() => ({}));
      let r; try { r = await verify(pass, env); } catch { return json({ ok: false, code: 'tokenlock_unavailable' }, 503); }
      if (!r.ok) return json({ ok: false, code: r.code }, 401);
      const age = Math.max(0, Math.floor((Date.parse(r.v.expires_at) - Date.now()) / 1000));
      return json({ ok: true, address: r.v.address }, 200, { 'set-cookie': cookie(pass, age) });
    }
    if (path === '/api/tokenlock/signout') return new Response(null, { status: 303, headers: { location: '/', 'set-cookie': cookie('', 0) } });
    const list = (v, d) => (v ? String(v).split(',').map((x) => x.trim()).filter(Boolean) : d);
    if (!under(path, list(env.TOKENLOCK_PROTECT, PROTECT))) return fetch(req);
    const accept = (req.headers.get('accept') || '').toLowerCase();
    const api = under(path, list(env.TOKENLOCK_API_PATHS, API_PATHS)) || (accept.includes('application/json') && !accept.includes('text/html'));
    const pass = readCookie(req, COOKIE);
    const resource = { path: path.toLowerCase(), method: req.method.toUpperCase(), environment: env.TOKENLOCK_ENVIRONMENT || null };
    let r = { ok: false, code: 'signin_required' };
    if (pass) {
      try { r = await verify(pass, env, resource); }
      catch { return json({ error: 'Could not check your sign-in right now. Try again in a moment.', code: 'tokenlock_unavailable', reason: 'The verification service did not answer; protected access is denied until it does.' }, 503, { 'retry-after': '15' }); }
    }
    if (r.ok) return fetch(req);
    const reason = (r.v && r.v.reason) || (pass ? 'Not allowed.' : 'Sign in first.');
    const body = { error: reason, code: r.code, reason, correlation_id: (r.v && r.v.correlation_id) || null };
    if (api) { const status = DENIED.includes(r.code) ? 403 : 401; return json(body, status, pass && status === 401 ? { 'set-cookie': cookie('', 0) } : {}); }
    if (FORBIDDEN.includes(r.code)) return json(body, 403);
    const to = new URL(SIGN_IN, url); to.searchParams.set('next', safeNext(path + url.search));
    return new Response(null, { status: 302, headers: { location: to.toString(), ...(pass ? { 'set-cookie': cookie('', 0) } : {}) } });
  },
};
