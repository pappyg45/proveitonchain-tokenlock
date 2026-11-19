// TOKENLOCK in front of any site on Cloudflare (Workers). No dependencies. Same decisions as the Node and PHP adapters:
// canonical, case-insensitive path matching; path + method + environment sent with every check; strict answers only
// (allowed === true for exactly this request); fail closed when the API can't answer; JSON 401/403 for API requests.
// Set secrets: wrangler secret put TOKENLOCK_SECRET_KEY ; set TOKENLOCK_SITE_KEY (and TOKENLOCK_ENVIRONMENT) in [vars].
// 0.4.2: TOKENLOCK_FAIL_OPEN, TOKENLOCK_CHECK_RESOURCE and TOKENLOCK_STRICT were removed; if any is set (to any value) the
// worker refuses protected requests with 500 bad_config. Every API call has a timeout (TOKENLOCK_TIMEOUT_MS, default 8000):
// a slow or hung API is answered 503 and nothing protected is served. Answers over 64 KiB are refused.
const COOKIE = 'tokenlock_pass';
const PROTECT = ['/members']; // prefixes: '/members' locks /members and everything under it (any case). Or set TOKENLOCK_PROTECT="/members,/admin"

const API_PATHS = ['/members/api']; // always JSON 401/403 here; Accept: application/json also gets JSON
const SIGN_IN = '/signin';
const FORBIDDEN = ['route_not_allowed', 'method_not_allowed', 'environment_not_allowed', 'bad_path', 'resource_mismatch', 'policy_required'];
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
const VERSION = '0.4.3';
const MAX_ANSWER_BYTES = 65536;
const REMOVED = ['TOKENLOCK_FAIL_OPEN', 'TOKENLOCK_CHECK_RESOURCE', 'TOKENLOCK_STRICT'];
/** Config check (0.4.2). Returns null when the settings are usable, else the reason. Never guesses a default for a bad value. */
export function configProblem(env) {
  env = env || {};
  for (const k of REMOVED) if (env[k] !== undefined) return `${k} was removed in 0.4.2; remove it (protected access always fails closed and every request is checked).`;
  if (typeof env.TOKENLOCK_SECRET_KEY !== 'string' || !/^sk_[A-Za-z0-9_-]{20,200}$/.test(env.TOKENLOCK_SECRET_KEY)) return 'TOKENLOCK_SECRET_KEY must be your sk_… secret key.';
  if (env.TOKENLOCK_TOKEN_ONLY !== undefined && !['', '0', '1'].includes(String(env.TOKENLOCK_TOKEN_ONLY))) return 'TOKENLOCK_TOKEN_ONLY must be 1 or 0.';
  if (env.TOKENLOCK_TIMEOUT_MS !== undefined && !(/^\d{1,5}$/.test(String(env.TOKENLOCK_TIMEOUT_MS)) && +env.TOKENLOCK_TIMEOUT_MS >= 1 && +env.TOKENLOCK_TIMEOUT_MS <= 60000)) return 'TOKENLOCK_TIMEOUT_MS must be a whole number of milliseconds from 1 to 60000.';
  if (env.TOKENLOCK_ENVIRONMENT !== undefined && !(typeof env.TOKENLOCK_ENVIRONMENT === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,29}$/.test(env.TOKENLOCK_ENVIRONMENT))) return 'TOKENLOCK_ENVIRONMENT must be 1-30 letters, digits, _, . or - (no spaces, not empty).';
  // 0.4.3: TOKENLOCK_PROTECT / TOKENLOCK_API_PATHS are plain path prefixes. A glob or pattern ("/api/*", "/api/:path*")
  // or a relative entry matched nothing, which left the intended paths unprotected; it is a configuration error now.
  for (const k of ['TOKENLOCK_PROTECT', 'TOKENLOCK_API_PATHS']) {
    if (env[k] === undefined) continue;
    const items = String(env[k]).split(',').map((x) => x.trim()).filter(Boolean);
    if (k === 'TOKENLOCK_PROTECT' && !items.length) return 'TOKENLOCK_PROTECT is empty; list path prefixes such as /members,/admin.';
    for (const it of items) if (!/^\/[A-Za-z0-9._~!$&'()+,;=@%\/-]*$/.test(it) || it.includes('*') || it.includes(':')) return `${k} entries must be plain path prefixes such as /members (no *, : or relative paths); got "${it.slice(0, 60)}".`;
  }
  if (env.TOKENLOCK_API !== undefined) { try { const u = new URL(env.TOKENLOCK_API); if (u.protocol !== 'https:' && u.protocol !== 'http:') return 'TOKENLOCK_API must be an http(s) URL.'; } catch { return 'TOKENLOCK_API must be an http(s) URL.'; } }
  return null;
}
// 0.4.3: the authorization request is explicit. resource = { path, method, environment? } (validated) or
// { identityOnly: true }. Anything else (missing, unknown fields, wrong types, empty or padded values) is refused.
function checkResource(resource) {
  if (!resource || typeof resource !== 'object' || Array.isArray(resource)) return 'bad_resource';
  const keys = Object.keys(resource);
  if ('identityOnly' in resource) return resource.identityOnly === true && keys.length === 1 ? null : 'bad_resource';
  for (const k of keys) if (!['path', 'method', 'environment'].includes(k)) return 'bad_resource';
  if (!('path' in resource) || !('method' in resource)) return 'bad_resource';
  for (const k of keys) { const v = resource[k]; if (typeof v !== 'string' || v === '' || v.trim() !== v) return 'bad_resource'; }
  if (!/^[A-Za-z]{1,10}$/.test(resource.method)) return 'bad_resource';
  if ('environment' in resource && !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,29}$/.test(resource.environment)) return 'bad_resource';
  if (!resource.path.startsWith('/') || canonicalPath(resource.path) === null) return 'bad_path';
  return null;
}
export async function verify(pass, env, resource) {
  const rc = checkResource(resource);
  if (rc) return { ok: false, code: rc };
  const body = resource.identityOnly ? { pass, identity_only: true } : { pass, path: resource.path, method: resource.method.toUpperCase(), ...(resource.environment ? { environment: resource.environment } : {}) };
  if (!pass || !/^pp1\.[\w-]+\.[\w-]+$/.test(pass) || pass.length > 4000) return { ok: false, code: 'bad_pass' };
  const ms = env.TOKENLOCK_TIMEOUT_MS !== undefined ? +env.TOKENLOCK_TIMEOUT_MS : 8000;
  let r, text;
  try {
    // Fail-closed timeout: a slow or hung API throws (→ 503), it never lets the request through.
    r = await fetch((env.TOKENLOCK_API || 'https://proveitonchain.com') + '/api/v1/gate/verify', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + env.TOKENLOCK_SECRET_KEY, 'x-tokenlock-sdk': 'cf-worker/' + VERSION }, body: JSON.stringify(body), signal: AbortSignal.timeout(ms) });
    if (r.status >= 500) throw new Error('tokenlock_unavailable');
    if (Number(r.headers.get('content-length') || 0) > MAX_ANSWER_BYTES) throw new Error('tokenlock_bad_answer');
    text = await r.text();
  } catch { throw new Error('tokenlock_unavailable'); }
  if (text.length > MAX_ANSWER_BYTES) throw new Error('tokenlock_unavailable');
  let v = null; try { v = JSON.parse(text); } catch { v = null; }
  if (r.ok && (!v || typeof v !== 'object' || Array.isArray(v))) throw new Error('tokenlock_unavailable'); // bad 2xx answer: deny (503)
  return { ...strictCheck(v, resource.identityOnly ? null : resource), v };
}
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;
const isObj = (x) => !!x && typeof x === 'object' && !Array.isArray(x);
/** Same rules as the SDK's strictCheck (0.4.2): wrong types, missing fields and contradictions are all a no. */
export function strictCheck(v, resource) {
  const no = (code) => ({ ok: false, code: isObj(v) && v.valid === false && typeof v.code === 'string' && v.code ? v.code : code });
  if (!isObj(v)) return no('bad_answer');
  const a = v.access;
  if (v.valid !== true) return no((typeof v.code === 'string' && v.code) || (isObj(a) && typeof a.reason === 'string' && a.reason) || 'bad_pass');
  if ((v.code !== undefined && v.code !== null && v.code !== 'ok') || v.error !== undefined || ('identity_valid' in v && v.identity_valid !== true)) return { ok: false, code: typeof v.code === 'string' && /^[a-z_]{1,64}$/.test(v.code) && v.code !== 'ok' ? v.code : 'conflicting_answer' };
  if (typeof v.address !== 'string' || !v.address || typeof v.site_id !== 'string' || !v.site_id) return no('incomplete_answer');
  if (v.assets_held !== undefined && !Array.isArray(v.assets_held)) return no('incomplete_answer');
  if (typeof v.expires_at !== 'string' || !ISO_TIME.test(v.expires_at)) return no('incomplete_answer');
  if (!(Date.parse(v.expires_at) > Date.now())) return no('expired');
  // 0.4.0: only a route policy (registered keys) can permit a resource; a valid answer without one is policy_required.
  if (resource && a === undefined) return { ok: false, code: 'policy_required' };
  if ('allowed' in v && v.allowed !== true) return no((isObj(a) && typeof a.reason === 'string' && a.reason !== 'ok' && a.reason) || 'not_allowed');
  if (a !== undefined) {
    if (!isObj(a) || a.mode !== 'registered_keys' || a.allowed !== true) return no((isObj(a) && typeof a.reason === 'string' && a.reason) || 'not_allowed');
    if (a.reason !== undefined && a.reason !== 'ok') return no('conflicting_answer');
  }
  const echoes = [v.resource, isObj(a) ? a.resource : undefined].filter((e) => e !== undefined && e !== null);
  if (resource) {
    if (v.allowed !== true) return no('not_allowed');
    if (!echoes.length) return no('incomplete_answer');
    for (const e of echoes) {
      if (!isObj(e)) return no('incomplete_answer');
      const ep = typeof e.path === 'string' ? e.path.toLowerCase() : e.path ?? null;
      if ((resource.path ?? null) !== ep || (resource.method ?? null) !== (e.method ?? null) || (resource.environment ?? null) !== (e.environment ?? null)) return no('resource_mismatch');
    }
  } else if (echoes.some((e) => !isObj(e) || e.path != null || e.method != null || e.environment != null)) return no('conflicting_answer'); // an identity answer must not name a resource
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
    const bad = configProblem(env);
    const badConfig = () => json({ error: 'This site\'s TOKENLOCK settings are invalid, so protected access is refused.', code: 'bad_config', reason: bad }, 500);
    // 0.4.3: when the protected-path list itself is unusable, no path can be known to be public: refuse everything.
    if (bad && /^TOKENLOCK_(PROTECT|API_PATHS) /.test(bad)) return badConfig();
    if (path === '/api/tokenlock/session' && req.method === 'POST') {
      if (bad) return badConfig();
      if (req.headers.get('origin') !== url.origin) return new Response('Wrong site', { status: 403 });
      const { pass } = await req.json().catch(() => ({}));
      let r; try { r = await verify(pass, env, { identityOnly: true }); } catch { return json({ ok: false, code: 'tokenlock_unavailable' }, 503); }
      if (!r.ok) return json({ ok: false, code: r.code }, 401);
      const age = Math.max(0, Math.min(86400 * 30, Math.floor((Date.parse(r.v.expires_at) - Date.now()) / 1000)));
      return json({ ok: true, address: r.v.address }, 200, { 'set-cookie': cookie(pass, age) });
    }
    if (path === '/api/tokenlock/signout') return new Response(null, { status: 303, headers: { location: '/', 'set-cookie': cookie('', 0) } });
    const list = (v, d) => (v ? String(v).split(',').map((x) => x.trim()).filter(Boolean) : d);
    if (!under(path, list(env.TOKENLOCK_PROTECT, PROTECT))) return fetch(req);
    if (bad) return badConfig(); // protected path + unusable settings: refuse, never serve
    const accept = (req.headers.get('accept') || '').toLowerCase();
    const api = under(path, list(env.TOKENLOCK_API_PATHS, API_PATHS)) || (accept.includes('application/json') && !accept.includes('text/html'));
    const pass = readCookie(req, COOKIE);
    const resource = { path: path.toLowerCase(), method: req.method.toUpperCase(), ...(env.TOKENLOCK_ENVIRONMENT ? { environment: env.TOKENLOCK_ENVIRONMENT } : {}) };
    let r = { ok: false, code: 'signin_required' };
    if (pass) {
      try {
        // TOKENLOCK_TOKEN_ONLY=1: every token holder may open the protected paths (token-only site). Check identity and
        // token; if the site has registered keys after all, enforce its route policy.
        if (env.TOKENLOCK_TOKEN_ONLY === '1') { r = await verify(pass, env, { identityOnly: true }); if (r.ok && r.v.access !== undefined) r = await verify(pass, env, resource); }
        else r = await verify(pass, env, resource);
      }
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
