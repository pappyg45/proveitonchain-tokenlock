// TOKENLOCK in front of any site on Cloudflare (Workers). No dependencies.
// Set secrets: wrangler secret put TOKENLOCK_SECRET_KEY ; set TOKENLOCK_SITE_KEY in wrangler.toml [vars].
// Requests to PROTECT need a valid pass cookie; everything else passes through to your origin.
const API = 'https://proveitonchain.com';
const COOKIE = 'tokenlock_pass';
const PROTECT = [/^\/members(\/|$)/];
const SIGN_IN = '/signin';

async function verify(pass, env) {
  if (!pass || !/^pp1\.[\w-]+\.[\w-]+$/.test(pass)) return null;
  const r = await fetch(API + '/api/v1/gate/verify', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + env.TOKENLOCK_SECRET_KEY }, body: JSON.stringify({ pass }) });
  const v = await r.json().catch(() => null);
  return v && v.valid && v.site_id ? v : null;
}
const readCookie = (req, name) => (req.headers.get('cookie') || '').split(/;\s*/).map((c) => c.split('=')).find(([k]) => k === name)?.[1] || null;
const cookie = (v, age) => `${COOKIE}=${v}; Path=/; Max-Age=${age}; HttpOnly; Secure; SameSite=Lax`;
const safeNext = (v) => (v && v.startsWith('/') && !v.startsWith('//') ? v : '/');

const SIGNIN_HTML = (siteKey) => `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in</title>
<main style="max-width:480px;margin:80px auto;font-family:system-ui;text-align:center"><h1>Members only</h1>
<script src="${API}/gate.js" data-site-key="${siteKey}"></script>
<button id="go">Sign in with your Token</button></main>
<script>go.onclick=async()=>{const{pass}=await ProveItGate.signIn();const r=await fetch('/api/tokenlock/session',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({pass})});if(r.ok)location.href=new URLSearchParams(location.search).get('next')||'/members';}</script>`;

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === SIGN_IN) return new Response(SIGNIN_HTML(env.TOKENLOCK_SITE_KEY), { headers: { 'content-type': 'text/html; charset=utf-8' } });
    if (url.pathname === '/api/tokenlock/session' && req.method === 'POST') {
      if (req.headers.get('origin') !== url.origin) return new Response('Wrong site', { status: 403 });
      const { pass } = await req.json().catch(() => ({}));
      const v = await verify(pass, env);
      if (!v) return Response.json({ ok: false }, { status: 401 });
      const age = Math.max(0, Math.floor((Date.parse(v.expires_at) - Date.now()) / 1000));
      return Response.json({ ok: true, address: v.address }, { headers: { 'set-cookie': cookie(pass, age) } });
    }
    if (url.pathname === '/api/tokenlock/signout') return new Response(null, { status: 303, headers: { location: '/', 'set-cookie': cookie('', 0) } });
    if (!PROTECT.some((re) => re.test(url.pathname))) return fetch(req);
    const pass = readCookie(req, COOKIE);
    if (await verify(pass, env)) return fetch(req);
    const to = new URL(SIGN_IN, url); to.searchParams.set('next', safeNext(url.pathname + url.search));
    return new Response(null, { status: 302, headers: { location: to.toString(), ...(pass ? { 'set-cookie': cookie('', 0) } : {}) } });
  },
};
