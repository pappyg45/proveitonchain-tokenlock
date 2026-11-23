import { NextResponse, type NextRequest } from 'next/server.js';
import { TokenlockClient, readPass, safeNext, DEFAULT_COOKIE, TokenlockError, splitAuthOptions, validateResource, authorizeResource, checkClientOptions, RESOURCE_KEYS, type PassInfo, type ClientOptions, type Resource, type IdentityOnly } from './core.js';
import { exchangePass, signOutCookie, createGuard, type GuardOptions, type SessionOptions } from './session.js';

export * from './core.js';

export interface TokenlockNextOptions extends GuardOptions {}

/**
 * Next.js middleware. In middleware.ts:
 *   export default tokenlock({ protect: ['/members/:path*'], signInPage: '/signin' });
 *   export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };
 * Keep config.matcher broad (or omit it): Next's own matcher is case-sensitive, so
 * matcher: ['/members/:path*'] would skip '/MEMBERS'. TOKENLOCK's `protect` decides which paths are locked.
 */
export function tokenlock(opts: TokenlockNextOptions) {
  const guard = createGuard(opts, 'tokenlock (next)');
  return async function middleware(req: NextRequest) {
    const raw = rawPathOf(req);
    const routing = nextRouting(req);
    const d = await guard.decide({ rawPath: raw, appPath: appPathOf(raw, routing), search: req.nextUrl.search, method: req.method, accept: req.headers.get('accept'), pass: readPass(req as any, guard.cookieName), url: req.url });
    if (d.action === 'skip') return NextResponse.next();
    if (d.action === 'allow') return NextResponse.next();
    const res = d.action === 'json'
      ? NextResponse.json(d.body, { status: d.status, headers: { 'cache-control': 'no-store', ...(d.headers || {}) } })
      : NextResponse.redirect(withBasePath(d.location, routing.basePath));
    if (d.clearCookie) res.headers.append('set-cookie', signOutCookie(opts, req.url));
    return res;
  };
}
/**
 * 0.4.5 RC5: the path Next.js routes on: the raw path without the basePath and without the locale prefix (i18n). Next
 * routes /docs/fr/members to pages/members, and its own matcher patterns leave both out, so `protect` is matched the same
 * way. basePath and locales come from Next's build-time config (process.env.__NEXT_ROUTER_BASEPATH / __NEXT_I18N_CONFIG,
 * which Next inlines into the middleware bundle) and from req.nextUrl. With basePath AND i18n, Next 15 hands middleware a
 * URL like /fr/docs/fr/members (basePath reported as ''), so one basePath and up to two locale segments are stripped in
 * any order. Locale segments compare case-insensitively after one percent-decoding, like Next's locale detection.
 * Stripping too much only adds a path that is checked as well: the guard locks if either path is protected.
 * null when there is nothing to strip.
 */
function nextRouting(req: NextRequest): { basePath: string; locales: string[] } {
  let basePath = '', locales: string[] = [];
  try { const b = process.env.__NEXT_ROUTER_BASEPATH as unknown; if (typeof b === 'string') basePath = b; } catch { /* not built by Next */ }
  try {
    const c = process.env.__NEXT_I18N_CONFIG as unknown;
    const cfg: any = typeof c === 'string' ? (c ? JSON.parse(c) : null) : c;
    if (cfg && Array.isArray(cfg.locales)) locales = cfg.locales.filter((x: unknown) => typeof x === 'string' && x);
  } catch { /* not built by Next */ }
  const nu: any = req.nextUrl || {};
  if (!basePath && typeof nu.basePath === 'string') basePath = nu.basePath;
  if (typeof nu.locale === 'string' && nu.locale && !locales.includes(nu.locale)) locales.push(nu.locale);
  if (!/^\/[^?#]*[^/?#]$/.test(basePath)) basePath = '';
  return { basePath, locales };
}
function appPathOf(raw: string, r: { basePath: string; locales: string[] }): string | null {
  let p = raw, baseLeft = !!r.basePath, localesLeft = r.locales.length ? 2 : 0;
  const lower = r.locales.map((x) => x.toLowerCase());
  for (let i = 0; i < 3; i++) {
    const b = r.basePath;
    if (baseLeft && p.toLowerCase().startsWith(b.toLowerCase()) && (p.length === b.length || p[b.length] === '/')) { p = p.slice(b.length) || '/'; baseLeft = false; continue; }
    const m = p.match(/^\/([^/]+)(\/.*)?$/);
    if (localesLeft && m) { let seg = m[1]; try { seg = decodeURIComponent(seg); } catch { /* left as is */ } if (lower.includes(seg.toLowerCase())) { p = m[2] || '/'; localesLeft--; continue; } }
    break;
  }
  return p === raw ? null : p;
}
/** A redirect to the sign-in page stays under the app's basePath (RC4 sent /signin, a 404 outside it). */
function withBasePath(location: string | URL, base: string): string {
  const s = String(location);
  if (!base) return s;
  try { const u = new URL(s); if (!u.pathname.startsWith(base + '/') && u.pathname !== base) u.pathname = base + u.pathname; return u.toString(); } catch { return s; }
}
/** The path as sent (before Next's own decoding), so encoded tricks are seen and rejected. */
function rawPathOf(req: NextRequest): string {
  const u = String(req.url || '');
  const m = u.match(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*([^?#]*)/i);
  return (m && m[1]) || req.nextUrl.pathname || '/';
}

/**
 * Route handlers for pass → cookie and sign-out. In app/api/tokenlock/[action]/route.ts:
 *   export const { GET, POST } = tokenlockRoutes();
 * POST /api/tokenlock/session { pass }  → sets the HttpOnly cookie
 * GET|POST /api/tokenlock/signout       → clears it and redirects
 */
export function tokenlockRoutes(opts: SessionOptions = {}) {
  let client: TokenlockClient | null = null;
  const action = (req: Request) => new URL(req.url).pathname.replace(/\/+$/, '').split('/').pop();
  async function POST(req: Request) {
    const a = action(req);
    if (a === 'signout') return signOut(req);
    if (a !== 'session') return Response.json({ ok: false, code: 'not_found' }, { status: 404 });
    client ||= new TokenlockClient(opts);
    const ct = req.headers.get('content-type') || '';
    let pass: unknown = null;
    if (ct.includes('application/json') || !ct) pass = (await req.json().catch(() => ({})))?.pass;
    else if (ct.includes('form')) pass = (await req.formData().catch(() => null))?.get('pass');
    const r = await exchangePass(client, opts, { pass, requestUrl: req.url, originHeader: req.headers.get('origin') });
    const res = Response.json(r.body, { status: r.status, headers: { 'cache-control': 'no-store' } });
    if (r.cookie) res.headers.append('set-cookie', r.cookie);
    return res;
  }
  function signOut(req: Request) {
    const to = new URL(safeNext(opts.afterSignOut, '/'), req.url);
    return new Response(null, { status: 303, headers: { location: to.toString(), 'set-cookie': signOutCookie(opts, req.url), 'cache-control': 'no-store' } });
  }
  async function GET(req: Request) {
    if (action(req) === 'signout') return signOut(req);
    return Response.json({ ok: false, code: 'not_found' }, { status: 404 });
  }
  return { GET, POST };
}

/**
 * The signed-in visitor (identity only), or null. In a Server Component or route handler:
 *   const pass = await getPass();          // reads cookies() from next/headers
 *   const pass = await getPass(request);   // or from a Request / NextRequest
 * getPass does NOT check a route. To authorize an action (route, method, environment), pass { path, method } here or
 * use authorize(), which is strict and uncached.
 */
export async function getPass(req?: { headers: any; cookies?: any }, opts: ClientOptions & { cookieName?: string } & (Resource | IdentityOnly | {}) = {}): Promise<PassInfo | null> {
  const { client: c, request, extra } = splitAuthOptions(opts as any, 'getPass', ['cookieName']);
  checkClientOptions(c, 'getPass');
  const res = validateResource(request, 'getPass'); // 0.4.3: a route or { identityOnly: true }; never inferred
  const pass = await passFrom(req, extra.cookieName || DEFAULT_COOKIE);
  if (!pass) return null;
  const { strict, cache, ...rest } = c;
  const info = await new TokenlockClient(rest).verifyPass(pass, res ?? { identityOnly: true }, { strict, cache });
  return info.valid ? info : null;
}
/**
 * Authorize one action, strict and uncached: `const a = await authorize(request, { path: '/api/orders', method: 'POST', environment: 'production' })`.
 * Returns the pass info when allowed, else { valid:false, allowed:false, code, reason }.
 */
export async function authorize(req: { headers: any; cookies?: any } | undefined, resource: Resource, opts: ClientOptions & { cookieName?: string } = {}): Promise<PassInfo> {
  const { client: c, extra } = splitAuthOptions(opts as any, 'authorize', ['cookieName']);
  checkClientOptions(c, 'authorize');
  const res = authorizeResource(resource);
  if (res === 'bad_path') return { valid: false, allowed: false, code: 'bad_path', reason: 'Not a valid path.' };
  const pass = await passFrom(req, extra.cookieName || DEFAULT_COOKIE);
  if (!pass) return { valid: false, allowed: false, code: 'signin_required', reason: 'Sign in first.' };
  const { strict, cache, ...rest } = c;
  return new TokenlockClient(rest).verifyPass(pass, res, { strict: true, cache: cache ?? false });
}
async function passFrom(req: { headers: any; cookies?: any } | undefined, name: string): Promise<string | null> {
  if (req) return readPass(req as any, name);
  const { cookies } = await import('next/headers.js');
  const jar: any = await (cookies as any)();
  return jar.get(name)?.value || null;
}
