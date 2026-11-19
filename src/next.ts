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
    const d = await guard.decide({ rawPath: raw, search: req.nextUrl.search, method: req.method, accept: req.headers.get('accept'), pass: readPass(req as any, guard.cookieName), url: req.url });
    if (d.action === 'skip') return NextResponse.next();
    if (d.action === 'allow') return NextResponse.next();
    const res = d.action === 'json'
      ? NextResponse.json(d.body, { status: d.status, headers: { 'cache-control': 'no-store', ...(d.headers || {}) } })
      : NextResponse.redirect(d.location);
    if (d.clearCookie) res.headers.append('set-cookie', signOutCookie(opts, req.url));
    return res;
  };
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
