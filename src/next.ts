import { NextResponse, type NextRequest } from 'next/server.js';
import { TokenlockClient, createMatcher, readPass, safeNext, DEFAULT_COOKIE, type Matcher, type PassInfo, type ClientOptions } from './core.js';
import { exchangePass, signOutCookie, signInRedirect, type SessionOptions } from './session.js';

export * from './core.js';

export interface TokenlockNextOptions extends SessionOptions {
  /** Paths to lock: '/members/:path*', '/admin', RegExp or a function. */
  protect: Matcher | Matcher[];
  /** Your public sign-in page, e.g. '/signin'. Visitors without a pass go there with ?next=<path>. */
  signInPage: string;
  /** Paths that are never locked (besides signInPage), e.g. ['/members/public']. */
  publicPaths?: Matcher | Matcher[];
}

/**
 * Next.js middleware. In middleware.ts:
 *   export default tokenlock({ protect: ['/members/:path*'], signInPage: '/signin' });
 *   export const config = { matcher: ['/members/:path*'] };
 */
export function tokenlock(opts: TokenlockNextOptions) {
  const isLocked = createMatcher(opts.protect);
  const isPublic = opts.publicPaths ? createMatcher(opts.publicPaths) : () => false;
  const name = opts.cookieName || DEFAULT_COOKIE;
  let client: TokenlockClient | null = null;
  return async function middleware(req: NextRequest) {
    const path = req.nextUrl.pathname;
    if (!isLocked(path) || isPublic(path) || createMatcher(opts.signInPage)(path)) return NextResponse.next();
    client ||= new TokenlockClient(opts);
    const pass = readPass(req as any, name);
    let info: PassInfo | null = null;
    if (pass) { try { info = await client.verifyPass(pass); } catch { info = null; } }
    if (info?.valid) return NextResponse.next();
    const res = NextResponse.redirect(signInRedirect(opts.signInPage, req.url, path, req.nextUrl.search));
    if (pass) res.headers.append('set-cookie', signOutCookie(opts, req.url));
    return res;
  };
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
 * The signed-in visitor, or null. In a Server Component or route handler:
 *   const pass = await getPass();          // reads cookies() from next/headers
 *   const pass = await getPass(request);   // or from a Request / NextRequest
 */
export async function getPass(req?: { headers: any; cookies?: any }, opts: ClientOptions & { cookieName?: string } = {}): Promise<PassInfo | null> {
  const { cookieName, ...c } = opts;
  const name = cookieName || DEFAULT_COOKIE;
  let pass: string | null = null;
  if (req) pass = readPass(req as any, name);
  else {
    const { cookies } = await import('next/headers.js');
    const jar: any = await (cookies as any)();
    pass = jar.get(name)?.value || null;
  }
  if (!pass) return null;
  const info = await new TokenlockClient(c).verifyPass(pass);
  return info.valid ? info : null;
}
