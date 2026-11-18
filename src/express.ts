import { TokenlockClient, createMatcher, readPass, safeNext, DEFAULT_COOKIE, FORBIDDEN_CODES, isUnavailable, type Matcher, type PassInfo } from './core.js';
import { exchangePass, signOutCookie, signInRedirect, type SessionOptions } from './session.js';

export * from './core.js';

export interface TokenlockExpressOptions extends SessionOptions {
  /** Paths to lock: '/members/:path*', '/admin', RegExp or a function. */
  protect: Matcher | Matcher[];
  /** Your public sign-in page, e.g. '/signin'. */
  signInPage: string;
  publicPaths?: Matcher | Matcher[];
  /** Pass → cookie endpoint (POST { pass }). Default '/api/tokenlock/session' */
  sessionPath?: string;
  /** Sign-out endpoint. Default '/api/tokenlock/signout' */
  signOutPath?: string;
  /** Behind a proxy, the public origin of your site, e.g. 'https://example.com' (used for cookie and origin checks). */
  publicOrigin?: string;
  /** Sent with each pass check so registered keys are checked against this environment, e.g. 'production'. */
  environment?: string;
  /** Send the request path and method with each pass check (default true). Sites with registered keys enforce them. */
  checkResource?: boolean;
  /**
   * If the TOKENLOCK API can't be reached, let requests that carry a pass cookie through unverified
   * (req.tokenlock = null, header x-tokenlock: fail-open). Default false = fail closed with 503 "try again".
   * Only for low-risk content; never for admin areas or APIs.
   */
  failOpen?: boolean;
}

type Req = { method?: string; url?: string; originalUrl?: string; path?: string; headers: Record<string, any>; body?: any; protocol?: string; get?: (h: string) => string | undefined; on?: any; tokenlock?: PassInfo | null; [k: string]: any };
type Res = { statusCode: number; setHeader(k: string, v: any): any; getHeader?(k: string): any; end(b?: any): any; [k: string]: any };

function readBody(req: Req): Promise<any> {
  if (req.body && typeof req.body === 'object') return Promise.resolve(req.body);
  if (typeof req.body === 'string') return Promise.resolve(parse(req.body, req.headers['content-type']));
  return new Promise((ok) => {
    let s = '';
    req.on('data', (c: Buffer) => { s += c; if (s.length > 16_384) { s = ''; } });
    req.on('end', () => ok(parse(s, req.headers['content-type'])));
    req.on('error', () => ok({}));
  });
}
function parse(s: string, ct = ''): any {
  if (String(ct).includes('application/x-www-form-urlencoded')) return Object.fromEntries(new URLSearchParams(s));
  try { return JSON.parse(s || '{}'); } catch { return {}; }
}
function addCookie(res: Res, c: string) {
  const prev = res.getHeader?.('set-cookie');
  res.setHeader('set-cookie', prev ? ([] as string[]).concat(prev as any, c) : c);
}
const send = (res: Res, status: number, body: unknown) => { res.statusCode = status; res.setHeader('content-type', 'application/json'); res.setHeader('cache-control', 'no-store'); res.end(JSON.stringify(body)); };
const redirect = (res: Res, status: number, to: string) => { res.statusCode = status; res.setHeader('location', to); res.end(); };

/**
 * Express (or plain Node http) middleware:
 *   app.use(tokenlock({ protect: ['/members/:path*'], signInPage: '/signin.html' }));
 * Locked requests get req.tokenlock = { address, assets_held, … }.
 */
export function tokenlock(opts: TokenlockExpressOptions) {
  const isLocked = createMatcher(opts.protect);
  const isPublic = opts.publicPaths ? createMatcher(opts.publicPaths) : () => false;
  const isSignIn = createMatcher(opts.signInPage);
  const sessionPath = opts.sessionPath || '/api/tokenlock/session';
  const signOutPath = opts.signOutPath || '/api/tokenlock/signout';
  const name = opts.cookieName || DEFAULT_COOKIE;
  let client: TokenlockClient | null = null;

  return async function tokenlockMiddleware(req: Req, res: Res, next: (e?: any) => void) {
    try {
      const raw = req.originalUrl || req.url || '/';
      const qi = raw.indexOf('?');
      const path = (qi < 0 ? raw : raw.slice(0, qi)) || '/';
      const search = qi < 0 ? '' : raw.slice(qi);
      const proto = opts.publicOrigin ? '' : (req.protocol || (req.headers['x-forwarded-proto'] || '').split(',')[0] || 'http');
      const base = opts.publicOrigin || `${proto}://${req.headers.host || 'localhost'}`;
      const url = base + raw;
      client ||= new TokenlockClient(opts);

      if (path === sessionPath && req.method === 'POST') {
        const body = await readBody(req);
        const r = await exchangePass(client, opts, { pass: body?.pass, requestUrl: url, originHeader: req.headers.origin });
        if (r.cookie) addCookie(res, r.cookie);
        return send(res, r.status, r.body);
      }
      if (path === signOutPath && (req.method === 'POST' || req.method === 'GET')) {
        addCookie(res, signOutCookie(opts, url));
        return redirect(res, 303, safeNext(opts.afterSignOut, '/'));
      }
      if (!isLocked(path) || isPublic(path) || isSignIn(path)) return next();
      const pass = readPass(req as any, name);
      let info: PassInfo | null = null;
      const resource = opts.checkResource === false ? undefined : { path, method: req.method || 'GET', environment: opts.environment };
      let apiDown = false;
      if (pass) { try { info = await client.verifyPass(pass, resource); } catch (e) { if (!isUnavailable(e)) throw e; info = null; apiDown = true; } }
      if (info?.valid) { req.tokenlock = info; return next(); }
      if (apiDown) {
        // Our API couldn't answer. Default: fail closed with a "try again" (the cookie is kept, so the visitor is
        // back in as soon as we answer). failOpen: let the request through unverified (low-risk content only).
        if (opts.failOpen) { req.tokenlock = null; res.setHeader('x-tokenlock', 'fail-open'); return next(); }
        res.setHeader('retry-after', '15');
        return send(res, 503, { error: 'Could not check your sign-in right now. Try again in a moment.', code: 'tokenlock_unavailable' });
      }
      if (info?.access && FORBIDDEN_CODES.includes(info.code || '')) return send(res, 403, { error: info.reason || 'Not allowed.', code: info.code, correlation_id: info.correlation_id ?? null });
      if (pass) addCookie(res, signOutCookie(opts, url));
      const to = signInRedirect(opts.signInPage, url, path, search);
      return redirect(res, 302, to.pathname + to.search);
    } catch (e) { return next(e); }
  };
}

/** The signed-in visitor for this request, or null (re-checks the cookie). */
export { getPass } from './core.js';
