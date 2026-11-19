import { readPass, safeNext, type PassInfo } from './core.js';
import { exchangePass, signOutCookie, createGuard, type GuardOptions } from './session.js';

export * from './core.js';

export interface TokenlockExpressOptions extends GuardOptions {
  /** Pass → cookie endpoint (POST { pass }). Default '/api/tokenlock/session' */
  sessionPath?: string;
  /** Sign-out endpoint. Default '/api/tokenlock/signout' */
  signOutPath?: string;
  /** Behind a proxy, the public origin of your site, e.g. 'https://example.com' (used for cookie and origin checks). */
  publicOrigin?: string;
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
  const guard = createGuard(opts, 'tokenlock (express)', ['sessionPath', 'signOutPath', 'publicOrigin']); // throws at config time (bad_config) for invalid options
  const sessionPath = opts.sessionPath || '/api/tokenlock/session';
  const signOutPath = opts.signOutPath || '/api/tokenlock/signout';

  return async function tokenlockMiddleware(req: Req, res: Res, next: (e?: any) => void) {
    try {
      const raw = req.originalUrl || req.url || '/';
      const qi = raw.search(/[?#]/);
      const path = (qi < 0 ? raw : raw.slice(0, qi)) || '/';
      const search = qi < 0 ? '' : raw.slice(qi).split('#')[0];
      const proto = opts.publicOrigin ? '' : (req.protocol || (req.headers['x-forwarded-proto'] || '').split(',')[0] || 'http');
      const base = opts.publicOrigin || `${proto}://${req.headers.host || 'localhost'}`;
      const url = base + (raw.startsWith('/') ? raw : '/');

      if (path === sessionPath && req.method === 'POST') {
        const body = await readBody(req);
        const r = await exchangePass(guard.client, opts, { pass: body?.pass, requestUrl: url, originHeader: req.headers.origin });
        if (r.cookie) addCookie(res, r.cookie);
        return send(res, r.status, r.body);
      }
      if (path === signOutPath && (req.method === 'POST' || req.method === 'GET')) {
        addCookie(res, signOutCookie(opts, url));
        return redirect(res, 303, safeNext(opts.afterSignOut, '/'));
      }
      const d = await guard.decide({ rawPath: path, search, method: req.method, accept: req.headers.accept, pass: readPass(req as any, guard.cookieName), url });
      if (d.action === 'skip') return next();
      if (d.action === 'allow') {
        req.tokenlock = d.info;
        return next();
      }
      if (d.clearCookie) addCookie(res, signOutCookie(opts, url));
      if (d.action === 'json') { for (const [k, v] of Object.entries(d.headers || {})) res.setHeader(k, v); return send(res, d.status, d.body); }
      return redirect(res, 302, d.location.pathname + d.location.search);
    } catch (e) { return next(e); }
  };
}

/** The signed-in visitor for this request, or null (re-checks the cookie). */
export { getPass, authorize } from './core.js';
