import { TokenlockClient, passCookie, clearPassCookie, wantsSecure, safeNext, DEFAULT_COOKIE, type ClientOptions, type PassInfo } from './core.js';

export interface SessionOptions extends ClientOptions {
  /** Cookie name. Default tokenlock_pass */
  cookieName?: string;
  /** Cookie path. Default '/' so every protected path sees it. */
  cookiePath?: string;
  /** Longest a sign-in lasts, in seconds (also capped by the pass). Default 86400. */
  maxAgeSeconds?: number;
  /** Where sign-out sends people. Default '/' */
  afterSignOut?: string;
}

/** Shared pass → cookie exchange. Returns status, JSON body and Set-Cookie. */
export async function exchangePass(client: TokenlockClient, o: SessionOptions, input: { pass: unknown; requestUrl: string; originHeader?: string | null }) {
  // Only accept the exchange from your own pages (stops other sites from planting a pass).
  const self = new URL(input.requestUrl).origin;
  if (input.originHeader && input.originHeader !== self) return { status: 403, body: { ok: false, code: 'bad_origin', error: 'Wrong site.' } };
  const pass = typeof input.pass === 'string' ? input.pass : '';
  let info: PassInfo;
  try { info = await client.verifyPass(pass); }
  catch (e: any) { return { status: 503, body: { ok: false, code: e?.code || 'unavailable', error: 'Could not check the pass right now. Try again.' } }; }
  if (!info.valid) return { status: 401, body: { ok: false, code: info.code || 'bad_pass', error: info.reason || 'Not signed in.' } };
  const cookie = passCookie(pass, info, { name: o.cookieName || DEFAULT_COOKIE, path: o.cookiePath, maxAgeSeconds: o.maxAgeSeconds, secure: wantsSecure(input.requestUrl) });
  return { status: 200, body: { ok: true, address: info.address, assets_held: info.assets_held, expires_at: info.expires_at }, cookie };
}

export function signOutCookie(o: SessionOptions, requestUrl: string) {
  return clearPassCookie({ name: o.cookieName || DEFAULT_COOKIE, path: o.cookiePath, secure: wantsSecure(requestUrl) });
}

export function signInRedirect(signInPage: string, requestUrl: string, path: string, search = '') {
  const u = new URL(signInPage, requestUrl);
  u.searchParams.set('next', safeNext(path + search));
  return u;
}

// ---------------------------------------------------------------- one decision for every adapter
import { createMatcher, canonicalPath, checkAdapterOptions, isApiRequest, isUnavailable, denialStatus, FORBIDDEN_CODES, type Matcher } from './core.js';

export interface GuardOptions extends SessionOptions {
  /** Paths to lock: '/members/:path*', '/admin', RegExp or a function. Matched in canonical form, case-insensitive. */
  protect: Matcher | Matcher[];
  /** Your public sign-in page, e.g. '/signin'. */
  signInPage: string;
  /** Paths that are never locked (besides signInPage). */
  publicPaths?: Matcher | Matcher[];
  /** Sent with each pass check so registered keys are checked against this environment, e.g. 'production'. */
  environment?: string;
  /** Send the request path and method with each pass check (default true). Required in strict mode. */
  checkResource?: boolean;
  /** Fail open when the TOKENLOCK API is down (default false). Not allowed in strict mode. */
  failOpen?: boolean;
  /** Match paths case-sensitively (default false: '/ADMIN' is the same as '/admin'). */
  caseSensitive?: boolean;
  /** Paths that always get JSON 401/403 instead of a redirect, e.g. ['/api/:path*']. Accept: application/json also does. */
  apiPaths?: Matcher | Matcher[];
}
export type GuardDecision =
  | { action: 'skip' }
  | { action: 'allow'; info: PassInfo | null; failOpen?: true }
  | { action: 'json'; status: number; body: Record<string, unknown>; clearCookie: boolean; headers?: Record<string, string> }
  | { action: 'redirect'; location: URL; clearCookie: boolean };

/**
 * The shared protection decision used by the Express and Next.js adapters (and mirrored by the Cloudflare example and
 * PHP drop-in), so every adapter answers the same request the same way.
 */
export function createGuard(opts: GuardOptions, adapter = 'tokenlock') {
  const strict = checkAdapterOptions(opts, adapter);
  const cs = { caseSensitive: !!opts.caseSensitive };
  const isLocked = createMatcher(opts.protect, cs);
  const isPublic = opts.publicPaths ? createMatcher(opts.publicPaths, cs) : () => false;
  const isSignIn = createMatcher(opts.signInPage, cs);
  const isApiPath = opts.apiPaths ? createMatcher(opts.apiPaths, cs) : undefined;
  const name = opts.cookieName || DEFAULT_COOKIE;
  const client = new TokenlockClient({ ...opts, strict });
  return {
    strict, client, cookieName: name,
    async decide(r: { rawPath: string; search?: string; method?: string; accept?: string | null; pass: string | null; url: string }): Promise<GuardDecision> {
      const canon = canonicalPath(r.rawPath || '/');
      if (canon === null) return { action: 'json', status: 400, body: { error: 'Not a valid path.', code: 'bad_path', reason: 'Not a valid path.' }, clearCookie: false };
      if (!isLocked(canon) || isPublic(canon) || isSignIn(canon)) return { action: 'skip' };
      const api = isApiRequest(r.accept, canon, isApiPath);
      const method = (r.method || 'GET').toUpperCase();
      const resource = opts.checkResource === false ? undefined : { path: canon, method, environment: opts.environment };
      let info: PassInfo | null = null;
      if (r.pass) {
        try { info = await client.verifyPass(r.pass, resource, { strict }); }
        catch (e) {
          if (!isUnavailable(e)) throw e;
          if (opts.failOpen && !strict) return { action: 'allow', info: null, failOpen: true };
          return { action: 'json', status: 503, body: { error: 'Could not check your sign-in right now. Try again in a moment.', code: 'tokenlock_unavailable', reason: 'The verification service did not answer; protected access is denied until it does.' }, clearCookie: false, headers: { 'retry-after': '15' } };
        }
        if (info.valid) return { action: 'allow', info };
      }
      const code = info ? info.code || 'bad_pass' : 'signin_required';
      const reason = info?.reason || (info ? 'Not allowed.' : 'Sign in first.');
      const body = { error: reason, code, reason, correlation_id: info?.correlation_id ?? null };
      if (api) { const status = denialStatus(code); return { action: 'json', status, body, clearCookie: !!r.pass && status === 401 }; }
      if (FORBIDDEN_CODES.includes(code)) return { action: 'json', status: 403, body, clearCookie: false };
      return { action: 'redirect', location: signInRedirect(opts.signInPage, r.url, canon, r.search || ''), clearCookie: !!r.pass };
    },
  };
}
