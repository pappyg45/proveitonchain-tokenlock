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
  try { info = await client.verifyPass(pass, { identityOnly: true }); }
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
import { ENVIRONMENT_RE, createMatcher, canonicalPath, checkClientOptions, isApiRequest, isUnavailable, denialStatus, FORBIDDEN_CODES, SECRET_KEY_RE, badConfig, type Matcher } from './core.js';

export interface GuardOptions extends SessionOptions {
  /** Paths to lock: '/members/:path*', '/admin', RegExp or a function. Matched in canonical form, case-insensitive. */
  protect: Matcher | Matcher[];
  /** Your public sign-in page, e.g. '/signin'. */
  signInPage: string;
  /** Paths that are never locked (besides signInPage). */
  publicPaths?: Matcher | Matcher[];
  /** Sent with each pass check so registered keys are checked against this environment, e.g. 'production'. */
  environment?: string;
  /**
   * Token-only sites (registered keys off): set `true` to state that every holder of your site's token may open every
   * protected path. Passes are then checked for identity and token only. If the site has registered keys, the route,
   * method and environment are still checked. Without it, 0.4.0 denies protected paths on token-only sites with
   * `policy_required` (403), because no route policy explicitly permits them.
   */
  tokenOnly?: boolean;
  /** Match paths case-sensitively (default false: '/ADMIN' is the same as '/admin'). */
  caseSensitive?: boolean;
  /** Paths that always get JSON 401/403 instead of a redirect, e.g. ['/api/:path*']. Accept: application/json also does. */
  apiPaths?: Matcher | Matcher[];
}
export type GuardDecision =
  | { action: 'skip' }
  | { action: 'allow'; info: PassInfo }
  | { action: 'json'; status: number; body: Record<string, unknown>; clearCookie: boolean; headers?: Record<string, string> }
  | { action: 'redirect'; location: URL; clearCookie: boolean };

/**
 * The shared protection decision used by the Express and Next.js adapters (and mirrored by the Cloudflare example and
 * PHP drop-in), so every adapter answers the same request the same way.
 */
const GUARD_KEYS = ['protect', 'signInPage', 'publicPaths', 'environment', 'tokenOnly', 'caseSensitive', 'apiPaths', 'cookieName', 'cookiePath', 'maxAgeSeconds', 'afterSignOut',
  'secretKey', 'siteKey', 'apiBase', 'fetch', 'timeoutMs', 'strict', 'cache'];
const isMatcher = (m: unknown) => (typeof m === 'string' && m.trim() !== '') || m instanceof RegExp || typeof m === 'function';
/**
 * Config-time validation for the middleware (0.4.2). Throws TokenlockError code 'bad_config' for: removed options
 * (failOpen, checkResource), strict:false, unknown options (typos such as `tokenonly`), wrong types (e.g. tokenOnly:'false'),
 * a missing or malformed secret key, an empty protect list or a missing sign-in page. Nothing is silently ignored.
 */
export function validateGuardOptions(opts: Record<string, any>, adapter: string, extraKeys: string[] = []) {
  if (!opts || typeof opts !== 'object') throw badConfig(`${adapter}: options are required.`);
  checkClientOptions(opts, adapter);
  const known = new Set([...GUARD_KEYS, ...extraKeys]);
  for (const k of Object.keys(opts)) if (!known.has(k)) throw badConfig(`${adapter}: unknown option "${k}". Check the spelling; unknown options are refused so a typo can't weaken protection.`);
  const list = (v: unknown, name: string, required: boolean) => {
    if (v === undefined && !required) return;
    const a = Array.isArray(v) ? v : [v];
    if ((required && !a.length) || !a.every(isMatcher)) throw badConfig(`${adapter}: ${name} must be a path pattern, RegExp or function, or a non-empty list of them.`);
  };
  list(opts.protect, 'protect', true);
  list(opts.publicPaths, 'publicPaths', false);
  list(opts.apiPaths, 'apiPaths', false);
  if (typeof opts.signInPage !== 'string' || !opts.signInPage.trim()) throw badConfig(`${adapter}: signInPage must be your sign-in page path, e.g. '/signin'.`);
  for (const k of ['tokenOnly', 'caseSensitive']) if (opts[k] !== undefined && typeof opts[k] !== 'boolean') throw badConfig(`${adapter}: ${k} must be true or false.`);
  for (const k of ['environment', 'cookieName', 'cookiePath', 'afterSignOut', ...extraKeys.filter((x) => x !== 'maxAgeSeconds')]) if (opts[k] !== undefined && typeof opts[k] !== 'string') throw badConfig(`${adapter}: ${k} must be a string.`);
  if (opts.environment !== undefined && !ENVIRONMENT_RE.test(opts.environment)) throw badConfig(`${adapter}: environment must be 1–30 letters, digits, '_', '.' or '-' (no spaces, not empty).`);
  if (opts.maxAgeSeconds !== undefined && !(typeof opts.maxAgeSeconds === 'number' && Number.isFinite(opts.maxAgeSeconds) && opts.maxAgeSeconds >= 0)) throw badConfig(`${adapter}: maxAgeSeconds must be a number of seconds.`);
  const sk = opts.secretKey ?? (typeof process !== 'undefined' && process.env ? process.env.TOKENLOCK_SECRET_KEY : undefined);
  if (typeof sk !== 'string' || !SECRET_KEY_RE.test(sk)) throw badConfig(`${adapter}: a secret key is required (sk_… from your dashboard): set TOKENLOCK_SECRET_KEY or pass { secretKey }.`);
}

export function createGuard(opts: GuardOptions, adapter = 'tokenlock', extraKeys: string[] = []) {
  validateGuardOptions(opts as any, adapter, extraKeys);
  const strict = true as const;
  const cs = { caseSensitive: !!opts.caseSensitive };
  const isLocked = createMatcher(opts.protect, cs);
  const isPublic = opts.publicPaths ? createMatcher(opts.publicPaths, cs) : () => false;
  const isSignIn = createMatcher(opts.signInPage, cs);
  const isApiPath = opts.apiPaths ? createMatcher(opts.apiPaths, cs) : undefined;
  const name = opts.cookieName || DEFAULT_COOKIE;
  const client = new TokenlockClient({ secretKey: opts.secretKey, siteKey: opts.siteKey, apiBase: opts.apiBase, fetch: opts.fetch, timeoutMs: opts.timeoutMs, cache: opts.cache });
  let warnedNoPolicy = false;
  return {
    strict, client, cookieName: name,
    async decide(r: { rawPath: string; search?: string; method?: string; accept?: string | null; pass: string | null; url: string }): Promise<GuardDecision> {
      const canon = canonicalPath(r.rawPath || '/');
      if (canon === null) return { action: 'json', status: 400, body: { error: 'Not a valid path.', code: 'bad_path', reason: 'Not a valid path.' }, clearCookie: false };
      if (!isLocked(canon) || isPublic(canon) || isSignIn(canon)) return { action: 'skip' };
      const api = isApiRequest(r.accept, canon, isApiPath);
      const method = (r.method || 'GET').toUpperCase();
      const resource = { path: canon, method, ...(opts.environment !== undefined ? { environment: opts.environment } : {}) };
      let info: PassInfo | null = null;
      if (r.pass) {
        try {
          if (opts.tokenOnly) {
            // Identity + token check; if the site turns out to have a route policy (registered keys), enforce it.
            info = await client.verifyPass(r.pass, { identityOnly: true }, { strict });
            if (info.valid && info.access !== undefined) info = await client.verifyPass(r.pass, resource, { strict });
          } else {
            info = await client.verifyPass(r.pass, resource, { strict });
            if (info.code === 'policy_required' && info.identity_valid && !warnedNoPolicy) { warnedNoPolicy = true; if (typeof console !== 'undefined') console.warn(`[TOKENLOCK] ${adapter}: this site has no route policy (registered keys are off), so protected paths are denied with policy_required. If every token holder may open them, set tokenOnly: true. See https://proveitonchain.com/security/advisories/2026-11-18`); }
          }
        }
        catch (e) {
          if (!isUnavailable(e)) throw e;
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
