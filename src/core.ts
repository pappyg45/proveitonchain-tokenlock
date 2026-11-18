/**
 * TOKENLOCK core: a tiny client for the Prove It Onchain gate API.
 * Your pages stay on your server. This checks, with your secret key, that a visitor's pass is real,
 * unexpired and was issued for your site. Which tokens unlock your site is set in your dashboard.
 */
export const DEFAULT_API = 'https://proveitonchain.com';
export const DEFAULT_COOKIE = 'tokenlock_pass';
export const VERSION = '0.2.2';

export interface PassInfo {
  /** True only if the pass is real, unexpired, issued for your site and holds a token your site accepts. */
  valid: boolean;
  /** Why it failed: bad_pass, expired, wrong_site, not_holder, bad_secret_key … */
  code?: string;
  reason?: string;
  /** The Bitcoin address that signed in. Proves control of the wallet, not who the person is. */
  address?: string;
  /** Which of your site's tokens that address held when it signed in. */
  assets_held?: string[];
  /** The Bitcoin name they signed in with, if your site lets in any name holder. */
  name?: string | null;
  origin?: string | null;
  site_id?: string | null;
  issued_at?: string;
  expires_at?: string;
  /** Present when you passed a resource (path/method/environment) or the site uses registered keys. */
  allowed?: boolean;
  /** The sign-in request's id; the same id appears in your decision log. */
  correlation_id?: string | null;
  /** Do not cache this answer longer than this many seconds (registered keys: revocation is live). */
  cache_max_s?: number;
  /** Enterprise access controls (sites with registered keys turned on). */
  access?: AccessInfo;
}

/** Enterprise access controls result for one pass and resource. */
export interface AccessInfo {
  mode: 'registered_keys';
  allowed: boolean;
  /** ok, not_registered, pending_approval, key_revoked, key_expired, org_not_approved, org_required, entitlement_revoked, not_holder, route_not_allowed, method_not_allowed, environment_not_allowed … */
  reason: string;
  key: { id: string; label: string; owner_type: 'org' | 'employee' | 'vendor' | 'agent'; owner_name: string | null; org_id: string | null } | null;
  permissions: { routes: string[]; methods: string[]; environments: string[] } | null;
  key_expires_at: string | null;
  resource?: Resource;
}
/** What the visitor is trying to reach. Checked against the key's permissions on sites with registered keys. */
export interface Resource { path?: string; method?: string; environment?: string }

export interface ChallengeInfo {
  challenge_id: string;
  message: string;
  assets: string[];
  any_name: boolean;
  origin: string | null;
  site_id: string | null;
  expires_at: string;
  pass_ttl_seconds: number;
  branding?: { name: string | null; powered_by: boolean } | null;
}

/**
 * Usage returned with a successful sign-in to a TOKENLOCK site. Plans are priced by monthly active wallets:
 * distinct wallets that sign in to any of the account's sites in a calendar month (UTC). Sign-ins are unlimited.
 * Going over never blocks a sign-in; `over` and `note` are informational.
 */
export interface SignInUsage {
  /** Calendar month, YYYY-MM (UTC). */
  month: string;
  /** Distinct wallets that signed in to this account's sites this month. */
  active_wallets: number;
  /** Active wallets included in the account's plan per month. */
  limit: number;
  /** active_wallets / limit, as a whole percent. */
  pct?: number;
  /** True when the account is over its monthly active wallets (sign-ins keep working). */
  over: boolean;
  /** True when this sign-in was the wallet's first this month (it counted). */
  new_wallet?: boolean;
  /** Successful sign-ins to this site this month (informational). */
  site_signins?: number;
  /** Always 'unlimited' now. Older servers returned a number of sign-ins this month. */
  signins: 'unlimited' | number;
  /** Present when over the limit. */
  note?: string;
}
export interface SignInResult extends PassInfo { pass?: string; usage?: SignInUsage }

export interface ClientOptions {
  /** sk_… from your TOKENLOCK dashboard. Server only. Defaults to process.env.TOKENLOCK_SECRET_KEY. */
  secretKey?: string;
  /** pk_… from your dashboard (safe in the browser). Defaults to process.env.TOKENLOCK_SITE_KEY. */
  siteKey?: string;
  /** API origin. Default https://proveitonchain.com */
  apiBase?: string;
  /** Custom fetch (tests, older runtimes). */
  fetch?: typeof fetch;
  /** Request timeout in ms. Default 8000. */
  timeoutMs?: number;
  /**
   * Strict enterprise mode: an answer counts only if it is complete and says `allowed: true` for exactly the
   * resource you asked about (echoed back by the API). Incomplete or unknown answers are denied. Default: on whenever
   * a resource (path/method/environment) is checked; pass false to opt out.
   */
  strict?: boolean;
  /** Cache good answers in memory (default true). In strict mode, answers for registered keys are never cached. */
  cache?: boolean;
}

export class TokenlockError extends Error {
  status: number;
  code?: string;
  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = 'TokenlockError';
    this.status = status;
    this.code = code;
  }
}

const env = (k: string): string | undefined => {
  try { return typeof process !== 'undefined' && process.env ? process.env[k] : undefined; } catch { return undefined; }
};

/** Low-level REST client for /api/v1/gate/*. */
export class TokenlockClient {
  readonly apiBase: string;
  private secretKey?: string;
  private siteKey?: string;
  private fetchImpl: typeof fetch;
  private timeoutMs: number;
  private strict?: boolean;
  private useCache: boolean;

  constructor(opts: ClientOptions = {}) {
    this.strict = opts.strict;
    this.useCache = opts.cache !== false;
    this.apiBase = (opts.apiBase || env('TOKENLOCK_API') || DEFAULT_API).replace(/\/+$/, '');
    this.secretKey = opts.secretKey ?? env('TOKENLOCK_SECRET_KEY');
    this.siteKey = opts.siteKey ?? env('TOKENLOCK_SITE_KEY') ?? env('NEXT_PUBLIC_TOKENLOCK_SITE_KEY');
    const f = opts.fetch ?? (typeof fetch !== 'undefined' ? fetch : undefined);
    if (!f) throw new TokenlockError('No fetch available. Use Node 18+ or pass { fetch }.', 0, 'no_fetch');
    this.fetchImpl = f;
    this.timeoutMs = opts.timeoutMs ?? 8000;
  }

  /** Call any /api/v1 endpoint. Adds the secret key as a Bearer token when set. */
  async request<T = unknown>(method: 'GET' | 'POST', path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
    const ctl = typeof AbortController !== 'undefined' ? new AbortController() : undefined;
    const t = ctl ? setTimeout(() => ctl.abort(), this.timeoutMs) : undefined;
    try {
      const h: Record<string, string> = { accept: 'application/json', 'x-tokenlock-sdk': VERSION, ...headers };
      if (this.secretKey) h.authorization = 'Bearer ' + this.secretKey;
      h['x-tokenlock-sdk'] = 'js/' + VERSION;
      if (body !== undefined) h['content-type'] = 'application/json';
      const r = await this.fetchImpl(this.apiBase + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), signal: ctl?.signal });
      const j = (await r.json().catch(() => null)) as any;
      if (!r.ok) throw new TokenlockError((j && j.error) || `TOKENLOCK API error ${r.status}`, r.status, j && j.code);
      return j as T;
    } catch (e: any) {
      if (e instanceof TokenlockError) throw e;
      throw new TokenlockError(e?.name === 'AbortError' ? 'TOKENLOCK API timed out.' : 'Could not reach the TOKENLOCK API.', 0, 'network');
    } finally { if (t) clearTimeout(t); }
  }

  /**
   * Check a pass with your secret key. Never throws for a bad pass; throws TokenlockError only if the API can't be reached.
   * Give `resource` ({ path, method, environment }) to have the route, method and environment checked too (sites with
   * registered keys); the answer then has `allowed` and `access`.
   */
  async verifyPass(pass: string | null | undefined, resource?: Resource, o: { strict?: boolean; cache?: boolean } = {}): Promise<PassInfo> {
    if (!this.secretKey) throw new TokenlockError('Missing secret key. Set TOKENLOCK_SECRET_KEY or pass { secretKey }.', 0, 'no_secret_key');
    if (!pass || typeof pass !== 'string' || !/^pp1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(pass) || pass.length > 4000) return { valid: false, code: 'bad_pass', reason: 'Not a valid pass.' };
    let res: Resource | null;
    try { res = cleanResource(resource); } catch { return { valid: false, allowed: false, code: 'bad_path', reason: 'Not a valid path.' }; }
    const strict = o.strict ?? this.strict ?? !!res;
    const useCache = (o.cache ?? this.useCache) !== false;
    // One cache entry per (site key, API, pass, mode, method, canonical lowercased path, environment). Every hit is
    // checked again against this request's resource, so a cached answer can never stand in for another path.
    const ck = [keyId(this.secretKey, this.apiBase), pass, strict ? 's' : 'l', res?.method || '', res?.path ?? '', res?.environment || ''].join('\n');
    if (useCache) {
      const hit = cache.get(ck);
      if (hit && hit.until > Date.now() && hit.key === this.secretKey) {
        const again = strict ? strictCheck(hit.info, res) : looseCheck(hit.info, res);
        if (again.valid) return again;
        cache.delete(ck);
      }
    }
    const info = await this.request<PassInfo>('POST', '/api/v1/gate/verify', { pass, ...(res || {}) });
    const out = strict ? strictCheck(info, res) : looseCheck(info, res);
    if (out.valid && useCache && !(strict && out.access)) remember(ck, pass, this.secretKey, out);
    return out;
  }

  /** Start a sign-in (server side or browser). Uses the tokens set for your site in the dashboard. */
  async createChallenge(o: { origin?: string; passTtlSeconds?: number } = {}): Promise<ChallengeInfo> {
    if (!this.siteKey) throw new TokenlockError('Missing site key. Set TOKENLOCK_SITE_KEY or pass { siteKey }.', 0, 'no_site_key');
    return this.request<ChallengeInfo>('POST', '/api/v1/gate/challenge', { site_key: this.siteKey, origin: o.origin, pass_ttl_seconds: o.passTtlSeconds });
  }

  /** Finish a sign-in with the visitor's signature. Returns { valid, pass, … } or { valid:false, code }. */
  async signIn(o: { challengeId: string; address: string; signature: string; name?: string }): Promise<SignInResult> {
    return this.request<SignInResult>('POST', '/api/v1/gate/signin', { challenge_id: o.challengeId, address: o.address, signature: o.signature, name: o.name });
  }
}

/**
 * Canonical request path (TOKENLOCK path rules v1.1, identical in every adapter and on the server). Strips query and
 * fragment, rejects backslashes, control bytes and encoded '/', '\\', NUL, '%' or '.' (no double decoding), decodes
 * once, collapses '//' and drops the trailing slash. Ambiguous forms are rejected outright (null, answered with 400)
 * instead of being resolved: any ';' (path parameters) and any '.' or '..' segment. Frameworks and proxies resolve
 * those differently, so resolving them here could protect a different path than the one your app serves (for
 * example '/admin/..'). Case is kept; matching and the resource sent to the API are case-insensitive (see
 * resourcePath). Returns null when the path must be rejected.
 */
export function canonicalPath(raw: string | null | undefined): string | null {
  let s = String(raw ?? '');
  if (!s || s.length > 2048) return null;
  s = s.split(/[?#]/)[0];
  if (/[\u0000-\u001f\u007f\\;]/.test(s) || /%(2f|5c|00|25|2e|3b)/i.test(s)) return null;
  try { s = decodeURIComponent(s); } catch { return null; }
  if (!s.startsWith('/') || /[\u0000-\u001f\u007f\\;]/.test(s)) return null;
  const out: string[] = [];
  for (const seg of s.split('/')) {
    if (seg === '.' || seg === '..') return null;
    if (seg !== '') out.push(seg);
  }
  return '/' + out.join('/');
}
/** The one form used for the resource sent to the API, the cache key and the answer check: canonical, lowercased. */
export function resourcePath(raw: string | null | undefined): string | null {
  const c = canonicalPath(raw);
  return c === null ? null : c.toLowerCase();
}
function cleanResource(r?: Resource): Resource | null {
  if (!r) return null;
  const out: Resource = {};
  if (typeof r.path === 'string' && r.path) { const c = resourcePath(r.path); if (!c) throw new TokenlockError('Not a valid path.', 400, 'bad_path'); out.path = c; }
  if (typeof r.method === 'string' && r.method) out.method = r.method.toUpperCase().slice(0, 10);
  if (typeof r.environment === 'string' && r.environment) out.environment = r.environment.slice(0, 30);
  return Object.keys(out).length ? out : null;
}
function looseCheck(info: PassInfo, res: Resource | null = null): PassInfo {
  // The server checks the site; double-check the answer is well-formed before trusting it.
  const ok = !!(info && info.valid === true && info.site_id && info.address && info.allowed !== false && info.access?.allowed !== false);
  if (!ok) return { ...info, valid: false, code: info?.code || info?.access?.reason || 'bad_pass' };
  // When the answer echoes a resource it must be this request's resource (compared in the same lowercased form).
  const e: any = (info as any).resource || info.access?.resource;
  if (res && e && !sameResource(res, e)) return { ...info, valid: false, allowed: false, code: 'resource_mismatch' };
  return info;
}
function sameResource(res: Resource, e: any): boolean {
  const ep = typeof e?.path === 'string' ? e.path.toLowerCase() : e?.path ?? null;
  return (res.path ?? null) === ep && (res.method ?? null) === (e?.method ?? null) && (res.environment ?? null) === (e?.environment ?? null);
}
/** Cache namespace for one secret key + API (a short non-reversible fingerprint; the full key is also compared on hit). */
function keyId(key: string | undefined, api: string): string {
  let h1 = 0x811c9dc5, h2 = 0x01000193;
  const s = api + '\n' + (key || '');
  for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); h1 = Math.imul(h1 ^ c, 16777619) >>> 0; h2 = Math.imul(h2 + c, 2246822519) >>> 0; }
  return api + '#' + h1.toString(16) + h2.toString(16);
}
const KNOWN_MODES = ['registered_keys'];
/** Strict enterprise mode: complete answer, explicit allowed === true, for exactly this resource. Anything else is a no. */
function strictCheck(info: PassInfo, res: Resource | null): PassInfo {
  const deny = (code: string): PassInfo => ({ ...(info || {}), valid: false, allowed: false, code: info?.code && info.valid === false ? info.code : code, reason: info?.reason || 'Not allowed.' });
  if (!info || typeof info !== 'object') return deny('bad_answer');
  if (info.valid !== true) return deny(info.code || info.access?.reason || 'bad_pass');
  if (typeof info.address !== 'string' || !info.address || typeof info.site_id !== 'string' || !info.site_id) return deny('incomplete_answer');
  const exp = Date.parse(info.expires_at || ''); if (!(exp > Date.now())) return deny('expired');
  if (info.access !== undefined) {
    if (!info.access || !KNOWN_MODES.includes(info.access.mode) || info.access.allowed !== true) return deny(info.access?.reason || 'not_allowed');
  }
  if (res) {
    if (info.allowed !== true) return deny(info.access?.reason || 'not_allowed');
    const e: any = (info as any).resource || info.access?.resource;
    if (!e) return deny('incomplete_answer');
    if (!sameResource(res, e)) return deny('resource_mismatch');
  } else if (info.allowed === false) return deny('not_allowed');
  return info;
}
// Small in-memory cache of good verifications: at most 60 s (or the server's cache_max_s), never past the pass expiry.
// Entries are indexed by pass so clearCache(pass) drops every resource-specific answer for it.
const cache = new Map<string, { until: number; key: string; info: PassInfo; pass: string }>();
const byPass = new Map<string, Set<string>>();
function remember(ck: string, pass: string, key: string, info: PassInfo) {
  const exp = Date.parse(info.expires_at || '') || 0;
  const maxS = typeof info.cache_max_s === 'number' && info.cache_max_s >= 0 ? Math.min(60, info.cache_max_s) : 60;
  const until = Math.min(Date.now() + maxS * 1000, exp);
  if (until <= Date.now()) return;
  if (cache.size > 500) { const old = cache.keys().next().value as string; const e = cache.get(old); cache.delete(old); if (e) byPass.get(e.pass)?.delete(old); }
  cache.set(ck, { until, key, info, pass });
  let set = byPass.get(pass); if (!set) byPass.set(pass, (set = new Set())); set.add(ck);
}
/** Clear the verification cache: every cached answer for `pass` (all resources), or everything. */
export function clearCache(pass?: string) {
  if (!pass) { cache.clear(); byPass.clear(); return; }
  for (const ck of byPass.get(pass) || []) cache.delete(ck);
  byPass.delete(pass);
}

let shared: TokenlockClient | null = null;
const client = (o?: ClientOptions) => (o && Object.keys(o).length ? new TokenlockClient(o) : (shared ||= new TokenlockClient()));

/** Check a pass. `verifyPass(pass, { secretKey, path, method, environment })` */
export function verifyPass(pass: string | null | undefined, opts: ClientOptions & Resource = {}): Promise<PassInfo> {
  const { path, method, environment, strict, cache: useCache, ...c } = opts;
  return client(c).verifyPass(pass, path || method || environment ? { path, method, environment } : undefined, { strict, cache: useCache });
}
/** True when the error means the TOKENLOCK API couldn't answer (network, timeout, 5xx): not a "no". */
export function isUnavailable(e: unknown): boolean {
  return e instanceof TokenlockError && (e.status === 0 || e.status >= 500) && e.code !== 'no_secret_key';
}
/** Deny reasons that a new sign-in can't fix: answer 403 instead of sending the visitor to sign in again. */
export const FORBIDDEN_CODES = ['route_not_allowed', 'method_not_allowed', 'environment_not_allowed', 'bad_path', 'resource_mismatch'];
/** Deny reasons that mean "signed in, but this key/token may not do this" (API mode answers 403, not 401). */
export const DENIED_CODES = [...FORBIDDEN_CODES, 'key_revoked', 'key_expired', 'pending_approval', 'not_registered', 'org_not_approved', 'org_required', 'entitlement_revoked', 'not_allowed', 'lookup_failed'];
/** HTTP status for a denial in API mode: 401 = no/invalid/expired pass (sign in), 403 = signed in but not allowed. */
export function denialStatus(code: string | undefined): 401 | 403 { return DENIED_CODES.includes(code || '') ? 403 : 401; }

/** Start a sign-in challenge for your site. */
export function createChallenge(opts: ClientOptions & { origin?: string; passTtlSeconds?: number } = {}): Promise<ChallengeInfo> {
  const { origin, passTtlSeconds, ...c } = opts;
  return client(c).createChallenge({ origin, passTtlSeconds });
}

// ---------------------------------------------------------------- cookies & requests
type HeaderBag = { get?: (k: string) => string | null | undefined } | Record<string, string | string[] | undefined>;
export type AnyRequest = { headers: HeaderBag; cookies?: any };

export function parseCookies(header: string | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    if (!k || k in out) continue;
    try { out[k] = decodeURIComponent(part.slice(i + 1).trim()); } catch { out[k] = part.slice(i + 1).trim(); }
  }
  return out;
}
export function headerOf(req: AnyRequest, name: string): string | undefined {
  const h: any = req?.headers;
  if (!h) return undefined;
  if (typeof h.get === 'function') return h.get(name) ?? undefined;
  const v = h[name] ?? h[name.toLowerCase()];
  return Array.isArray(v) ? v.join(', ') : v;
}

/** Read the raw pass from the request cookie (Fetch Request, NextRequest, Node/Express req). */
export function readPass(req: AnyRequest, cookieName = DEFAULT_COOKIE): string | null {
  const c: any = req?.cookies;
  if (c && typeof c.get === 'function') { const v = c.get(cookieName); const s = typeof v === 'string' ? v : v?.value; if (s) return s; }
  else if (c && typeof c[cookieName] === 'string') return c[cookieName];
  return parseCookies(headerOf(req, 'cookie'))[cookieName] || null;
}

/** The signed-in visitor for this request, or null. Checks the pass cookie with your secret key. */
export async function getPass(req: AnyRequest, opts: ClientOptions & { cookieName?: string } & Resource = {}): Promise<PassInfo | null> {
  const { cookieName, path, method, environment, strict, cache: useCache, ...c } = opts;
  const pass = readPass(req, cookieName || DEFAULT_COOKIE);
  if (!pass) return null;
  const info = await client(c).verifyPass(pass, path || method || environment ? { path, method, environment } : undefined, { strict, cache: useCache });
  return info.valid ? info : null;
}
/**
 * Authorize one action: strict, uncached by default, for exactly this resource. Use it for sensitive operations and
 * agent APIs. Returns the pass info when allowed, else { valid:false, allowed:false, code, reason }.
 */
export async function authorize(req: AnyRequest, resource: Resource, opts: ClientOptions & { cookieName?: string } = {}): Promise<PassInfo> {
  const { cookieName, ...c } = opts;
  if (!resource || !resource.path || !resource.method) throw new TokenlockError('authorize() needs { path, method }.', 0, 'resource_required');
  const pass = readPass(req, cookieName || DEFAULT_COOKIE);
  if (!pass) return { valid: false, allowed: false, code: 'signin_required', reason: 'Sign in first.' };
  return client(c).verifyPass(pass, resource, { strict: true, cache: c.cache ?? false });
}

export interface CookieOptions { name?: string; path?: string; secure?: boolean; maxAgeSeconds?: number; sameSite?: 'Lax' | 'Strict' }
/** Set-Cookie value for a verified pass: HttpOnly, Secure, SameSite=Lax, ends when the pass ends. */
export function passCookie(pass: string, info: PassInfo, o: CookieOptions = {}): string {
  const left = Math.floor(((Date.parse(info.expires_at || '') || 0) - Date.now()) / 1000);
  const maxAge = Math.max(0, Math.min(left, o.maxAgeSeconds ?? 86400));
  return `${o.name || DEFAULT_COOKIE}=${encodeURIComponent(pass)}; Path=${o.path || '/'}; Max-Age=${maxAge}; HttpOnly;${o.secure === false ? '' : ' Secure;'} SameSite=${o.sameSite || 'Lax'}`;
}
export function clearPassCookie(o: CookieOptions = {}): string {
  return `${o.name || DEFAULT_COOKIE}=; Path=${o.path || '/'}; Max-Age=0; HttpOnly;${o.secure === false ? '' : ' Secure;'} SameSite=${o.sameSite || 'Lax'}`;
}
/** Secure cookies everywhere except plain-http localhost during development. */
export function wantsSecure(url: string): boolean {
  try { const u = new URL(url); return !(u.protocol === 'http:' && /^(localhost|127\.0\.0\.1|\[::1\])$/.test(u.hostname)); } catch { return true; }
}

// ---------------------------------------------------------------- path matching
export type Matcher = string | RegExp | ((path: string) => boolean);
/**
 * Next-style patterns: '/members', '/members/:path*', '/docs/:slug', '/admin/*'. Also RegExp or a function.
 * Paths are matched in canonical form (see canonicalPath) and case-insensitively unless { caseSensitive: true }.
 * RegExp and function matchers get the canonical path (lower-cased unless caseSensitive).
 */
export function createMatcher(protect: Matcher | Matcher[], o: { caseSensitive?: boolean } = {}): (path: string) => boolean {
  const flags = o.caseSensitive ? '' : 'i';
  const list = (Array.isArray(protect) ? protect : [protect]).map((m) => {
    if (typeof m === 'function') return m;
    if (m instanceof RegExp) return (p: string) => m.test(p);
    const src = String(m).replace(/\/+$/, '') || '/';
    const re = new RegExp('^' + src
      .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
      .replace(/\/:[A-Za-z0-9_]+\*/g, '(?:/.*)?')
      .replace(/\/:[A-Za-z0-9_]+\+/g, '/.+')
      .replace(/:[A-Za-z0-9_]+/g, '[^/]+')
      .replace(/\/\*$/, '(?:/.*)?')
      .replace(/\*/g, '.*') + '/?$', flags);
    return (p: string) => re.test(p);
  });
  return (path: string) => {
    const c = canonicalPath(path);
    if (c === null) return true; // unparseable paths are treated as locked (and rejected by the adapters)
    const p = o.caseSensitive ? c : c.toLowerCase();
    return list.some((f) => f(p));
  };
}
/** Is this an API request (JSON answers instead of redirects)? Accept: application/json, or a configured API path. */
export function isApiRequest(accept: string | null | undefined, path: string, apiPaths?: (p: string) => boolean): boolean {
  if (apiPaths && apiPaths(path)) return true;
  const a = String(accept || '').toLowerCase();
  return a.includes('application/json') && !a.includes('text/html');
}
/**
 * Config-time checks shared by the adapters. Strict is the default. Setting failOpen: true or checkResource: false
 * without strict turns strict off with a loud warning (0.2.0 configs keep working); with strict: true it throws.
 */
export function checkAdapterOptions(o: { strict?: boolean; failOpen?: boolean; checkResource?: boolean }, name: string) {
  const unsafe = !!o.failOpen || o.checkResource === false;
  if (o.strict === true && o.failOpen) throw new TokenlockError(`${name}: failOpen cannot be used with strict: true. Remove one; failOpen is for low-risk content only.`, 0, 'bad_config');
  if (o.strict === true && o.checkResource === false) throw new TokenlockError(`${name}: checkResource: false cannot be used with strict: true.`, 0, 'bad_config');
  const strict = o.strict ?? !unsafe;
  if (!strict && typeof console !== 'undefined') console.warn(`[TOKENLOCK] WARNING ${name}: strict mode is OFF${o.failOpen ? '; failOpen lets requests through UNVERIFIED when the API is down' : ''}${o.checkResource === false ? '; routes, methods and environments are NOT checked' : ''}. Use only for low-risk content.`)
  return strict;
}

/**
 * A safe same-site path to go back to after sign-in, or `fallback` ('/'). Only a relative path that starts with a
 * single '/' is allowed. Rejected: '//' and '/\\' (other sites), any backslash, control characters, tabs and newlines
 * (browsers strip them, so '/\t/evil.com' would become '//evil.com'), schemes ('javascript:', 'https://') and anything that still looks like one
 * of those after decoding up to three times ('/%2f%2fevil.com', '/%5cevil.com'). It has no dependencies, so a sign-in page
 * can ship it to the browser as `const tlSafeNext = ${safeNext.toString()};`. Same rules as tokenlock_safe_next() in PHP.
 */
export function safeNext(v: string | null | undefined, fallback = '/'): string {
  if (typeof v !== 'string' || !v || v.length > 2000) return fallback;
  let d = v;
  for (let i = 0; i < 4; i++) {
    if (d[0] !== '/' || d[1] === '/' || d[1] === '\\' || /[\u0000-\u001f\u007f-\u009f\\\u2028\u2029]/.test(d)) return fallback;
    if (!/%[0-9a-f]{2}/i.test(d)) return v;
    let n: string;
    try { n = decodeURIComponent(d); } catch { return fallback; }
    if (n === d) return v;
    d = n;
  }
  return fallback;
}
