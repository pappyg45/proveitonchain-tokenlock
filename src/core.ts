/**
 * TOKENLOCK core: a tiny client for the Prove It Onchain gate API.
 * Your pages stay on your server. This checks, with your secret key, that a visitor's pass is real,
 * unexpired and was issued for your site. Which tokens unlock your site is set in your dashboard.
 */
export const DEFAULT_API = 'https://proveitonchain.com';
export const DEFAULT_COOKIE = 'tokenlock_pass';
export const VERSION = '0.1.1';

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
}

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

  constructor(opts: ClientOptions = {}) {
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

  /** Check a pass with your secret key. Never throws for a bad pass; throws TokenlockError only if the API can't be reached. */
  async verifyPass(pass: string | null | undefined): Promise<PassInfo> {
    if (!this.secretKey) throw new TokenlockError('Missing secret key. Set TOKENLOCK_SECRET_KEY or pass { secretKey }.', 0, 'no_secret_key');
    if (!pass || typeof pass !== 'string' || !/^pp1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(pass) || pass.length > 4000) return { valid: false, code: 'bad_pass', reason: 'Not a valid pass.' };
    const hit = cache.get(pass);
    if (hit && hit.until > Date.now() && hit.key === this.secretKey) return hit.info;
    const info = await this.request<PassInfo>('POST', '/api/v1/gate/verify', { pass });
    // The server checks the site; double-check the answer is well-formed before trusting it.
    const ok = !!(info && info.valid === true && info.site_id && info.address);
    const out: PassInfo = ok ? info : { ...info, valid: false, code: info?.code || 'bad_pass' };
    if (out.valid) remember(pass, this.secretKey, out);
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

// Small in-memory cache of good verifications: at most 60 s, never past the pass expiry.
const cache = new Map<string, { until: number; key: string; info: PassInfo }>();
function remember(pass: string, key: string, info: PassInfo) {
  const exp = Date.parse(info.expires_at || '') || 0;
  const until = Math.min(Date.now() + 60_000, exp);
  if (until <= Date.now()) return;
  if (cache.size > 500) cache.delete(cache.keys().next().value as string);
  cache.set(pass, { until, key, info });
}
/** Clear the verification cache (tests, or after a sign-out). */
export function clearCache(pass?: string) { if (pass) cache.delete(pass); else cache.clear(); }

let shared: TokenlockClient | null = null;
const client = (o?: ClientOptions) => (o && Object.keys(o).length ? new TokenlockClient(o) : (shared ||= new TokenlockClient()));

/** Check a pass. `verifyPass(pass, { secretKey })` */
export function verifyPass(pass: string | null | undefined, opts: ClientOptions = {}): Promise<PassInfo> { return client(opts).verifyPass(pass); }

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
export async function getPass(req: AnyRequest, opts: ClientOptions & { cookieName?: string } = {}): Promise<PassInfo | null> {
  const { cookieName, ...c } = opts;
  const pass = readPass(req, cookieName || DEFAULT_COOKIE);
  if (!pass) return null;
  const info = await client(c).verifyPass(pass);
  return info.valid ? info : null;
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
/** Next-style patterns: '/members', '/members/:path*', '/docs/:slug', '/admin/*'. Also RegExp or a function. */
export function createMatcher(protect: Matcher | Matcher[]): (path: string) => boolean {
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
      .replace(/\*/g, '.*') + '/?$');
    return (p: string) => re.test(p);
  });
  return (path: string) => list.some((f) => f(path));
}

/** A safe same-site path to go back to after sign-in (blocks //evil.com and absolute URLs). */
export function safeNext(v: string | null | undefined, fallback = '/'): string {
  if (!v || typeof v !== 'string' || !v.startsWith('/') || v.startsWith('//') || v.startsWith('/\\')) return fallback;
  return v.slice(0, 2000);
}
