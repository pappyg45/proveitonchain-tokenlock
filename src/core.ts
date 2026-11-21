/**
 * TOKENLOCK core: a tiny client for the Prove It Onchain gate API.
 * Your pages stay on your server. This checks, with your secret key, that a visitor's pass is real,
 * unexpired and was issued for your site. Which tokens unlock your site is set in your dashboard.
 */
export const DEFAULT_API = 'https://proveitonchain.com';
export const DEFAULT_COOKIE = 'tokenlock_pass';
export const VERSION = '0.5.0';

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
  /** On a `policy_required` denial: true when the pass itself (identity and token) is good but no route policy applies. */
  identity_valid?: boolean;
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
/** 0.4.3: an identity-only check must be asked for explicitly. */
export interface IdentityOnly { identityOnly: true }

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
   * Strict mode is always on since 0.4.2: an answer counts only if it is complete, unambiguous and says
   * `allowed: true` for exactly the resource you asked about (echoed back by the API). Anything else is denied.
   * `strict: true` is accepted for older configs; `strict: false` (loose mode) was removed and is a config error.
   */
  strict?: true;
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
    checkClientOptions(opts as any, 'TokenlockClient');
    this.strict = true;
    this.useCache = opts.cache !== false;
    this.apiBase = (opts.apiBase || env('TOKENLOCK_API') || DEFAULT_API).replace(/\/+$/, '');
    this.secretKey = opts.secretKey ?? env('TOKENLOCK_SECRET_KEY');
    this.siteKey = opts.siteKey ?? env('TOKENLOCK_SITE_KEY') ?? env('NEXT_PUBLIC_TOKENLOCK_SITE_KEY');
    if (this.secretKey !== undefined && !SECRET_KEY_RE.test(String(this.secretKey))) throw badConfig('TokenlockClient: the secret key is not an sk_… secret key (check TOKENLOCK_SECRET_KEY / secretKey).');
    if (!validApiBase(this.apiBase)) throw badConfig('TokenlockClient: apiBase / TOKENLOCK_API must be an http(s) URL.');
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
      // 0.4.2: answers are capped (MAX_ANSWER_BYTES) and must be a JSON object; anything else is a bad answer (502 → denied).
      const len = Number(r.headers?.get?.('content-length') || 0);
      if (len > MAX_ANSWER_BYTES) throw new TokenlockError('TOKENLOCK API answer is too large.', 502, 'bad_answer');
      const text = typeof r.text === 'function' ? await r.text().catch(() => '') : typeof (r as any).json === 'function' ? JSON.stringify(await (r as any).json().catch(() => null)) : '';
      if (text.length > MAX_ANSWER_BYTES) throw new TokenlockError('TOKENLOCK API answer is too large.', 502, 'bad_answer');
      let j: any = null; try { j = text ? JSON.parse(text) : null; } catch { j = null; }
      if (!r.ok) throw new TokenlockError((isObj(j) && typeof j.error === 'string' && j.error) || `TOKENLOCK API error ${r.status}`, r.status, isObj(j) && typeof j.code === 'string' ? j.code : undefined);
      if (!isObj(j)) throw new TokenlockError('TOKENLOCK API answered with something that is not a JSON object.', 502, 'bad_answer');
      return j as T;
    } catch (e: any) {
      if (e instanceof TokenlockError) throw e;
      throw new TokenlockError(e?.name === 'AbortError' ? 'TOKENLOCK API timed out.' : 'Could not reach the TOKENLOCK API.', 0, 'network');
    } finally { if (t) clearTimeout(t); }
  }

  /**
   * Check a pass with your secret key. A bad, expired or out-of-scope pass is an answer (`valid: false` + `code`), not
   * an exception. Throws `TokenlockError` when no answer could be obtained:
   * - `code: 'no_secret_key'` (status 0): no secret key configured (option or `TOKENLOCK_SECRET_KEY`);
   * - `code: 'no_fetch'` (status 0, from the constructor): no `fetch` in this runtime;
   * - `code: 'network'` (status 0): the API could not be reached or timed out (`timeoutMs`, default 8000);
   * - any non-2xx HTTP answer: `status` is the HTTP status (e.g. 400, 429 rate limited, 5xx) and `code` the API's code.
   * `isUnavailable(e)` is true for network, timeout and 5xx errors. Fail closed on every error in protected routes.
   * Give `resource` ({ path, method, environment }) to have the route, method and environment checked too (sites with
   * registered keys); the answer then has `allowed` and `access`.
   */
  async verifyPass(pass: string | null | undefined, resource: Resource | IdentityOnly, o: { strict?: boolean; cache?: boolean } = {}): Promise<PassInfo> {
    if (o && o.strict !== undefined && o.strict !== true) throw badConfig('verifyPass: strict: false (loose mode) was removed in 0.4.2; answers are always checked strictly.');
    if (o && o.cache !== undefined && typeof o.cache !== 'boolean') throw badConfig('verifyPass: cache must be true or false.');
    if (!this.secretKey) throw new TokenlockError('Missing secret key. Set TOKENLOCK_SECRET_KEY or pass { secretKey }.', 0, 'no_secret_key');
    // 0.4.3: the authorization request is validated first. A malformed one is refused (bad_resource / bad_path) and is
    // never sent as an identity-only check; an identity-only check must be asked for with { identityOnly: true }.
    let res: Resource | null;
    try { res = validateResource(resource, 'verifyPass'); } catch (e: any) { if (e?.code === 'bad_path') return { valid: false, allowed: false, code: 'bad_path', reason: 'Not a valid path.' }; throw e; }
    if (!pass || typeof pass !== 'string' || !/^pp1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(pass) || pass.length > 4000) return { valid: false, code: 'bad_pass', reason: 'Not a valid pass.' };
    const strict = true; // 0.4.2: always strict
    const useCache = (o.cache ?? this.useCache) !== false;
    // One cache entry per (site key, API, pass, mode, method, canonical lowercased path, environment). Every hit is
    // checked again against this request's resource, so a cached answer can never stand in for another path.
    const ck = [keyId(this.secretKey, this.apiBase), pass, strict ? 's' : 'l', res?.method || '', res?.path ?? '', res?.environment || ''].join('\n');
    if (useCache) {
      const hit = cache.get(ck);
      if (hit && hit.until > Date.now() && hit.key === this.secretKey) {
        const again = strictCheck(hit.info, res);
        if (again.valid) return again;
        cache.delete(ck);
      }
    }
    const info = await this.request<PassInfo>('POST', '/api/v1/gate/verify', res ? { pass, ...res } : { pass, identity_only: true });
    const out = strictCheck(info, res);
    if (out.valid && useCache && !out.access) remember(ck, pass, this.secretKey, out);
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
export const RESOURCE_KEYS = ['path', 'method', 'environment'] as const;
export const METHOD_RE = /^[A-Za-z]{1,10}$/;
export const ENVIRONMENT_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,29}$/;
const badResource = (m: string) => new TokenlockError(m, 400, 'bad_resource');
const IDENTITY_HINT = 'Pass { path, method } (and optionally environment) to authorize a route, or { identityOnly: true } for an identity-only check.';
/**
 * 0.4.3: the one schema for an authorization request, used by every entry point (verifyPass, TokenlockClient.verifyPass,
 * getPass, authorize, the middleware and self-verify). Returns the canonical resource, or null for an explicit
 * identity-only request ({ identityOnly: true } and nothing else). Throws TokenlockError 'bad_resource' for anything
 * else: not a plain object, unknown fields, a path without a method (or the reverse), values that are not strings or
 * are empty, whitespace-only or padded, null/undefined values, over-long methods or environments (never truncated);
 * and 'bad_path' for a path that is relative or fails the canonical path rules (a query or fragment is dropped, as in path rules v1.1).
 * A malformed request can therefore never become an identity-only check.
 */
export function validateResource(r: unknown, name = 'verifyPass'): Resource | null {
  const proto = r !== null && typeof r === 'object' ? Object.getPrototypeOf(r) : undefined;
  if (r === null || typeof r !== 'object' || Array.isArray(r) || (proto !== Object.prototype && proto !== null)) throw badResource(`${name}: missing or malformed authorization request. ${IDENTITY_HINT}`);
  const o = r as Record<string, unknown>; const keys = Object.keys(o);
  const has = (k: string) => Object.prototype.hasOwnProperty.call(o, k); // own fields only (0.4.4: never an inherited/polluted one)
  for (const k of keys) if (k !== 'identityOnly' && !(RESOURCE_KEYS as readonly string[]).includes(k)) throw badResource(`${name}: unknown authorization field "${k}". ${IDENTITY_HINT}`);
  if (has('identityOnly')) {
    if (o.identityOnly !== true || keys.length !== 1) throw badResource(`${name}: identityOnly must be exactly true and can't be combined with path, method or environment.`);
    return null;
  }
  if (!has('path') || !has('method')) throw badResource(`${name}: an authorization request needs both path and method. ${IDENTITY_HINT}`);
  const str = (k: string) => { const v = o[k]; if (typeof v !== 'string' || v === '' || v.trim() !== v) throw badResource(`${name}: ${k} must be a non-empty string without surrounding whitespace.`); return v; };
  const path = str('path');
  if (!path.startsWith('/')) throw new TokenlockError('Not a valid path.', 400, 'bad_path');
  const cp = resourcePath(path); if (!cp) throw new TokenlockError('Not a valid path.', 400, 'bad_path');
  const method = str('method'); if (!METHOD_RE.test(method)) throw badResource(`${name}: method must be an HTTP method name (letters only, at most 10).`);
  const out: Resource = { path: cp, method: method.toUpperCase() };
  if (has('environment')) { const e = str('environment'); if (!ENVIRONMENT_RE.test(e)) throw badResource(`${name}: environment must be 1–30 letters, digits, '_', '.' or '-'.`); out.environment = e; }
  return out;
}
const CLIENT_KEYS = ['secretKey', 'siteKey', 'apiBase', 'fetch', 'timeoutMs', 'cache', 'strict'];
/** Split a combined options object into client options and the authorization request (keys present only). Unknown keys are refused. */
export function splitAuthOptions(opts: Record<string, any>, name: string, extra: string[] = []): { client: Record<string, any>; request: Record<string, any> | undefined; extra: Record<string, any> } {
  if (opts === null || typeof opts !== 'object' || Array.isArray(opts)) throw badResource(`${name}: options must be an object.`);
  const client: Record<string, any> = {}, request: Record<string, any> = {}, ex: Record<string, any> = {};
  let hasReq = false;
  for (const k of Object.keys(opts)) {
    if ((RESOURCE_KEYS as readonly string[]).includes(k) || k === 'identityOnly') { request[k] = opts[k]; hasReq = true; }
    else if (CLIENT_KEYS.includes(k) || k in REMOVED_OPTIONS) client[k] = opts[k];
    else if (extra.includes(k)) ex[k] = opts[k];
    else throw badResource(`${name}: unknown option or authorization field "${k}". ${IDENTITY_HINT}`);
  }
  return { client, request: hasReq ? request : undefined, extra: ex };
}
/** 0.4.0: a resource is granted only by a route policy (registered keys). A valid answer with no access block means none applied. */
function noPolicy(info: PassInfo): PassInfo {
  return { ...info, valid: false, allowed: false, identity_valid: true, code: 'policy_required', reason: POLICY_REQUIRED_REASON };
}
export const POLICY_REQUIRED_REASON = 'No route policy applies (registered keys are off), so this path, method or environment cannot be authorized. Check identity only, or turn on registered keys and grant the route. Token-only sites using the middleware: set tokenOnly: true.';
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
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;
const isObj = (v: unknown): v is Record<string, any> => !!v && typeof v === 'object' && !Array.isArray(v);
/**
 * Strict mode (the only mode since 0.4.2): a complete, unambiguous answer that says allowed === true for exactly this
 * resource. Wrong types, missing fields, contradictions (valid:true with an error code, allowed vs access.allowed,
 * two echoes naming different resources, an access reason other than ok) and unknown modes are all a no.
 */
function strictCheck(info: PassInfo, res: Resource | null): PassInfo {
  const deny = (code: string): PassInfo => ({ ...(isObj(info) ? info : {}), valid: false, allowed: false, code: isObj(info) && info.valid === false && typeof info.code === 'string' && info.code ? info.code : code, reason: (isObj(info) && typeof info.reason === 'string' && info.reason) || 'Not allowed.' });
  if (!isObj(info)) return deny('bad_answer');
  const i: any = info;
  if (i.valid !== true) return deny(typeof i.code === 'string' && i.code ? i.code : (isObj(i.access) && typeof i.access.reason === 'string' && i.access.reason) || 'bad_pass');
  // contradictions: a "yes" that also carries an error, a denial code or a failed identity is ambiguous → no
  if ((i.code !== undefined && i.code !== null && i.code !== 'ok') || i.error !== undefined || ('identity_valid' in i && i.identity_valid !== true)) return { ...deny('conflicting_answer'), code: typeof i.code === 'string' && /^[a-z_]{1,64}$/.test(i.code) && i.code !== 'ok' ? i.code : 'conflicting_answer' };
  if (typeof i.address !== 'string' || !i.address || typeof i.site_id !== 'string' || !i.site_id) return deny('incomplete_answer');
  if (i.assets_held !== undefined && !Array.isArray(i.assets_held)) return deny('incomplete_answer');
  if (typeof i.expires_at !== 'string' || !ISO_TIME.test(i.expires_at)) return deny('incomplete_answer');
  const exp = Date.parse(i.expires_at); if (!(exp > Date.now())) return deny('expired');
  if (res && i.access === undefined) return noPolicy(info);
  if ('allowed' in i && i.allowed !== true) return deny(isObj(i.access) && typeof i.access.reason === 'string' && i.access.reason !== 'ok' ? i.access.reason : 'not_allowed');
  if (i.access !== undefined) {
    const a = i.access;
    if (!isObj(a) || !KNOWN_MODES.includes(a.mode) || a.allowed !== true) return deny((isObj(a) && typeof a.reason === 'string' && a.reason) || 'not_allowed');
    if (a.reason !== undefined && a.reason !== 'ok') return deny('conflicting_answer');
  }
  const echoes = [i.resource, isObj(i.access) ? i.access.resource : undefined].filter((e) => e !== undefined && e !== null);
  if (res) {
    if (i.allowed !== true) return deny('not_allowed');
    if (!echoes.length) return deny('incomplete_answer');
    for (const e of echoes) { if (!isObj(e)) return deny('incomplete_answer'); if (!sameResource(res, e)) return deny('resource_mismatch'); }
  } else if (echoes.some((e) => !isObj(e) || e.path != null || e.method != null || e.environment != null)) return deny('conflicting_answer'); // an identity answer must not name a resource
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

/** Check a pass. `verifyPass(pass, { secretKey, path, method, environment })`. Throws `TokenlockError` (see TokenlockClient.verifyPass). */
export async function verifyPass(pass: string | null | undefined, opts: ClientOptions & (Resource | IdentityOnly | {}) = {}): Promise<PassInfo> {
  const { client: c, request } = splitAuthOptions(opts as any, 'verifyPass');
  const { strict, cache: useCache, ...rest } = c;
  checkClientOptions(c, 'verifyPass');
  let res: Resource | null; // throws before any network call; null = explicit identity-only
  try { res = validateResource(request, 'verifyPass'); } catch (e: any) { if (e?.code === 'bad_path') return { valid: false, allowed: false, code: 'bad_path', reason: 'Not a valid path.' }; throw e; }
  return client(rest).verifyPass(pass, res ?? { identityOnly: true }, { strict, cache: useCache });
}
/** True when the error means the TOKENLOCK API couldn't answer (network, timeout, 5xx): not a "no". */
export function isUnavailable(e: unknown): boolean {
  return e instanceof TokenlockError && (e.status === 0 || e.status >= 500) && e.code !== 'no_secret_key';
}
/** Deny reasons that a new sign-in can't fix: answer 403 instead of sending the visitor to sign in again. */
export const FORBIDDEN_CODES = ['route_not_allowed', 'method_not_allowed', 'environment_not_allowed', 'bad_path', 'resource_mismatch', 'policy_required'];
/** Deny reasons that mean "signed in, but this key/token may not do this" (API mode answers 403, not 401). */
export const DENIED_CODES = [...FORBIDDEN_CODES, 'key_revoked', 'key_expired', 'pending_approval', 'not_registered', 'org_not_approved', 'org_required', 'entitlement_revoked', 'not_allowed', 'lookup_failed'];
/** HTTP status for a denial in API mode: 401 = no/invalid/expired pass (sign in), 403 = signed in but not allowed. */
export function denialStatus(code: string | undefined): 401 | 403 { return DENIED_CODES.includes(code || '') ? 403 : 401; }

/** Start a sign-in challenge for your site. */
export async function createChallenge(opts: ClientOptions & { origin?: string; passTtlSeconds?: number } = {}): Promise<ChallengeInfo> {
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
export async function getPass(req: AnyRequest, opts: ClientOptions & { cookieName?: string } & (Resource | IdentityOnly | {}) = {}): Promise<PassInfo | null> {
  const { client: c, request, extra } = splitAuthOptions(opts as any, 'getPass', ['cookieName']);
  const { strict, cache: useCache, ...rest } = c;
  checkClientOptions(c, 'getPass');
  const res = validateResource(request, 'getPass'); // 0.4.3: a route or { identityOnly: true }; never inferred
  const pass = readPass(req, extra.cookieName || DEFAULT_COOKIE);
  if (!pass) return null;
  const info = await client(rest).verifyPass(pass, res ?? { identityOnly: true }, { strict, cache: useCache });
  return info.valid ? info : null;
}
/**
 * Authorize one action: strict, uncached by default, for exactly this resource. Use it for sensitive operations and
 * agent APIs. Returns the pass info when allowed, else { valid:false, allowed:false, code, reason }.
 */
export async function authorize(req: AnyRequest, resource: Resource, opts: ClientOptions & { cookieName?: string } = {}): Promise<PassInfo> {
  const { client: c, extra } = splitAuthOptions(opts as any, 'authorize', ['cookieName']);
  for (const k of RESOURCE_KEYS) if (k in c) throw badResource('authorize: pass the resource as the second argument.');
  checkClientOptions(c, 'authorize');
  const res = authorizeResource(resource);
  if (res === 'bad_path') return { valid: false, allowed: false, code: 'bad_path', reason: 'Not a valid path.' };
  const pass = readPass(req, extra.cookieName || DEFAULT_COOKIE);
  if (!pass) return { valid: false, allowed: false, code: 'signin_required', reason: 'Sign in first.' };
  const { strict, cache, ...rest } = c;
  return client(rest).verifyPass(pass, res, { strict: true, cache: cache ?? false });
}
/** authorize() always names an action: { path, method } required, identity-only refused. */
export function authorizeResource(resource: unknown): Resource | 'bad_path' {
  let res: Resource | null;
  try { res = validateResource(resource, 'authorize'); } catch (e: any) { if (e?.code === 'bad_path') return 'bad_path'; throw e; }
  if (!res) throw badResource('authorize: an action needs { path, method }; use getPass(req, { identityOnly: true }) for identity only.');
  return res;
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
/** Most bytes read from one API answer (0.4.2). Bigger answers are refused (denied as a bad answer). */
export const MAX_ANSWER_BYTES = 65536;
const SECRET_KEY_RE = /^sk_[A-Za-z0-9_-]{20,200}$/;
const badConfig = (m: string) => new TokenlockError(m, 0, 'bad_config');
function validApiBase(u: string): boolean { try { const x = new URL(u); return (x.protocol === 'https:' || x.protocol === 'http:') && !!x.hostname; } catch { return false; } }
/** Options removed in 0.4.2. Any value, even the old default, is a configuration error so nothing is silently ignored. */
export const REMOVED_OPTIONS: Record<string, string> = {
  failOpen: 'failOpen was removed in 0.4.2: protected access is always denied while the TOKENLOCK API cannot answer.',
  checkResource: 'checkResource was removed in 0.4.2: the path, method and environment are always checked. For a token-only site use tokenOnly: true.',
};
/** Config-time checks for client options: removed options, strict:false and wrong types throw (bad_config). */
export function checkClientOptions(o: Record<string, any>, name: string) {
  if (!o || typeof o !== 'object') return;
  for (const k of Object.keys(REMOVED_OPTIONS)) if (k in o) throw badConfig(`${name}: ${REMOVED_OPTIONS[k]}`);
  if (o.strict !== undefined && o.strict !== true) throw badConfig(`${name}: strict: false (loose mode) was removed in 0.4.2; strict mode is always on. Remove the strict option.`);
  if (o.cache !== undefined && typeof o.cache !== 'boolean') throw badConfig(`${name}: cache must be true or false.`);
  if (o.timeoutMs !== undefined && !(typeof o.timeoutMs === 'number' && Number.isFinite(o.timeoutMs) && o.timeoutMs > 0 && o.timeoutMs <= 120000)) throw badConfig(`${name}: timeoutMs must be a number of milliseconds between 1 and 120000.`);
  if (o.apiBase !== undefined && (typeof o.apiBase !== 'string' || !validApiBase(o.apiBase))) throw badConfig(`${name}: apiBase must be an http(s) URL.`);
  if (o.secretKey !== undefined && (typeof o.secretKey !== 'string' || !SECRET_KEY_RE.test(o.secretKey))) throw badConfig(`${name}: secretKey must be your sk_… secret key.`);
  if (o.siteKey !== undefined && typeof o.siteKey !== 'string') throw badConfig(`${name}: siteKey must be a string.`);
  if (o.fetch !== undefined && typeof o.fetch !== 'function') throw badConfig(`${name}: fetch must be a function.`);
}
/**
 * Kept for 0.4.x callers: checks adapter options and returns true (strict is always on since 0.4.2). Removed options
 * (failOpen, checkResource) and strict:false throw a TokenlockError with code 'bad_config'.
 */
export function checkAdapterOptions(o: Record<string, any>, name: string): true {
  checkClientOptions(o, name);
  return true;
}
export { SECRET_KEY_RE, validApiBase, badConfig };

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
