// TOKENLOCK self-verify (Enterprise), spec v1: https://proveitonchain.com/docs/self-verify
// Your server issues the challenge, stores the nonce, verifies the wallet signature locally and reads holdings from
// a source you choose. Our API is optional: only if you pick our holdings provider or pull a signed policy bundle.
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1.js';
import { verifyMessageSignature, decodeAddress, taggedHash } from './btcsig.js';
import { canonicalPath, validateResource } from '../core.js';
export { verifyMessageSignature, decodeAddress, _addr } from './btcsig.js';

export const SPEC_VERSION = 1;
const iso = (ms: number) => new Date(ms).toISOString();
const te = new TextEncoder();

// ------------------------------------------------------------------ errors
export class SelfVerifyError extends Error {
  code: string; status: number;
  constructor(code: string, message: string, status = 400) { super(message); this.code = code; this.status = status; }
}
const fail = (code: string, message: string, status = 400): never => { throw new SelfVerifyError(code, message, status); };

// ------------------------------------------------------------------ assets
const NAMED = /^[B-Z][A-Z]{3,11}$/, NUMERIC = /^A\d{12,21}$/, SUB = /^([B-Z][A-Z]{3,11}|A\d{12,21})\.[a-zA-Z0-9.\-_@!]{1,200}$/;
export function normalizeAsset(raw: string): string {
  let a = String(raw || '').trim();
  const dot = a.indexOf('.');
  a = dot > 0 ? a.slice(0, dot).toUpperCase() + a.slice(dot) : a.toUpperCase();
  if (NAMED.test(a) || NUMERIC.test(a) || SUB.test(a)) return a;
  return fail('bad_asset', `"${String(raw).slice(0, 60)}" is not a valid Bitcoin asset name.`);
}

// ------------------------------------------------------------------ challenge message (spec §2)
export interface ChallengeRecord { v: 1; nonce: string; site: string; assets: string[]; any_name: boolean; issued_at: string; expires_at: string; pass_ttl_s: number }
export function buildMessage(r: Pick<ChallengeRecord, 'site' | 'assets' | 'any_name' | 'nonce' | 'issued_at' | 'expires_at'>): string {
  const req = `${r.assets.length ? r.assets.join(' or ') : ''}${r.assets.length && r.any_name ? ' or ' : ''}${r.any_name ? 'any name on Bitcoin' : ''}`;
  return ['Sign in with your Token', `Site: ${r.site}`, `Requires: ${req}`, 'Via: self-verify', `Nonce: ${r.nonce}`, `Issued: ${r.issued_at}`, `Expires: ${r.expires_at}`,
    'Signing proves you control this address. It moves no funds.'].join('\n');
}

// ------------------------------------------------------------------ nonce store (spec §3: replay protection is yours)
export interface NonceStore {
  /** Save a new challenge until `expiresAtMs`. */
  put(nonce: string, record: ChallengeRecord, expiresAtMs: number): Promise<void>;
  /** Atomically fetch AND delete. Must return null if the nonce is unknown or was already taken. */
  take(nonce: string): Promise<ChallengeRecord | null>;
}
export function memoryNonceStore(max = 100_000): NonceStore {
  const m = new Map<string, { r: ChallengeRecord; e: number }>();
  return {
    async put(n, r, e) { if (m.size >= max) { const now = Date.now(); for (const [k, v] of m) if (v.e < now) m.delete(k); if (m.size >= max) fail('busy', 'Too many open challenges.', 503); } m.set(n, { r, e }); },
    async take(n) { const v = m.get(n); if (!v) return null; m.delete(n); return v.r; },
  };
}
/** One file per challenge; `take` is an atomic rename, so two servers sharing the folder can't both accept a nonce. */
export function fileNonceStore(dir: string): NonceStore {
  const fsP = import('node:fs/promises'); const pathP = import('node:path');
  return {
    async put(n, r, e) { const [fs, path] = await Promise.all([fsP, pathP]); await fs.mkdir(dir, { recursive: true, mode: 0o700 }); await fs.writeFile(path.join(dir, n + '.json'), JSON.stringify({ r, e }), { flag: 'wx', mode: 0o600 }); },
    async take(n) {
      if (!/^[0-9a-f]{32}$/.test(n)) return null;
      const [fs, path] = await Promise.all([fsP, pathP]);
      const src = path.join(dir, n + '.json'), dst = src + '.taken.' + randomBytes(4).toString('hex');
      try { await fs.rename(src, dst); } catch { return null; }
      try { const { r, e } = JSON.parse(await fs.readFile(dst, 'utf8')); return e >= Date.now() - 60_000 ? r : null; } catch { return null; } finally { fs.unlink(dst).catch(() => {}); }
    },
  };
}
/** Redis-style store: anything with set(key, val, 'PX', ms, 'NX') and getdel(key) (ioredis, node-redis via adapter). */
export function redisNonceStore(client: { set: (...a: any[]) => Promise<any>; getdel: (k: string) => Promise<string | null> }, prefix = 'tokenlock:nonce:'): NonceStore {
  return {
    async put(n, r, e) { const ok = await client.set(prefix + n, JSON.stringify(r), 'PX', Math.max(1000, e - Date.now()), 'NX'); if (!ok) fail('nonce_collision', 'Nonce already exists.', 500); },
    async take(n) { const v = await client.getdel(prefix + n); return v ? JSON.parse(v) : null; },
  };
}

export interface ChallengeOptions { site: string; assets?: string[]; anyName?: boolean; ttlSeconds?: number; passTtlSeconds?: number; store: NonceStore; now?: number }
/** Create a one-time challenge for the visitor's wallet to sign. Default lifetime 10 minutes (60 s to 30 min). */
export async function createChallenge(o: ChallengeOptions) {
  let site: string; try { site = new URL(o.site).origin; } catch { return fail('bad_site', '`site` must be your origin, e.g. https://shop.example'); }
  const assets = [...new Set((o.assets || []).map(normalizeAsset))];
  if (assets.length > 10) fail('too_many_assets', 'At most 10 assets.');
  if (!assets.length && !o.anyName) fail('asset_required', 'Give `assets` (any one is enough) or set `anyName: true`.');
  const ttl = Math.min(1800, Math.max(60, Math.round(o.ttlSeconds ?? 600)));
  const now = o.now ?? Date.now();
  const r: ChallengeRecord = { v: 1, nonce: randomBytes(16).toString('hex'), site, assets, any_name: !!o.anyName, issued_at: iso(now), expires_at: iso(now + ttl * 1000), pass_ttl_s: Math.min(86400, Math.max(60, Math.round(o.passTtlSeconds ?? 900))) };
  await o.store.put(r.nonce, r, now + ttl * 1000);
  return { challenge_id: r.nonce, message: buildMessage(r), assets, any_name: r.any_name, origin: site, issued_at: r.issued_at, expires_at: r.expires_at, mode: 'self-verify' as const };
}

// ------------------------------------------------------------------ holdings providers (spec §4)
export interface Holding { held: boolean; how?: 'owner' | 'balance' | null; quantity?: string; exists?: boolean }
export interface HoldingsProvider { name: string; holdings(address: string, assets: string[]): Promise<Record<string, Holding>> }
type FetchLike = (url: string, init?: any) => Promise<{ ok: boolean; status: number; json(): Promise<any> }>;
async function getJson(f: FetchLike, url: string, timeoutMs: number, headers: Record<string, string> = {}) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await f(url, { headers: { accept: 'application/json', ...headers }, signal: ctl.signal });
    const body = await r.json().catch(() => null);
    return { status: r.status, ok: r.ok, body };
  } finally { clearTimeout(t); }
}
const lookupFailed = (who: string, why: string) => new SelfVerifyError('lookup_failed', `${who}: could not read holdings (${why}).`, 502);

/** Our hosted lookup (optional): GET /api/v1/tokenlock/holdings. You then trust our reading of the chain. */
export function proveitonchainProvider(o: { api?: string; fetch?: FetchLike; timeoutMs?: number } = {}): HoldingsProvider {
  const api = (o.api || 'https://proveitonchain.com').replace(/\/$/, ''); const f = o.fetch || (globalThis.fetch as any);
  return { name: 'proveitonchain', async holdings(address, assets) {
    let r; try { r = await getJson(f, `${api}/api/v1/tokenlock/holdings?address=${encodeURIComponent(address)}&assets=${encodeURIComponent(assets.join(','))}`, o.timeoutMs ?? 8000); } catch (e: any) { throw lookupFailed('proveitonchain', e?.name === 'AbortError' ? 'timeout' : 'network'); }
    if (!r.ok || !r.body?.holdings || typeof r.body.holdings !== 'object' || Array.isArray(r.body.holdings)) throw lookupFailed('proveitonchain', 'status ' + r.status);
    const out: Record<string, Holding> = {};
    for (const a of assets) {
      const x = r.body.holdings[a];
      if (x === undefined || x === null) { out[a] = { held: false, how: null }; continue; }
      // 0.4.2: an entry must be an object whose `held` is a boolean; "false", 1 or "yes" are unreadable, not "held".
      if (typeof x !== 'object' || Array.isArray(x) || typeof x.held !== 'boolean') throw lookupFailed('proveitonchain', 'unreadable answer');
      out[a] = { held: x.held, how: x.how ?? null, quantity: x.quantity, exists: x.exists };
    }
    return out;
  } };
}
/** Public explorer tokenscan.io (no key). Reads the asset's owner and the address balances. */
export function tokenscanProvider(o: { base?: string; fetch?: FetchLike; timeoutMs?: number } = {}): HoldingsProvider {
  const base = (o.base || 'https://tokenscan.io/api').replace(/\/$/, ''); const f = o.fetch || (globalThis.fetch as any); const to = o.timeoutMs ?? 8000;
  return { name: 'tokenscan', async holdings(address, assets) {
    const out: Record<string, Holding> = {}; let balances: Map<string, number> | null = null;
    for (const a of assets) {
      let info; try { info = await getJson(f, `${base}/asset/${encodeURIComponent(a)}`, to); } catch { throw lookupFailed('tokenscan', 'network'); }
      if (/not found/i.test(String(info.body?.error || ''))) { out[a] = { held: false, how: null, exists: false }; continue; }
      if (!info.ok || !info.body?.asset) throw lookupFailed('tokenscan', 'status ' + info.status);
      if ((info.body.owner || info.body.issuer) === address) { out[a] = { held: true, how: 'owner', exists: true }; continue; }
      if (!balances) {
        balances = new Map();
        for (let page = 1; page <= 4; page++) {
          let r; try { r = await getJson(f, `${base}/balances/${encodeURIComponent(address)}/${page}/500`, to); } catch { throw lookupFailed('tokenscan', 'network'); }
          if (!r.ok) throw lookupFailed('tokenscan', 'status ' + r.status);
          const list = Array.isArray(r.body?.data) ? r.body.data : [];
          for (const b of list) { const q = Number(b.quantity); if (q > 0) { if (b.asset) balances.set(String(b.asset), q); if (b.asset_longname) balances.set(String(b.asset_longname), q); } }
          if (list.length < 500) break;
        }
      }
      const q = balances.get(a);
      out[a] = q && q > 0 ? { held: true, how: 'balance', quantity: String(q), exists: true } : { held: false, how: null, exists: true };
    }
    return out;
  } };
}
/**
 * Any HTTP JSON source: your own node, your own indexer, or another explorer. `url` has {address} and {asset}.
 * `quantity(body)` returns the balance (number/string) and optional `owner(body)` the asset owner address.
 */
export function httpJsonProvider(o: { name?: string; url: string; quantity: (body: any) => number | string | null | undefined; owner?: (body: any) => string | null | undefined; notFound?: (status: number, body: any) => boolean; headers?: Record<string, string>; fetch?: FetchLike; timeoutMs?: number }): HoldingsProvider {
  const f = o.fetch || (globalThis.fetch as any); const name = o.name || 'http-json';
  if (!/\{address\}/.test(o.url)) fail('bad_provider', '`url` must contain {address}.');
  return { name, async holdings(address, assets) {
    const out: Record<string, Holding> = {};
    for (const a of assets) {
      const url = o.url.replace(/\{address\}/g, encodeURIComponent(address)).replace(/\{asset\}/g, encodeURIComponent(a));
      let r; try { r = await getJson(f, url, o.timeoutMs ?? 8000, o.headers); } catch { throw lookupFailed(name, 'network'); }
      if (o.notFound && o.notFound(r.status, r.body)) { out[a] = { held: false, how: null, exists: false }; continue; }
      if (!r.ok) throw lookupFailed(name, 'status ' + r.status);
      const owner = o.owner ? o.owner(r.body) : null;
      if (owner && owner === address) { out[a] = { held: true, how: 'owner' }; continue; }
      const q = Number(o.quantity(r.body));
      if (!Number.isFinite(q)) throw lookupFailed(name, 'unreadable answer');
      out[a] = q > 0 ? { held: true, how: 'balance', quantity: String(q) } : { held: false, how: null };
    }
    return out;
  } };
}
/** Fixed answers (tests, allowlists, or holdings you already know). */
export function staticProvider(map: Record<string, string[]>): HoldingsProvider {
  return { name: 'static', async holdings(address, assets) { const have = map[address] || []; const out: Record<string, Holding> = {}; for (const a of assets) out[a] = { held: have.includes(a), how: have.includes(a) ? 'balance' : null }; return out; } };
}
/** Try providers in order; the first that answers wins. Fails closed if none answers. */
export function firstAvailable(providers: HoldingsProvider[]): HoldingsProvider {
  return { name: 'first(' + providers.map((p) => p.name).join(',') + ')', async holdings(a, s) {
    for (const p of providers) { try { return await p.holdings(a, s); } catch { /* next */ } }
    throw new SelfVerifyError('lookup_failed', 'No holdings source answered.', 502);
  } };
}
/** Ask every provider; all must answer and agree on `held`, else fail closed. Use two independent sources. */
export function requireAgreement(providers: HoldingsProvider[]): HoldingsProvider {
  return { name: 'agree(' + providers.map((p) => p.name).join(',') + ')', async holdings(a, s) {
    const all = await Promise.all(providers.map((p) => p.holdings(a, s)));
    for (const x of s) {
      const vals = all.map((h) => h?.[x]?.held);
      if (vals.some((v) => v !== undefined && typeof v !== 'boolean')) throw new SelfVerifyError('lookup_failed', `A holdings source gave an unreadable answer for ${x}.`, 502);
      if (new Set(vals.map((v) => v === true)).size !== 1) throw new SelfVerifyError('lookup_disagreement', `Holdings sources disagree on ${x}.`, 502);
    }
    return all[0];
  } };
}

// ------------------------------------------------------------------ policy (spec §5)
export interface PolicyKey { id: string; address: string; status: string; owner_type?: string; org_id?: string | null; assets?: string[]; permissions?: { routes?: string[]; methods?: string[]; environments?: string[] }; expires_at?: string | null; pass_ttl_s?: number | null }
export interface Policy { v: 1; typ: 'tokenlock.policy'; site_id: string; seq: number; issued_at: string; expires_at: string; mode: 'token' | 'registered_keys'; assets?: string[]; any_name?: boolean; origins?: string[]; settings?: { require_org?: boolean; default_pass_ttl_s?: number; agent_pass_ttl_s?: number }; orgs: { id: string; status: string }[]; revoked_assets: string[]; keys: PolicyKey[] }
export interface PolicyBundle { v: 1; typ: 'tokenlock.policy-bundle'; alg: 'BIP340'; kid: string; payload: string; sig: string }
const b64url = (s: string) => { const b = s.replace(/-/g, '+').replace(/_/g, '/'); return Uint8Array.from(Buffer.from(b + '='.repeat((4 - (b.length % 4)) % 4), 'base64')); };
const hexb = (h: string) => { if (!/^([0-9a-f]{2})+$/i.test(h)) return null; return Uint8Array.from(Buffer.from(h, 'hex')); };

/** Check a policy bundle offline: signature by a pinned key, site, freshness and no rollback. Throws SelfVerifyError. */
export function verifyPolicyBundle(bundle: PolicyBundle, o: { publicKeys: Record<string, string> | string[]; siteId: string; now?: number; minSeq?: number; maxAgeSeconds?: number }): Policy {
  if (!bundle || bundle.v !== 1 || bundle.alg !== 'BIP340' || typeof bundle.payload !== 'string' || typeof bundle.sig !== 'string') fail('policy_invalid', 'Not a policy bundle.', 502);
  const candidates = Array.isArray(o.publicKeys) ? o.publicKeys : [o.publicKeys[bundle.kid]].filter(Boolean);
  if (!candidates.length) fail('policy_untrusted_key', `Policy signed by unknown key ${String(bundle.kid).slice(0, 20)}.`, 502);
  const bytes = b64url(bundle.payload); const sig = hexb(bundle.sig);
  const msg = taggedHash('TOKENLOCK/policy/v1', bytes);
  const ok = !!sig && sig.length === 64 && candidates.some((pk) => { const p = hexb(pk); try { return !!p && p.length === 32 && schnorr.verify(sig, msg, p); } catch { return false; } });
  if (!ok) fail('policy_bad_signature', 'Policy bundle signature does not verify.', 502);
  let p: Policy; try { p = JSON.parse(new TextDecoder().decode(bytes)); } catch { return fail('policy_invalid', 'Policy payload is not JSON.', 502); }
  if (!p || typeof p !== 'object' || Array.isArray(p) || p.typ !== 'tokenlock.policy' || p.v !== 1) fail('policy_invalid', 'Unknown policy version.', 502);
  if (p.site_id !== o.siteId) fail('policy_wrong_site', 'Policy is for another site.', 502);
  const now = o.now ?? Date.now();
  validatePolicy(p, now, true);
  if (!(Date.parse(p.expires_at) > now)) fail('policy_expired', 'Policy bundle expired. Fetch a fresh one.', 503);
  if (o.maxAgeSeconds && now - Date.parse(p.issued_at) > o.maxAgeSeconds * 1000) fail('policy_stale', 'Policy bundle is older than allowed.', 503);
  if (o.minSeq != null && p.seq < o.minSeq) fail('policy_rollback', 'Policy bundle is older than one already seen.', 502);
  return p;
}

const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;
const isoMs = (v: unknown): number | null => (typeof v === 'string' && ISO_TIME.test(v) && Number.isFinite(Date.parse(v)) ? Date.parse(v) : null);
const strList = (v: unknown) => Array.isArray(v) && v.every((x) => typeof x === 'string');
export const KEY_STATUSES = ['active', 'revoked', 'pending_approval'];
/** Most clock skew accepted on a signed bundle's issued_at (a bundle "issued" further in the future is invalid). */
export const POLICY_FUTURE_SKEW_MS = 5 * 60e3;
/**
 * 0.4.2: shape check for a policy (signed or local). Anything malformed is policy_invalid and access is denied: a typo in
 * `mode`, a string where a list belongs ('GET,POST' would match by substring), an unparseable date (an unparseable key
 * expiry would never expire), a non-integer seq (breaks rollback protection) or an unknown key status.
 */
export function validatePolicy(p: any, now = Date.now(), signed = false): void {
  const bad = (why: string): never => fail('policy_invalid', 'Policy is malformed: ' + why + '.', 502);
  if (!p || typeof p !== 'object' || Array.isArray(p)) bad('not an object');
  if (p.v !== 1 || p.typ !== 'tokenlock.policy') bad('unknown version');
  if (typeof p.site_id !== 'string' || !p.site_id) bad('site_id');
  if (!Number.isSafeInteger(p.seq) || p.seq < 0) bad('seq must be a whole number >= 0');
  const iss = isoMs(p.issued_at), exp = isoMs(p.expires_at);
  if (iss === null) bad('issued_at'); if (exp === null) bad('expires_at');
  if ((exp as number) < (iss as number)) bad('expires_at is before issued_at');
  if (signed && (iss as number) > now + POLICY_FUTURE_SKEW_MS) bad('issued_at is in the future');
  if (p.mode !== 'token' && p.mode !== 'registered_keys') bad('mode must be "token" or "registered_keys"');
  if (!Array.isArray(p.orgs) || !p.orgs.every((x: any) => x && typeof x === 'object' && typeof x.id === 'string' && typeof x.status === 'string')) bad('orgs');
  if (!strList(p.revoked_assets)) bad('revoked_assets');
  if (p.assets !== undefined && !strList(p.assets)) bad('assets');
  if (p.origins !== undefined && !strList(p.origins)) bad('origins');
  if (p.any_name !== undefined && typeof p.any_name !== 'boolean') bad('any_name');
  if (p.settings !== undefined && (!p.settings || typeof p.settings !== 'object' || Array.isArray(p.settings))) bad('settings');
  if (!Array.isArray(p.keys)) bad('keys must be a list');
  for (const k of p.keys) {
    if (!k || typeof k !== 'object' || Array.isArray(k)) bad('key');
    if (typeof k.id !== 'string' || !k.id || typeof k.address !== 'string' || !k.address) bad('key id/address');
    if (!KEY_STATUSES.includes(k.status)) bad('key status');
    if (k.org_id != null && typeof k.org_id !== 'string') bad('key org_id');
    if (k.assets != null && !strList(k.assets)) bad('key assets');
    if (k.expires_at != null && isoMs(k.expires_at) === null) bad('key expires_at');
    if (k.pass_ttl_s != null && !(typeof k.pass_ttl_s === 'number' && k.pass_ttl_s > 0)) bad('key pass_ttl_s');
    if (k.permissions != null) {
      const pm = k.permissions;
      if (typeof pm !== 'object' || Array.isArray(pm)) bad('key permissions');
      for (const f of ['routes', 'methods', 'environments']) if (pm[f] != null && !strList(pm[f])) bad(`key permissions.${f} must be a list`);
    }
  }
}

export interface PolicySource { get(): Promise<Policy> }
/** Load state of a `signedPolicy` source (for health checks and logs). Times are ms since epoch. */
export interface SignedPolicyStatus { seq: number | null; fetched_at: number | null; expires_at: string | null; failures: number; last_error: string | null; next_retry_at: number | null; loads: number }
/**
 * Pull the signed bundle from our API with your secret key and cache it. Refreshes every `refreshSeconds` (default 60).
 * Concurrent calls share one in-flight load. After a failed load, no new load starts until a backoff window has passed:
 * `retryMinSeconds` (default 5), doubling on each consecutive failure up to `retryMaxSeconds` (default `refreshSeconds`).
 * During that window `get()` answers at once without a network call: the cached bundle while it is unexpired, otherwise
 * the last error (`policy_unavailable`, or the bundle's own error code). When the cached bundle expires and no refresh has
 * succeeded, access fails closed (`policy_expired`).
 */
export function signedPolicy(o: { siteId: string; secretKey: string; publicKeys: Record<string, string> | string[]; api?: string; refreshSeconds?: number; retryMinSeconds?: number; retryMaxSeconds?: number; ttlSeconds?: number; fetch?: FetchLike; timeoutMs?: number; load?: () => Promise<PolicyBundle> }): PolicySource & { status(): SignedPolicyStatus } {
  const api = (o.api || 'https://proveitonchain.com').replace(/\/$/, ''); const f = o.fetch || (globalThis.fetch as any);
  const refreshMs = Math.max(0, o.refreshSeconds ?? 60) * 1000;
  const retryMinMs = Math.max(0.1, o.retryMinSeconds ?? 5) * 1000;
  const retryMaxMs = Math.max(retryMinMs, (o.retryMaxSeconds ?? Math.max(1, o.refreshSeconds ?? 60)) * 1000);
  let cur: Policy | null = null, fetchedAt = 0, seq = -1, inflight: Promise<void> | null = null;
  let failures = 0, retryAt = 0, lastErr: SelfVerifyError | null = null, loads = 0;
  const load = o.load || (async () => {
    const r = await getJson(f, `${api}/api/v1/tokenlock/access/policy${o.ttlSeconds ? '?ttl=' + o.ttlSeconds : ''}`, o.timeoutMs ?? 8000, { authorization: 'Bearer ' + o.secretKey });
    if (!r.ok) throw new SelfVerifyError('policy_unavailable', 'Policy endpoint answered ' + r.status, 503);
    return r.body as PolicyBundle;
  });
  const asErr = (e: any) => e instanceof SelfVerifyError ? e : new SelfVerifyError('policy_unavailable', 'Could not load the policy bundle.', 503);
  async function refresh() {
    loads++;
    try {
      const b = await load();
      const p = verifyPolicyBundle(b, { publicKeys: o.publicKeys, siteId: o.siteId, minSeq: seq < 0 ? undefined : seq });
      cur = p; seq = p.seq; fetchedAt = Date.now(); failures = 0; retryAt = 0; lastErr = null;
    } catch (e: any) {
      failures++; lastErr = asErr(e);
      retryAt = Date.now() + Math.min(retryMaxMs, retryMinMs * 2 ** Math.min(failures - 1, 30));
      throw lastErr;
    }
  }
  return {
    async get() {
      const due = !cur || Date.now() - fetchedAt > refreshMs;
      if (due && (inflight || Date.now() >= retryAt)) {
        inflight ||= refresh().finally(() => { inflight = null; });
        try { await inflight; } catch (e) { if (!cur) throw asErr(e); }
      } else if (!cur) {
        throw lastErr || new SelfVerifyError('policy_unavailable', 'Could not load the policy bundle.', 503); // backing off
      }
      if (!cur || !(Date.parse(cur.expires_at) > Date.now())) throw new SelfVerifyError('policy_expired', 'Policy bundle expired and could not be refreshed.', 503);
      return cur;
    },
    status() {
      const c = cur as Policy | null;
      return { seq: c ? c.seq : null, fetched_at: c ? fetchedAt : null, expires_at: c ? c.expires_at : null, failures, last_error: lastErr ? lastErr.code : null, next_retry_at: failures ? retryAt : null, loads };
    },
  };
}
/** Your own policy (file, database, config): same shape, no signature needed because you are the source. */
export function localPolicy(get: Partial<Policy> | (() => Partial<Policy> | Promise<Partial<Policy>>)): PolicySource {
  const defaults = { v: 1, typ: 'tokenlock.policy', site_id: 'local', seq: 0, issued_at: iso(0), expires_at: '9999-12-31T23:59:59.000Z', orgs: [], revoked_assets: [], keys: [], mode: 'registered_keys' };
  return { async get() { const p = typeof get === 'function' ? await get() : get; const out = Object.assign({}, defaults, p) as Policy; validatePolicy(out); return out; } };
}

// access rule, same as hosted TOKENLOCK (access.evaluate)
/** Canonical path (TOKENLOCK path rules v1.1, same as the hosted API and every adapter). null = reject. */
export function normalizePath(raw: string): string | null { return canonicalPath(raw); }
/** Case-insensitive route match on a canonical path, same as the hosted API. */
export function routeMatches(pattern: string, path: string) {
  const p = String(pattern || '').trim().toLowerCase();
  const q = String(path || '').toLowerCase();
  if (p === '*' || p === '/*') return true;
  if (p.endsWith('/*')) { const base = p.slice(0, -2).replace(/\/+$/, ''); return q === base || q.startsWith(base + '/') || (base === '' && q.startsWith('/')); }
  if (p.endsWith('/') && p.length > 1) { const base = p.replace(/\/+$/, ''); return q === base || q.startsWith(base + '/'); }
  return q === p.replace(/\/+$/, '') || (p === '/' && q === '/');
}
export interface Resource { path?: string; method?: string; environment?: string }
export function evaluate(policy: Policy, o: { address: string; held: string[] | null; resource?: Resource | null; now?: number }): { allowed: boolean; reason: string; key?: PolicyKey } {
  const now = o.now ?? Date.now();
  // 0.4.2: defensive (callers may evaluate a policy that never went through validatePolicy): malformed → deny.
  if (!policy || (policy.mode !== 'token' && policy.mode !== 'registered_keys') || !Array.isArray(policy.keys) || (policy.revoked_assets != null && !strList(policy.revoked_assets))) return { allowed: false, reason: 'policy_invalid' };
  const revoked = policy.revoked_assets || [];
  if (policy.mode !== 'registered_keys') {
    if (o.held && !o.held.filter((a) => !revoked.includes(a)).length) return { allowed: false, reason: o.held.length ? 'entitlement_revoked' : 'not_holder' };
    return { allowed: true, reason: 'ok' };
  }
  const key = (policy.keys || []).find((k) => k.address === o.address);
  const no = (reason: string) => ({ allowed: false, reason, key });
  if (!key) return no('not_registered');
  if (key.status === 'revoked') return no('key_revoked');
  if (key.status === 'pending_approval') return no('pending_approval');
  if (key.status !== 'active') return no('not_registered');
  if (key.expires_at != null && key.expires_at !== '') { const e = isoMs(key.expires_at); if (e === null || e <= now) return no('key_expired'); }
  if (key.org_id) { const org = (policy.orgs || []).find((x) => x.id === key.org_id); if (!org || org.status !== 'approved') return no('org_not_approved'); }
  else if (policy.settings?.require_org) return no('org_required');
  if (o.held) { const ok = o.held.filter((a) => !revoked.includes(a) && (!key.assets?.length || key.assets.includes(a))); if (!ok.length) return no(o.held.length ? 'entitlement_revoked' : 'not_holder'); }
  // 0.4.3: a resource given here is validated with the same schema as every other entry point; a malformed one is
  // refused (bad_resource / bad_path) instead of skipping the route rules. resource null/absent = identity only (low level).
  let r: Resource | null = null;
  if (o.resource != null) { try { r = validateResource(o.resource, 'evaluate'); } catch (e: any) { return no(e?.code === 'bad_path' ? 'bad_path' : 'bad_resource'); } if (!r) return no('bad_resource'); }
  if (r) {
    const perm: any = key.permissions || {}; const routes = perm.routes ?? ['*'], methods = perm.methods ?? ['*'], envs = perm.environments ?? [];
    if (!strList(routes) || !strList(methods) || !strList(envs)) return no('policy_invalid');
    if (r.environment && envs.length && !envs.includes('*') && !envs.includes(r.environment)) return no('environment_not_allowed');
    if (r.path) { const p = normalizePath(r.path); if (!p) return no('bad_path'); if (!routes.some((x) => routeMatches(x, p))) return no('route_not_allowed'); }
    if (r.method && !methods.includes('*') && !methods.includes(String(r.method).toUpperCase())) return no('method_not_allowed');
  }
  return { allowed: true, reason: 'ok', key };
}

// ------------------------------------------------------------------ sign-in + local pass (spec §6)
export interface SignInResult { valid: boolean; code: string; reason: string; address?: string; assets_held?: string[]; pass?: string; expires_at?: string; key_id?: string | null; correlation_id: string }
const REASONS: Record<string, string> = {
  ok: 'Signed in.', bad_pass: 'Not a valid pass.', route_not_allowed: 'This key is not allowed on this route.', method_not_allowed: 'This key is not allowed to use this method here.', environment_not_allowed: 'This key is not allowed in this environment.', bad_path: 'Not a valid path.', bad_resource: 'Malformed authorization request: pass a valid { path, method } or { identityOnly: true }.', unknown_challenge: 'This sign-in request is unknown or was already used. Start again.', expired: 'This sign-in request expired. Start again.',
  bad_signature: 'The signature does not match this address and message.', bad_address: 'Not a Bitcoin address we support.', not_holder: 'This wallet does not hold the token.',
  lookup_failed: 'Could not read holdings right now. Try again in a minute.', lookup_disagreement: 'Holdings sources disagree. Try again in a minute.', name_required: 'Give the name you hold.',
  not_registered: 'This wallet is not a registered key for this site.', key_revoked: 'This key was revoked.', key_expired: 'This key has expired.', pending_approval: 'Waiting for the site admin to approve this wallet.',
  org_not_approved: 'The organization for this key is not approved.', org_required: 'This site requires keys to belong to an organization.', entitlement_revoked: 'This token no longer unlocks this site.',
  policy_expired: 'Access policy is out of date. Try again in a minute.', policy_invalid: 'Access policy is malformed, so access is denied. Fix the policy.', policy_unavailable: 'Access policy is unavailable. Try again in a minute.',
  policy_required: 'No route policy applies: a resource (path, method or environment) was given but there is no policy, or the policy has no route rules (token mode), so it cannot be explicitly permitted. Use a registered-keys policy that grants the route, or drop `resource` for an identity-only check.',
};
export interface SelfVerifyConfig { store: NonceStore; holdings: HoldingsProvider; passSecret: string; policy?: PolicySource; clockSkewSeconds?: number }
/** Verify a sign-in with no call to our API (except providers/policy you chose). Fails closed on any lookup error. */
export async function verifySignIn(input: { challenge_id: string; address: string; signature: string; name?: string }, cfg: SelfVerifyConfig, now = Date.now()): Promise<SignInResult> {
  const cid = String(input?.challenge_id || '');
  const out = (code: string, extra: Partial<SignInResult> = {}): SignInResult => ({ valid: code === 'ok', code, reason: REASONS[code] || code, correlation_id: cid, ...extra });
  if (!/^[0-9a-f]{32}$/.test(cid)) return out('unknown_challenge');
  const rec = await cfg.store.take(cid);                    // single use: taken even if what follows fails
  if (!rec) return out('unknown_challenge');
  if (now > Date.parse(rec.expires_at) + (cfg.clockSkewSeconds ?? 0) * 1000) return out('expired');
  const address = String(input.address || '').trim();
  if (!decodeAddress(address)) return out('bad_address');
  if (!verifyMessageSignature(address, buildMessage(rec), String(input.signature || ''))) return out('bad_signature', { address });
  let policy: Policy | null = null;
  if (cfg.policy) { try { policy = await cfg.policy.get(); } catch (e: any) { return out(e?.code === 'policy_expired' || e?.code === 'policy_invalid' ? e.code : 'policy_unavailable', { address }); } }
  const want = [...rec.assets];
  if (rec.any_name) { if (!input.name) { if (!want.length) return out('name_required', { address }); } else want.push(normalizeAsset(input.name)); }
  let h: Record<string, Holding>;
  try { h = await cfg.holdings.holdings(address, want); } catch (e: any) { return out(e?.code === 'lookup_disagreement' ? 'lookup_disagreement' : 'lookup_failed', { address }); }
  const held = want.filter((a) => h?.[a]?.held === true);
  if (!held.length) return out('not_holder', { address, assets_held: [] });
  let keyId: string | null = null, ttl = rec.pass_ttl_s;
  if (policy) {
    const ev = evaluate(policy, { address, held });
    if (!ev.allowed) return out(ev.reason, { address, assets_held: held });
    if (ev.key) { keyId = ev.key.id; const kt = ev.key.pass_ttl_s || (ev.key.owner_type === 'agent' ? policy.settings?.agent_pass_ttl_s : policy.settings?.default_pass_ttl_s); if (kt) ttl = Math.min(ttl, kt); if (ev.key.expires_at) ttl = Math.min(ttl, Math.max(60, Math.floor((Date.parse(ev.key.expires_at) - now) / 1000))); }
  }
  const exp = now + ttl * 1000;
  const pass = issuePass({ sub: address, h: held, k: keyId, n: cid, s: rec.site, i: now, e: exp }, cfg.passSecret);
  return out('ok', { address, assets_held: held, pass, expires_at: iso(exp), key_id: keyId });
}

// local pass: tl3.<base64url(json)>.<base64url(hmac-sha256)>, keyed by YOUR secret (never ours)
const enc = (b: Uint8Array | string) => Buffer.from(typeof b === 'string' ? te.encode(b) : b).toString('base64url');
export function issuePass(p: { sub: string; h: string[]; k: string | null; n: string; s: string; i: number; e: number }, secret: string) {
  if (!secret || secret.length < 32) fail('bad_secret', '`passSecret` must be at least 32 characters.', 500);
  const body = enc(JSON.stringify({ v: 1, ...p }));
  return `tl3.${body}.${createHmac('sha256', secret).update('tl3.' + body).digest('base64url')}`;
}
const SCOPE = new Set(['route_not_allowed', 'method_not_allowed', 'environment_not_allowed', 'bad_path']);
/**
 * Check a local pass. `valid` = authentic, unexpired and access still granted; `allowed` also covers this resource.
 * Identity only (no `resource`): `policy` is optional. With a `resource` ({ path, method, environment }) a `policy` is
 * required, because route, method and environment rules live in the policy: without one the answer is
 * `{ valid: false, allowed: false, code: 'policy_required' }` (a configuration error, never an allow). Since 0.4.0 the same
 * applies to a token-mode policy (registered keys off): it has no route rules, so a resource is never "explicitly permitted".
 * `identity_valid: true` on those answers means the pass itself (and, in token mode, the token) is still good.
 */
function tokenModeIdentity(pol: Policy, p: any, now: number): boolean { return evaluate(pol, { address: p.sub, held: p.h, resource: null, now }).allowed; }
const LOCAL_PASS_KEYS = ['passSecret', 'policy', 'resource', 'identityOnly', 'now'];
export async function verifyLocalPass(token: string, o: { passSecret: string; policy?: PolicySource; resource?: Resource | null; identityOnly?: true; now?: number }): Promise<{ valid: boolean; allowed: boolean; code: string; reason: string; identity_valid?: boolean; address?: string; assets_held?: string[]; expires_at?: string; key_id?: string | null }> {
  const no = (code: string, extra = {}) => ({ valid: SCOPE.has(code), allowed: false, code, reason: REASONS[code] || code, ...extra });
  // 0.4.3: the authorization request is explicit. { identityOnly: true } (and no resource) is an identity-only check; a
  // resource must pass the shared schema; anything else (no resource, unknown option, malformed resource) is refused.
  if (!o || typeof o !== 'object') return no('bad_resource');
  for (const k of Object.keys(o)) if (!LOCAL_PASS_KEYS.includes(k)) return no('bad_resource');
  let req: Resource | null;
  if ('identityOnly' in o) { if (o.identityOnly !== true || o.resource !== undefined) return no('bad_resource'); req = null; }
  else { try { req = validateResource(o.resource, 'verifyLocalPass'); } catch (e: any) { return no(e?.code === 'bad_path' ? 'bad_path' : 'bad_resource'); } if (!req) return no('bad_resource'); }
  const m = /^tl3\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{43})$/.exec(String(token || ''));
  if (!m) return no('bad_pass');
  const want = createHmac('sha256', o.passSecret).update('tl3.' + m[1]).digest();
  const got = Buffer.from(m[2], 'base64url');
  if (got.length !== want.length || !timingSafeEqual(got, want)) return no('bad_pass');
  let p: any; try { p = JSON.parse(Buffer.from(m[1], 'base64url').toString('utf8')); } catch { return no('bad_pass'); }
  const now = o.now ?? Date.now();
  if (!(p.e > now)) return no('expired');
  const base = { address: p.sub, assets_held: p.h, expires_at: iso(p.e), key_id: p.k ?? null };
  if (o.policy) {
    let pol: Policy; try { pol = await o.policy.get(); } catch (e: any) { return no(e?.code === 'policy_expired' || e?.code === 'policy_invalid' ? e.code : 'policy_unavailable', base); }
    if (req != null && pol.mode !== 'registered_keys') {
      // Token-mode policy: no route rules exist, so a resource cannot be explicitly permitted (0.4.0).
      return { valid: false, allowed: false, identity_valid: tokenModeIdentity(pol, p, now), code: 'policy_required', reason: REASONS.policy_required, ...base };
    }
    const ev = evaluate(pol, { address: p.sub, held: p.h, resource: req, now });
    if (!ev.allowed) return no(ev.reason, base);
    if (pol.mode === 'registered_keys' && (ev.key?.id ?? null) !== (p.k ?? null)) return no('not_registered', base); // pass bound to its key
  } else if (req != null) {
    // 0.3.2 returned allowed: true here, which read as "route, method and environment were checked". They were not.
    return { valid: false, allowed: false, identity_valid: true, code: 'policy_required', reason: REASONS.policy_required, ...base };
  }
  return { valid: true, allowed: true, code: 'ok', reason: 'Allowed.', ...base };
}
