// 0.4.4 widened audit: EVERY export of every entry point (and the Cloudflare worker) is enumerated programmatically and
// fuzzed. The 0.4.3 audit listed public entry points by hand and probed them; lower-level exports (evaluate,
// strictCheck, verifyLocalPass's secret, held) were reached only through those entry points, which validate first, so
// their own early-return branches and single-path time checks were never exercised. Here:
//  1. every export must be classified (an unclassified export fails the run, so a new export can't be skipped);
//  2. decision functions (anything that can answer allow) get a valid baseline that must allow, then every mutation of
//     one input (malformed resource, identity not explicit, held, secret, expired / not-yet-valid policy, expired pass /
//     key / challenge / answer) must deny; network-backed ones get a PERMISSIVE fake API, so a malformed request that is
//     sent instead of refused shows up as an allow;
//  3. guards (validators, canonicalizers, config checks) get oracle-checked malformed inputs;
//  4. every function (support code too) is called with a generic fuzz corpus in every argument position, plus seeded
//     random structures; any allow-shaped answer from a decision/guard function on that corpus is a finding, and every
//     function must return or throw within 2 s (no hangs).
// usage: node --test test/fuzz-exports.test.mjs           (TL_PKG_ROOT=<package root> to fuzz an installed copy)
//        FUZZ_REPORT=out.json to write the per-export results.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHmac } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const ROOT = process.env.TL_PKG_ROOT ? pathToFileURL(process.env.TL_PKG_ROOT.replace(/\/?$/, '/')) : new URL('../', import.meta.url);
const MOD = {};
for (const e of ['index', 'next', 'express', 'self-verify', 'react']) {
  try { MOD[e] = await import(new URL(`dist/${e}.js`, ROOT)); } catch (err) { MOD[e] = { __load_error: String(err.message).slice(0, 120) }; }
}
MOD.cf = await import(new URL('examples/cloudflare-worker/worker.js', ROOT));
const VERSION = JSON.parse(readFileSync(new URL('package.json', ROOT), 'utf8')).version;

// ---------------------------------------------------------------- fixtures
const SK = 'sk_' + 'f'.repeat(40), SECRET = 's'.repeat(40), A = 'bc1qfuzz00000000000000000000000000000000';
const PASS = 'pp1.' + 'A'.repeat(40) + '.' + 'B'.repeat(43);
const iso = (ms) => new Date(ms).toISOString();
const NOW = Date.now();
const OKRES = { path: '/members/x', method: 'GET' };
const policy = (o = {}) => ({ v: 1, typ: 'tokenlock.policy', site_id: 'local', seq: 1, issued_at: iso(NOW - 60e3), expires_at: iso(NOW + 3600e3), orgs: [], revoked_assets: [], keys: [], ...o });
const KEY = { id: 'k1', address: A, status: 'active', permissions: { routes: ['/*'], methods: ['*'], environments: ['*'] } };
const REG = policy({ mode: 'registered_keys', keys: [KEY] });
const TOK = policy({ mode: 'token', assets: ['GOTPROOF'] });
const TIME_BAD = {
  'policy expired (2020)': { issued_at: '2020-01-01T00:00:00.000Z', expires_at: '2020-01-31T00:00:00.000Z' },
  'policy expired 1 s ago': { issued_at: iso(NOW - 3600e3), expires_at: iso(NOW - 1000) },
  'policy issued tomorrow (not yet valid)': { issued_at: iso(NOW + 86400e3), expires_at: iso(NOW + 2 * 86400e3) },
};
// Malformed authorization requests. Every one must be refused wherever a resource is accepted.
const MAL = {
  undefined: undefined, null: null, 'empty object': {}, array: [], string: '/members/x', number: 1, true: true,
  'typo pth': { pth: '/members/x', method: 'GET' }, 'typo pth only': { pth: '/members/x' }, 'path array': { path: ['/members/x'], method: 'GET' }, 'path array only': { path: ['/members/x'] },
  'path only': { path: '/members/x' }, 'method only': { method: 'GET' }, 'environment only': { environment: 'production' },
  'empty path': { path: '', method: 'GET' }, 'padded path': { path: ' /members/x', method: 'GET' }, 'empty method': { path: '/members/x', method: '' },
  'null method': { path: '/members/x', method: null }, 'empty environment': { ...OKRES, environment: '' }, 'null environment': { ...OKRES, environment: null }, 'padded environment': { ...OKRES, environment: ' production ' },
  'relative path': { path: 'members/x', method: 'GET' }, traversal: { path: '/a/../members/x', method: 'GET' }, 'encoded dot': { path: '/%2e%2e/members', method: 'GET' }, 'double encoded': { path: '/%252e%252e/x', method: 'GET' },
  'encoded slash': { path: '/members%2fx', method: 'GET' }, backslash: { path: '/members\\x', method: 'GET' }, NUL: { path: '/members\u0000x', method: 'GET' }, 'bad escape': { path: '/%zz', method: 'GET' },
  'long method': { path: '/members/x', method: 'GETXXXXXXXXXXX' }, 'method with space': { path: '/members/x', method: 'G ET' }, 'method array': { path: '/members/x', method: ['GET'] },
  'extra field': { ...OKRES, route: '/admin' }, 'identityOnly "true"': { identityOnly: 'true' }, 'identityOnly false': { identityOnly: false }, 'identityOnly + path': { identityOnly: true, ...OKRES }, 'identity_only (snake)': { identity_only: true },
  'inherited fields': Object.create({ path: '/members/x', method: 'GET' }), 'path object': { path: { toString: () => '/members/x' }, method: 'GET' }, 'class instance': new (class R { constructor() { this.path = '/members/x'; this.method = 'GET'; } })(),
  'over-long path': { path: '/' + 'a'.repeat(3000), method: 'GET' }, 'environment with space': { ...OKRES, environment: 'prod uction' },
};
// seeded random malformed resources (each has at least one defect)
function rng(seed) { return () => { seed |= 0; seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const R = rng(0x044);
const pick = (a) => a[Math.floor(R() * a.length)];
const VALS = [undefined, null, '', ' ', 0, 1, -1, NaN, true, false, [], [''], {}, '/x', '/members/x', 'GET', 'production', '../', '/%2e', '\u0000', 'x'.repeat(40), ['/x'], { a: 1 }];
for (let i = 0; i < 150; i++) {
  const o = {}; const keys = ['path', 'method', 'environment', 'identityOnly', 'pth', 'Path', 'METHOD', 'identity_only', '__proto__x'];
  const n = 1 + Math.floor(R() * 3);
  for (let j = 0; j < n; j++) o[pick(keys)] = pick(VALS);
  const valid = (typeof o.path === 'string' && /^\/[a-z/]*$/.test(o.path) && o.path.length > 1 && typeof o.method === 'string' && /^[A-Za-z]{1,10}$/.test(o.method) && Object.keys(o).every((k) => ['path', 'method', 'environment'].includes(k)) && (o.environment === undefined ? !('environment' in o) : typeof o.environment === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,29}$/.test(o.environment)))
    || (o.identityOnly === true && Object.keys(o).length === 1);
  if (!valid) MAL[`random #${i}`] = o;
}
const GENERIC = [undefined, null, '', 'x', '/', '/members/x', 0, -1, 1e309, NaN, true, false, [], [null], {}, { valid: true, allowed: true }, () => true, Symbol('s'), 10n, Object.create(null), '%zz', '\u0000', 'a'.repeat(5000), new Date(0)];
const allowShaped = (v) => v === true || (!!v && typeof v === 'object' && (v.valid === true || v.allowed === true || v.ok === true));

// permissive fake API: answers "valid, allowed, for exactly what you asked" to ANY request, so anything that reaches the
// network counts as an allow; `calls` shows whether the request was sent at all.
function permissiveFetch(calls) {
  return async (url, init = {}) => {
    const b = JSON.parse(init.body || '{}'); calls.push(b);
    const res = b.identity_only ? undefined : { path: typeof b.path === 'string' ? b.path.toLowerCase() : b.path ?? null, method: b.method ?? null, environment: b.environment ?? null };
    const body = { valid: true, allowed: true, address: A, site_id: 's1', expires_at: iso(NOW + 3600e3), assets_held: ['GOTPROOF'], ...(res ? { resource: res, access: { mode: 'registered_keys', allowed: true, reason: 'ok', resource: res } } : {}) };
    return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  };
}
const withOpts = (v, o) => { if (v && typeof v === 'object' && !Array.isArray(v)) { const x = Object.create(Object.getPrototypeOf(v)); return Object.assign(x, v, o); } return { ...o, resource: v }; };
const req = (cookie = PASS) => ({ headers: { cookie: 'tokenlock_pass=' + cookie } });
const pass = (o = {}) => MOD['self-verify'].issuePass({ sub: A, h: ['GOTPROOF'], k: 'k1', n: 'n', s: 'https://shop.example', i: NOW, e: NOW + 3600e3, ...o }, SECRET);

// ---------------------------------------------------------------- decision harnesses: baseline must allow; every mutation must deny
const findings = [];
const report = {};
const isDeny = (r) => !allowShaped(r);
async function outcome(fn) { try { const v = await Promise.race([fn(), new Promise((_, j) => setTimeout(() => j(new Error('TIMEOUT')), 2000))]); return { v }; } catch (e) { return { e: e?.code || e?.message || String(e) }; } }
async function decision(name, baseline, mutations) {
  const r = { kind: 'decision', baseline: null, mutations: 0, denied: 0, findings: [] };
  const b = await outcome(baseline);
  r.baseline = b.e ? 'threw ' + b.e : allowShaped(b.v) ? 'allow' : 'deny ' + (b.v?.code || b.v?.reason || '');
  if (r.baseline !== 'allow') r.findings.push('baseline did not allow (harness or regression): ' + r.baseline);
  for (const [label, fn] of mutations) {
    r.mutations++;
    const o = await outcome(fn);
    if (o.e === 'TIMEOUT') r.findings.push(`${label}: TIMEOUT`);
    else if (!o.e && allowShaped(o.v)) r.findings.push(`${label}: ALLOWED ${JSON.stringify(o.v).slice(0, 160)}`);
    else r.denied++;
  }
  report[name] = r; for (const f of r.findings) findings.push(`${name}: ${f}`);
}
const SV = () => MOD['self-verify'];
const resMutations = (mk, skip = []) => Object.entries(MAL).filter(([k]) => !skip.includes(k)).map(([k, v]) => [`resource ${k}`, () => mk(v)]);
// verifyPass(pass, opts) / getPass(req, opts) take ONE options object and copy its own fields: a class instance whose own
// path/method are valid strings is the same request as the plain object (inherited fields are not copied). Documented
// exclusion; TokenlockClient#verifyPass(pass, resource) gets the instance itself and must refuse it.
const OPTS_CONTAINER_SKIP = ['class instance'];
const H = {};
// ---- self-verify
H['self-verify.evaluate'] = () => decision('self-verify.evaluate', () => SV().evaluate(REG, { address: A, held: ['GOTPROOF'], resource: OKRES }), [
  ...resMutations((v) => SV().evaluate(REG, { address: A, held: ['GOTPROOF'], resource: v })),
  ...resMutations((v) => SV().evaluate(TOK, { address: A, held: ['GOTPROOF'], resource: v })).map(([l, f]) => ['token mode ' + l, f]),
  ['token mode, valid resource (no route rules)', () => SV().evaluate(TOK, { address: A, held: ['GOTPROOF'], resource: OKRES })],
  ['identity not explicit (no resource)', () => SV().evaluate(TOK, { address: A, held: ['GOTPROOF'] })],
  ['unknown option', () => SV().evaluate(TOK, { address: A, held: ['GOTPROOF'], identityOnly: true, resourse: OKRES })],
  ...[null, undefined, 'GOTPROOF', [1], {}].map((h) => [`held ${JSON.stringify(h)}`, () => SV().evaluate(TOK, { address: A, held: h, identityOnly: true })]),
  ['held [] (holds nothing)', () => SV().evaluate(TOK, { address: A, held: [], identityOnly: true })],
  ...Object.entries(TIME_BAD).flatMap(([k, t]) => [[`${k} (registered, resource)`, () => SV().evaluate({ ...REG, ...t }, { address: A, held: ['GOTPROOF'], resource: OKRES })], [`${k} (token, identity)`, () => SV().evaluate({ ...TOK, ...t }, { address: A, held: ['GOTPROOF'], identityOnly: true })]]),
  ['key expired', () => SV().evaluate(policy({ mode: 'registered_keys', keys: [{ ...KEY, expires_at: iso(NOW - 1000) }] }), { address: A, held: ['GOTPROOF'], resource: OKRES })],
  ['key revoked', () => SV().evaluate(policy({ mode: 'registered_keys', keys: [{ ...KEY, status: 'revoked' }] }), { address: A, held: ['GOTPROOF'], resource: OKRES })],
  ['malformed policy (mode typo)', () => SV().evaluate({ ...REG, mode: 'registered_key' }, { address: A, held: ['GOTPROOF'], resource: OKRES })],
  ['malformed policy (keys string)', () => SV().evaluate({ ...REG, keys: 'k1' }, { address: A, held: ['GOTPROOF'], resource: OKRES })],
  ['policy missing expires_at', () => { const p = { ...REG }; delete p.expires_at; return SV().evaluate(p, { address: A, held: ['GOTPROOF'], resource: OKRES }); }],
]);
H['self-verify.verifyLocalPass'] = () => decision('self-verify.verifyLocalPass', () => SV().verifyLocalPass(pass(), { passSecret: SECRET, policy: SV().localPolicy(REG), resource: OKRES }), [
  ...resMutations((v) => SV().verifyLocalPass(pass(), { passSecret: SECRET, policy: SV().localPolicy(REG), resource: v })),
  ['no resource, no identityOnly', () => SV().verifyLocalPass(pass(), { passSecret: SECRET, policy: SV().localPolicy(REG) })],
  ['token-mode policy + resource', () => SV().verifyLocalPass(pass({ k: null }), { passSecret: SECRET, policy: SV().localPolicy(TOK), resource: OKRES })],
  ['no policy + resource', () => SV().verifyLocalPass(pass(), { passSecret: SECRET, resource: OKRES })],
  ...['', 'short', undefined, null, 5].map((s) => [`passSecret ${JSON.stringify(s)} + pass forged with that key`, () => { const body = Buffer.from(JSON.stringify({ v: 1, sub: A, h: ['GOTPROOF'], k: null, n: 'x', s: 'x', i: NOW, e: NOW + 3600e3 })).toString('base64url'); return SV().verifyLocalPass(`tl3.${body}.${createHmac('sha256', String(s ?? '')).update('tl3.' + body).digest('base64url')}`, { passSecret: s, identityOnly: true }); }]),
  ['pass signed with another secret', () => SV().verifyLocalPass(SV().issuePass({ sub: A, h: ['GOTPROOF'], k: 'k1', n: 'n', s: 's', i: NOW, e: NOW + 3600e3 }, 'o'.repeat(40)), { passSecret: SECRET, identityOnly: true })],
  ['pass expired', () => SV().verifyLocalPass(pass({ e: NOW - 1000 }), { passSecret: SECRET, identityOnly: true })],
  ...Object.entries(TIME_BAD).flatMap(([k, t]) => [[`${k}, identity`, () => SV().verifyLocalPass(pass(), { passSecret: SECRET, policy: SV().localPolicy({ ...REG, ...t }), identityOnly: true })], [`${k}, resource`, () => SV().verifyLocalPass(pass(), { passSecret: SECRET, policy: SV().localPolicy({ ...REG, ...t }), resource: OKRES })], [`${k}, custom source`, () => SV().verifyLocalPass(pass(), { passSecret: SECRET, policy: { get: async () => ({ ...REG, ...t }) }, identityOnly: true })], [`${k}, token mode identity`, () => SV().verifyLocalPass(pass({ k: null }), { passSecret: SECRET, policy: SV().localPolicy({ ...TOK, ...t }), identityOnly: true })]]),
  ['custom source returns a malformed policy', () => SV().verifyLocalPass(pass(), { passSecret: SECRET, policy: { get: async () => ({ ...REG, mode: 'x' }) }, identityOnly: true })],
  ['policy source throws', () => SV().verifyLocalPass(pass(), { passSecret: SECRET, policy: { get: async () => { throw new Error('down'); } }, identityOnly: true })],
  ['pass bound to another key', () => SV().verifyLocalPass(pass({ k: 'k2' }), { passSecret: SECRET, policy: SV().localPolicy(REG), resource: OKRES })],
  ['unknown option', () => SV().verifyLocalPass(pass(), { passSecret: SECRET, identityOnly: true, polcy: {} })],
]);
H['self-verify.localPolicy'] = () => decision('self-verify.localPolicy', () => SV().localPolicy(REG).get().then(() => ({ ok: true })), [
  ...Object.entries(TIME_BAD).map(([k, t]) => [k, () => SV().localPolicy({ ...REG, ...t }).get().then(() => ({ ok: true }))]),
  ['mode typo', () => SV().localPolicy({ ...REG, mode: 'tokens' }).get().then(() => ({ ok: true }))],
  ['expires_at not a date', () => SV().localPolicy({ ...REG, expires_at: 'tomorrow' }).get().then(() => ({ ok: true }))],
]);
H['self-verify.validatePolicy'] = () => decision('self-verify.validatePolicy', () => { SV().validatePolicy(REG); return { ok: true }; }, [
  ['mode typo', () => { SV().validatePolicy({ ...REG, mode: 'x' }); return { ok: true }; }], ['seq float', () => { SV().validatePolicy({ ...REG, seq: 1.5 }); return { ok: true }; }],
  ['methods string', () => { SV().validatePolicy({ ...REG, keys: [{ ...KEY, permissions: { methods: 'GET,POST' } }] }); return { ok: true }; }],
  ['expires before issued', () => { SV().validatePolicy({ ...REG, issued_at: iso(NOW), expires_at: iso(NOW - 1) }); return { ok: true }; }],
]);
H['self-verify.verifySignIn'] = async () => {
  const { secp256k1 } = await import('@noble/curves/secp256k1.js');
  const { createHash } = await import('node:crypto');
  const priv = secp256k1.utils.randomSecretKey(); const addr = SV()._addr.p2wpkh(secp256k1.getPublicKey(priv, true));
  const sign = (message) => { const sha = (b) => createHash('sha256').update(b).digest(); const m = Buffer.from(message); const len = m.length < 253 ? Buffer.from([m.length]) : Buffer.from([253, m.length & 255, m.length >> 8]); const h = sha(sha(Buffer.concat([Buffer.from('\x18Bitcoin Signed Message:\n'), len, m]))); const s = secp256k1.sign(h, priv, { prehash: false, format: 'recovered' }); return Buffer.concat([Buffer.from([39 + s[0]]), Buffer.from(s.slice(1))]).toString('base64'); };
  const run = async (cfg = {}, opts = {}) => { const store = SV().memoryNonceStore(); const ch = await SV().createChallenge({ site: 'https://shop.example', assets: ['GOTPROOF'], store, ...(opts.ttl ? { ttlSeconds: opts.ttl } : {}) }); const r = await SV().verifySignIn({ challenge_id: ch.challenge_id, address: addr, signature: opts.badSig ? sign('other') : sign(ch.message) }, { store, holdings: SV().staticProvider({ [addr]: ['GOTPROOF'] }), passSecret: SECRET, ...cfg }, opts.now); return r; };
  await decision('self-verify.verifySignIn', () => run(), [
    ['bad signature', () => run({}, { badSig: true })], ['challenge expired', () => run({}, { now: NOW + 3600e3 })],
    ['holdings provider throws', () => run({ holdings: { name: 'x', async holdings() { throw new Error('down'); } } })],
    ['holdings provider says held: "yes"', () => run({ holdings: { name: 'x', async holdings() { return { GOTPROOF: { held: 'yes' } }; } } })],
    ...Object.entries(TIME_BAD).map(([k, t]) => [`${k} (token policy)`, () => run({ policy: SV().localPolicy({ ...TOK, ...t }) })]),
    ...Object.entries(TIME_BAD).map(([k, t]) => [`${k} (custom source)`, () => run({ policy: { get: async () => ({ ...TOK, ...t }) } })]),
    ['registered-keys policy, wallet not registered', () => run({ policy: SV().localPolicy(REG) })],
    ['passSecret too short', () => run({ passSecret: 'short' })],
  ]);
};
// bundles signed here with a throwaway BIP340 key (same construction as test/self-verify.test.mjs)
async function signer() {
  const { secp256k1, schnorr } = await import('@noble/curves/secp256k1.js'); const { createHash } = await import('node:crypto');
  const sha = (b) => createHash('sha256').update(b).digest(); const sk = secp256k1.utils.randomSecretKey(); const pk = Buffer.from(schnorr.getPublicKey(sk)).toString('hex');
  const sign = (payload) => { const bytes = Buffer.from(JSON.stringify(payload)); const tag = sha(Buffer.from('TOKENLOCK/policy/v1')); return { v: 1, typ: 'tokenlock.policy-bundle', alg: 'BIP340', kid: 'k1', payload: bytes.toString('base64url'), sig: Buffer.from(schnorr.sign(sha(Buffer.concat([tag, tag, bytes])), sk)).toString('hex') }; };
  return { pk, sign };
}
H['self-verify.verifyPolicyBundle'] = async () => {
  const { pk, sign } = await signer(); const P = { ...TOK, site_id: 's1' }; const o = { publicKeys: { k1: pk }, siteId: 's1' };
  const v = (b, x = {}) => { SV().verifyPolicyBundle(b, { ...o, ...x }); return { ok: true }; };
  await decision('self-verify.verifyPolicyBundle', () => v(sign(P)), [
    ...Object.entries(TIME_BAD).map(([k, t]) => [k, () => v(sign({ ...P, ...t }))]),
    ['other site', () => v(sign(P), { siteId: 'other' })], ['tampered payload', () => { const b = sign(P); return v({ ...b, payload: Buffer.from(JSON.stringify({ ...P, mode: 'registered_keys' })).toString('base64url') }); }],
    ['unpinned key', () => v(sign(P), { publicKeys: ['00'.repeat(32)] })], ['rollback', () => v(sign(P), { minSeq: 99 })], ['maxAge exceeded', () => v(sign({ ...P, issued_at: iso(NOW - 7200e3) }), { maxAgeSeconds: 60 })],
  ]);
};
H['self-verify.signedPolicy'] = async () => {
  const { pk, sign } = await signer(); const P = { ...TOK, site_id: 's1' };
  const get = (load) => SV().signedPolicy({ siteId: 's1', secretKey: SK, publicKeys: { k1: pk }, load }).get().then(() => ({ ok: true }));
  await decision('self-verify.signedPolicy', () => get(async () => sign(P)), [
    ...Object.entries(TIME_BAD).map(([k, t]) => [k, () => get(async () => sign({ ...P, ...t }))]),
    ['load throws', () => get(async () => { throw new Error('down'); })], ['garbage bundle', () => get(async () => ({ v: 1 }))], ['bundle for another site', () => get(async () => sign({ ...P, site_id: 'other' }))],
  ]);
};
// ---- providers: garbage / failing upstream answers never mean "held"
const PROVIDERS = {
  tokenscanProvider: (f) => SV().tokenscanProvider({ fetch: f }), proveitonchainProvider: (f) => SV().proveitonchainProvider({ fetch: f }),
  httpJsonProvider: (f) => SV().httpJsonProvider({ url: 'https://h.example/{address}/{asset}', quantity: (b) => b?.qty, fetch: f }),
};
for (const [n, mk] of Object.entries(PROVIDERS)) H['self-verify.' + n] = async () => {
  const r = { kind: 'decision (holdings)', mutations: 0, denied: 0, findings: [] };
  const answers = { 'HTTP 500': () => new Response('x', { status: 500 }), 'non-JSON 200': () => new Response('<html>', { status: 200 }), 'JSON null': () => new Response('null', { status: 200 }), 'JSON array': () => new Response('[1]', { status: 200 }), 'held as string': () => new Response(JSON.stringify({ held: 'true', qty: 'many', data: [{ asset: 'GOTPROOF', quantity: 'NaN' }], result: { owner: [] } }), { status: 200 }), 'network error': () => { throw new Error('down'); } };
  for (const [label, ans] of Object.entries(answers)) {
    r.mutations++;
    const o = await outcome(() => mk(async () => ans()).holdings(A, ['GOTPROOF']));
    if (!o.e && o.v?.GOTPROOF?.held === true) { r.findings.push(`${label}: held true`); findings.push(`self-verify.${n}: ${label}: held true`); } else r.denied++;
  }
  report['self-verify.' + n] = r;
};
H['self-verify.firstAvailable+requireAgreement'] = async () => {
  const yes = SV().staticProvider({ [A]: ['GOTPROOF'] }), no = SV().staticProvider({}), down = { name: 'down', async holdings() { throw new Error('down'); } };
  const r1 = await outcome(() => SV().requireAgreement([yes, no]).holdings(A, ['GOTPROOF']));
  const r2 = await outcome(() => SV().requireAgreement([yes, down]).holdings(A, ['GOTPROOF']));
  const r3 = await outcome(() => SV().firstAvailable([down, down]).holdings(A, ['GOTPROOF']));
  report['self-verify.firstAvailable+requireAgreement'] = { kind: 'decision (holdings)', results: [r1, r2, r3].map((o) => o.e || JSON.stringify(o.v)) };
  for (const [l, o] of [['requireAgreement yes/no', r1], ['requireAgreement yes/down', r2], ['firstAvailable all down', r3]]) if (!o.e && o.v?.GOTPROOF?.held === true) findings.push(`self-verify: ${l}: held true`);
};
// ---- hosted-client SDK (index / next / express): malformed requests must be refused before any network call
for (const m of ['index', 'next', 'express']) {
  H[`${m}.verifyPass`] = async () => { const calls = []; await decision(`${m}.verifyPass`, () => MOD[m].verifyPass(PASS, { secretKey: SK, fetch: permissiveFetch(calls), cache: false, ...OKRES }), resMutations((v) => MOD[m].verifyPass(PASS, withOpts(v, { secretKey: SK, fetch: permissiveFetch(calls), cache: false })), OPTS_CONTAINER_SKIP).concat([['no resource (identity not explicit)', () => MOD[m].verifyPass(PASS, { secretKey: SK, fetch: permissiveFetch(calls), cache: false })]])); };
  H[`${m}.getPass`] = async () => { const calls = []; await decision(`${m}.getPass`, () => MOD[m].getPass(req(), { secretKey: SK, fetch: permissiveFetch(calls), cache: false, ...OKRES }), resMutations((v) => MOD[m].getPass(req(), withOpts(v, { secretKey: SK, fetch: permissiveFetch(calls), cache: false })), OPTS_CONTAINER_SKIP).concat([['no resource (identity not explicit)', () => MOD[m].getPass(req(), { secretKey: SK, fetch: permissiveFetch(calls), cache: false })]])); };
  H[`${m}.authorize`] = async () => { const calls = []; await decision(`${m}.authorize`, () => MOD[m].authorize(req(), OKRES, { secretKey: SK, fetch: permissiveFetch(calls) }), resMutations((v) => MOD[m].authorize(req(), v, { secretKey: SK, fetch: permissiveFetch(calls) })).concat([['identityOnly (authorize needs an action)', () => MOD[m].authorize(req(), { identityOnly: true }, { secretKey: SK, fetch: permissiveFetch(calls) })]])); };
  H[`${m}.TokenlockClient`] = async () => { const calls = []; const c = new MOD[m].TokenlockClient({ secretKey: SK, fetch: permissiveFetch(calls), cache: false }); await decision(`${m}.TokenlockClient#verifyPass`, () => c.verifyPass(PASS, OKRES), resMutations((v) => c.verifyPass(PASS, v))); };
}
// middleware: malformed config refused; request paths fuzzed through the real middleware with a permissive API
const mwConfigBad = { 'protect without /': { protect: ['members/*'] }, 'protect empty': { protect: [] }, 'tokenOnly string': { tokenOnly: 'false' }, 'typo option': { tokenonly: true }, failOpen: { failOpen: false }, checkResource: { checkResource: true }, 'strict false': { strict: false }, 'bad environment': { environment: 'prod uction' }, 'bad secret': { secretKey: 'nope' }, 'no signInPage': { signInPage: '' } };
for (const m of ['express', 'next']) H[`${m}.tokenlock`] = async () => {
  const base = { protect: ['/members/:path*'], signInPage: '/signin', secretKey: SK };
  const r = { kind: 'decision (middleware)', mutations: 0, denied: 0, findings: [] };
  for (const [label, o] of Object.entries(mwConfigBad)) { r.mutations++; try { MOD[m].tokenlock({ ...base, ...o }); r.findings.push(`config ${label}: accepted`); findings.push(`${m}.tokenlock: config ${label}: accepted`); } catch (e) { if (e.code === 'bad_config') r.denied++; else { r.findings.push(`config ${label}: threw ${e.code || e.message}`); } } }
  report[`${m}.tokenlock`] = r;
};
H['express.tokenlock(paths)'] = async () => {
  const calls = []; const mw = MOD.express.tokenlock({ protect: ['/members/:path*'], signInPage: '/signin', secretKey: SK, fetch: permissiveFetch(calls), cache: false });
  const run = (url, cookie) => new Promise((done) => { const res = { statusCode: 200, headers: {}, setHeader(k, v) { this.headers[k] = v; }, getHeader(k) { return this.headers[k]; }, end() { done({ status: this.statusCode, next: false }); } }; mw({ method: 'GET', url, originalUrl: url, headers: { host: 'x', cookie: cookie ? 'tokenlock_pass=' + cookie : '', accept: 'application/json' } }, res, () => done({ status: 200, next: true })); });
  const r = { kind: 'decision (middleware paths)', mutations: 0, denied: 0, findings: [] };
  for (const p of ['/MEMBERS/x', '//members/x', '/%6dembers/x', '/members%2fx', '/members/../members/x', '/members/%2e%2e/x', '/members;x', '/members\\x', '/members/%252e']) {
    r.mutations++; const o = await run(p, null); if (o.next) { r.findings.push(`no pass ${p}: served`); findings.push(`express.tokenlock: no pass ${p}: served`); } else r.denied++;
  }
  report['express.tokenlock(paths)'] = r;
};
// ---- Cloudflare worker
const CFENV = { TOKENLOCK_SECRET_KEY: SK, TOKENLOCK_SITE_KEY: 'pk_x' };
H['cf.verify'] = async () => { const calls = []; const f0 = globalThis.fetch; globalThis.fetch = permissiveFetch(calls); try { await decision('cf.verify', () => MOD.cf.verify(PASS, CFENV, OKRES).then((x) => ({ ok: x.ok })), resMutations((v) => MOD.cf.verify(PASS, CFENV, v).then((x) => ({ ok: x.ok })))); } finally { globalThis.fetch = f0; } };
H['cf.strictCheck'] = async () => {
  const ans = (res) => ({ valid: true, allowed: true, address: A, site_id: 's1', expires_at: iso(NOW + 3600e3), access: { mode: 'registered_keys', allowed: true, reason: 'ok' }, resource: res });
  await decision('cf.strictCheck', () => MOD.cf.strictCheck(ans({ path: '/members/x', method: 'GET', environment: null }), OKRES), [
    ...resMutations((v) => MOD.cf.strictCheck(ans({ path: null, method: null, environment: null }), v === null || v === undefined ? { pth: 1 } : v)),
    ['answer expired', () => MOD.cf.strictCheck({ ...ans({ path: '/members/x', method: 'GET', environment: null }), expires_at: iso(NOW - 1000) }, OKRES)],
    ['answer for another resource', () => MOD.cf.strictCheck(ans({ path: '/admin', method: 'GET', environment: null }), OKRES)],
    ['answer without access block (token-only)', () => MOD.cf.strictCheck({ valid: true, allowed: true, address: A, site_id: 's1', expires_at: iso(NOW + 3600e3), resource: { path: '/members/x', method: 'GET', environment: null } }, OKRES)],
  ]);
};
H['cf.configProblem'] = async () => {
  const r = { kind: 'guard', mutations: 0, denied: 0, findings: [] };
  for (const [label, env] of Object.entries({ 'no secret': {}, 'secret not sk_': { TOKENLOCK_SECRET_KEY: 'x' }, 'FAIL_OPEN set': { ...CFENV, TOKENLOCK_FAIL_OPEN: '0' }, 'PROTECT glob': { ...CFENV, TOKENLOCK_PROTECT: '/members/*' }, 'PROTECT relative': { ...CFENV, TOKENLOCK_PROTECT: 'members' }, 'TOKEN_ONLY yes': { ...CFENV, TOKENLOCK_TOKEN_ONLY: 'yes' }, 'timeout 0': { ...CFENV, TOKENLOCK_TIMEOUT_MS: '0' }, 'API ftp': { ...CFENV, TOKENLOCK_API: 'ftp://x' }, 'environment space': { ...CFENV, TOKENLOCK_ENVIRONMENT: 'a b' } })) {
    r.mutations++; if (MOD.cf.configProblem(env) === null) { r.findings.push(label + ': accepted'); findings.push('cf.configProblem: ' + label + ': accepted'); } else r.denied++;
  }
  report['cf.configProblem'] = r;
};
H['cf.default'] = async () => {
  const calls = []; const f0 = globalThis.fetch; let origin = 0;
  let fwd = '';
  globalThis.fetch = async (input, init) => { if (input instanceof Request) { fwd = new URL(input.url).pathname; origin = MOD.cf.canonicalPath(fwd) === null || /^\/members(\/|$)/i.test(MOD.cf.canonicalPath(fwd)) ? 1 : 0; return new Response('ORIGIN CONTENT'); } return permissiveFetch(calls)(input, init); };
  const r = { kind: 'decision (worker paths)', mutations: 0, denied: 0, findings: [] };
  try {
    for (const p of ['/members/x', '/MEMBERS/x', '//members/x', '/%6dembers/x', '/members%2fx', '/members/../members/x', '/members/%2e%2e/x', '/members/%252e']) {
      r.mutations++; origin = 0;
      const res = await MOD.cf.default.fetch(new Request('https://w.example' + p, { headers: { accept: 'application/json' } }), CFENV);
      if (origin) { r.findings.push(`no pass ${p}: served ${fwd}`); findings.push(`cf.default: no pass ${p}: forwarded protected ${fwd} (${res.status})`); } else r.denied++;
    }
  } finally { globalThis.fetch = f0; }
  report['cf.default'] = r;
};
// ---------------------------------------------------------------- guards (oracle-checked)
const GUARDS = {
  'index.validateResource': () => Object.entries(MAL).map(([k, v]) => [k, () => { const x = MOD.index.validateResource(v); return x === null ? { allowed: true, identity: true } : { allowed: true }; }]),
  'index.authorizeResource': () => Object.entries(MAL).map(([k, v]) => [k, () => { const x = MOD.index.authorizeResource(v); return x === 'bad_path' ? { allowed: false } : { allowed: true }; }]),
  'index.splitAuthOptions': () => [['unknown key', () => (MOD.index.splitAuthOptions({ pth: '/x' }, 't'), { allowed: true })], ['array', () => (MOD.index.splitAuthOptions([], 't'), { allowed: true })]],
  'index.canonicalPath': () => ['/a/../b', '/%2e%2e', '/a%2fb', '/a\\b', '/a;b', '/%252e', 'rel', '', '/\u0000', '/%zz'].map((p) => [p, () => ({ allowed: MOD.index.canonicalPath(p) !== null })]),
  'index.resourcePath': () => ['/a/../b', '/%2e%2e', 'rel', ''].map((p) => [p, () => ({ allowed: MOD.index.resourcePath(p) !== null })]),
  'self-verify.normalizePath': () => ['/a/../b', '/%2e%2e', 'rel', '', '/%252e'].map((p) => [p, () => ({ allowed: SV().normalizePath(p) !== null })]),
  'cf.canonicalPath': () => ['/a/../b', '/%2e%2e', '/a%2fb', '/a\\b', '/%252e', 'rel', ''].map((p) => [p, () => ({ allowed: MOD.cf.canonicalPath(p) !== null })]),
  'index.checkClientOptions': () => Object.entries({ failOpen: { failOpen: false }, 'strict false': { strict: false }, 'cache string': { cache: 'no' }, 'timeout 0': { timeoutMs: 0 }, 'apiBase ftp': { apiBase: 'ftp://x' }, 'secret bad': { secretKey: 'x' } }).map(([k, o]) => [k, () => (MOD.index.checkClientOptions(o, 't'), { allowed: true })]),
  'index.checkAdapterOptions': () => [['failOpen', () => (MOD.index.checkAdapterOptions({ failOpen: true }, 't'), { allowed: true })]],
  'index.safeNext': () => ['//evil.com', '/\\evil.com', 'javascript:alert(1)', 'https://evil.com', '/%2f%2fevil.com', '/\t/evil.com', '/%5cevil.com'].map((p) => [p, () => ({ allowed: MOD.index.safeNext(p, '/') !== '/' })]),
  'cf.safeNext': () => ['//evil.com', '/\\evil.com', 'javascript:alert(1)', '/%2f%2fevil.com'].map((p) => [p, () => ({ allowed: MOD.cf.safeNext(p) !== '/' })]),
  'index.createMatcher': () => ['/MEMBERS', '//members', '/%6dembers', '/members/../x', '/members%2f..'].map((p) => [p, () => ({ allowed: !MOD.index.createMatcher(['/members/:path*'])(p) })]),
  'self-verify.routeMatches': () => [['/membersX vs /members/*', () => ({ allowed: SV().routeMatches('/members/*', '/membersx') })], ['/admin vs /members', () => ({ allowed: SV().routeMatches('/members', '/admin') })]],
  'self-verify.verifyMessageSignature': () => [['empty signature', () => ({ allowed: SV().verifyMessageSignature(A, 'm', '') })], ['garbage', () => ({ allowed: SV().verifyMessageSignature(A, 'm', 'AAAA') })], ['non-string', () => ({ allowed: SV().verifyMessageSignature(A, 'm', {}) })]],
  'self-verify.decodeAddress': () => [['garbage', () => ({ allowed: !!SV().decodeAddress('bc1qnotanaddress') })], ['object', () => ({ allowed: !!SV().decodeAddress({}) })]],
  'self-verify.normalizeAsset': () => [['lowercase junk', () => (SV().normalizeAsset('a b'), { allowed: true })], ['empty', () => (SV().normalizeAsset(''), { allowed: true })]],
  'self-verify.issuePass': () => [['short secret', () => (SV().issuePass({ sub: A, h: [], k: null, n: 'n', s: 's', i: 0, e: 1 }, 'short'), { allowed: true })], ['empty secret', () => (SV().issuePass({ sub: A, h: [], k: null, n: 'n', s: 's', i: 0, e: 1 }, ''), { allowed: true })]],
  'index.isUnavailable': () => [['no_secret_key', () => ({ allowed: MOD.index.isUnavailable(new MOD.index.TokenlockError('x', 0, 'no_secret_key')) })], ['plain Error', () => ({ allowed: MOD.index.isUnavailable(new Error('x')) })]],
  'index.denialStatus': () => [['undefined → 401', () => ({ allowed: MOD.index.denialStatus(undefined) !== 401 })]],
};
async function guard(name, cases) {
  const r = { kind: 'guard', mutations: 0, denied: 0, findings: [] };
  for (const [label, fn] of cases) { r.mutations++; const o = await outcome(fn); if (!o.e && allowShaped(o.v)) { r.findings.push(`${label}: accepted`); findings.push(`${name}: ${label}: accepted ${JSON.stringify(o.v)}`); } else r.denied++; }
  report[name] = r;
}
// ---------------------------------------------------------------- classification of every export
const SUPPORT = { // no allow/deny answer of their own; fuzzed generically for crashes and hangs
  DEFAULT_API: 'constant', DEFAULT_COOKIE: 'constant', DENIED_CODES: 'constant', ENVIRONMENT_RE: 'constant (used by validateResource, fuzzed there)', FORBIDDEN_CODES: 'constant', MAX_ANSWER_BYTES: 'constant', METHOD_RE: 'constant (used by validateResource)',
  POLICY_REQUIRED_REASON: 'constant', REMOVED_OPTIONS: 'constant', RESOURCE_KEYS: 'constant', SECRET_KEY_RE: 'constant (used by checkClientOptions)', VERSION: 'constant', TokenlockError: 'error class', badConfig: 'error factory',
  clearCache: 'cache reset', clearPassCookie: 'string builder', passCookie: 'string builder', createChallenge: 'starts a sign-in (no access decision)', headerOf: 'header read', parseCookies: 'cookie parse', readPass: 'cookie read', validApiBase: 'URL check (used by checkClientOptions, fuzzed there)', wantsSecure: 'cookie flag', isApiRequest: 'chooses JSON vs redirect after a denial',
  tokenlockRoutes: 'pass → cookie exchange; verifies with { identityOnly: true } (exchangePass), fuzzed generically',
  FORMAT_PROBLEMS: 'constant (format-error texts)', signatureFormatProblem: 'names why a signature is malformed for error messages; never grants access (verifyMessageSignature decides)',
  KEY_STATUSES: 'constant', POLICY_FUTURE_SKEW_MS: 'constant', SPEC_VERSION: 'constant', SelfVerifyError: 'error class', _addr: 'address encoders (test helper)', buildMessage: 'string builder',
  fileNonceStore: 'nonce store (single-use take; covered in self-verify tests)', memoryNonceStore: 'nonce store', redisNonceStore: 'nonce store', staticProvider: 'test provider',
  SignInWithBitcoin: 'React button (browser UI; no decision)', SignInWithToken: 'React button (browser UI; no decision)', SignOutLink: 'React link (browser UI)', loadGate: 'loads gate.js in the browser (no decision)',
};
function classify(mod, name) {
  const full = `${mod}.${name}`;
  if (H[full] || H[`${mod}.${name}(paths)`] || GUARDS[full]) return 'decision/guard';
  if (mod === 'self-verify' && ['firstAvailable', 'requireAgreement'].includes(name)) return 'decision/guard';
  if (['next', 'express'].includes(mod) && GUARDS['index.' + name]) return 'decision/guard (same function as index)';
  if (SUPPORT[name]) return 'support: ' + SUPPORT[name];
  if (mod === 'cf' && name === 'default') return 'decision/guard';
  return null;
}
async function generic(mod, name, fn) {
  const out = { calls: 0, threw: 0, hangs: 0 };
  if (typeof fn !== 'function') return out;
  const arity = Math.min(3, Math.max(1, fn.length + 1));
  for (let pos = 0; pos < arity; pos++) for (const g of GENERIC) {
    const args = new Array(arity).fill(undefined); args[pos] = g;
    out.calls++;
    const o = await outcome(() => (/^[A-Z]/.test(name) && !['TokenlockError', 'SelfVerifyError'].includes(name) ? new fn(...args) : fn(...args)));
    if (o.e === 'TIMEOUT') { out.hangs++; findings.push(`${mod}.${name}: hang with arg${pos}=${String(typeof g)}`); } else if (o.e) out.threw++;
  }
  return out;
}

test(`widened audit: every export of @tokenlock/sdk ${VERSION} is classified and fuzzed`, { timeout: 600000 }, async () => {
  const exportsList = [];
  for (const [m, ns] of Object.entries(MOD)) for (const n of Object.keys(ns)) if (n !== '__load_error') exportsList.push([m, n, ns[n]]);
  const unclassified = exportsList.filter(([m, n]) => !classify(m, n)).map(([m, n]) => `${m}.${n}`);
  for (const h of Object.values(H)) await h();
  for (const [n, mk] of Object.entries(GUARDS)) await guard(n, mk());
  let genericCalls = 0;
  for (const [m, n, v] of exportsList) { const g = await generic(m, n, v); genericCalls += g.calls; report[`${m}.${n}`] = { ...(report[`${m}.${n}`] || {}), class: classify(m, n), generic: g }; }
  const summary = { version: VERSION, root: ROOT.href, exports: exportsList.length, unique_names: new Set(exportsList.map(([, n]) => n)).size, modules: Object.fromEntries(Object.entries(MOD).map(([k, v]) => [k, v.__load_error ? 'load error: ' + v.__load_error : Object.keys(v).length])),
    decision_and_guard_mutations: Object.values(report).reduce((s, r) => s + (r.mutations || 0), 0), generic_calls: genericCalls, unclassified, findings };
  if (process.env.FUZZ_REPORT) writeFileSync(process.env.FUZZ_REPORT, JSON.stringify({ summary, report }, null, 1));
  console.log(JSON.stringify({ ...summary, findings: findings.length }, null, 1));
  for (const f of findings) console.log('FINDING ' + f);
  assert.deepEqual(unclassified, [], 'every export must be classified');
  assert.deepEqual(findings, [], `${findings.length} finding(s)`);
});
