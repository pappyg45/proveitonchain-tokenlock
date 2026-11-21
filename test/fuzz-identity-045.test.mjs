// RC4 (review): every export fuzzed again with nested and identity-flag inputs. The 0.4.4 fuzzer (fuzz-exports)
// treats { identityOnly: true } as a valid request everywhere (it is the client APIs' identity selector), so it never sent
// it as a *resource* to evaluate(), whose selector is a separate top-level field. Here a corpus of identity flags nested
// up to 3 levels (inside resource, path, lists, identityOnly / identity_only values) goes through:
//   - every decision export, in every request position it has (options spread, resource field, resource argument):
//     self-verify evaluate + verifyLocalPass (token and registered), index/next/express verifyPass, getPass, authorize,
//     TokenlockClient#verifyPass (permissive fake API), Cloudflare verify + strictCheck;
//   - the guards validateResource (null = identity: only for exactly { identityOnly: true }) and authorizeResource;
//   - every function export of every entry point, corpus value in each of the first 3 argument positions: any
//     allow-shaped answer is listed (decision/guard exports: a failure; others: reported for review).
// FUZZ_REPORT=<file> writes the results.
import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { VARIANTS, POLICIES, strictIdentity, validResourceRequest } from './vectors/identity-cases.mjs';

const ROOT = process.env.TL_PKG_ROOT ? pathToFileURL(process.env.TL_PKG_ROOT.replace(/\/?$/, '/')) : new URL('../', import.meta.url);
const MOD = {};
for (const e of ['index', 'next', 'express', 'self-verify', 'react']) { try { MOD[e] = await import(new URL(`dist/${e}.js`, ROOT)); } catch (err) { MOD[e] = {}; } }
MOD.cf = await import(new URL('examples/cloudflare-worker/worker.js', ROOT));
const SV = MOD['self-verify'];
const iso = (ms) => new Date(ms).toISOString();
const T = Date.now();
const A = 'bc1qidentityselector000000000000000000000000';
const SK = 'sk_' + 'f'.repeat(40), PASS = 'pp1.' + 'A'.repeat(40) + '.' + 'B'.repeat(43), SECRET = 's'.repeat(40);
const LIVE = Object.fromEntries(Object.entries(POLICIES).map(([k, p]) => [k, { ...p, issued_at: iso(T - 60e3), expires_at: iso(T + 3600e3) }]));

// corpus: identity flags nested up to depth 3
const LEAF = [true, 'true', 1, { identityOnly: true }, { identity_only: true }];
const WRAP = [(x) => ({ resource: x }), (x) => [x], (x) => ({ path: x, method: 'GET' }), (x) => ({ identityOnly: x }), (x) => ({ identity_only: x }), (x) => ({ identityOnly: true, resource: x })];
const corpus = new Map();
const add = (x) => corpus.set(JSON.stringify(x), x);
for (const [, v] of VARIANTS) add(v);
let level = LEAF.slice(); for (const l of level) add(l);
for (let d = 0; d < 3; d++) { const next = []; for (const x of level) for (const w of WRAP) { const y = w(x); next.push(y); add(y); } level = next.slice(0, 400); }
const C = [...corpus.values()];
const allowShaped = (v) => v === true || (!!v && typeof v === 'object' && (v.valid === true || v.allowed === true || v.ok === true));
async function out(fn) { try { return { v: await Promise.race([fn(), new Promise((_, j) => setTimeout(() => j(new Error('TIMEOUT')), 2000))]) }; } catch (e) { return { e: e?.code || e?.message || String(e) }; } }
function permissiveFetch(calls) {
  return async (url, init = {}) => {
    const b = JSON.parse(init.body || '{}'); calls.push(b);
    const res = b.identity_only ? undefined : { path: typeof b.path === 'string' ? b.path.toLowerCase() : b.path ?? null, method: b.method ?? null, environment: b.environment ?? null };
    return new Response(JSON.stringify({ valid: true, allowed: true, address: A, site_id: 's1', expires_at: iso(Date.now() + 3600e3), assets_held: ['GOODTOKEN'], ...(res ? { resource: res, access: { mode: 'registered_keys', allowed: true, reason: 'ok', resource: res } } : {}) }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
}
const asObj = (c) => (c && typeof c === 'object' && !Array.isArray(c) ? c : { resource: c });
const legit = (req) => strictIdentity(req) || validResourceRequest(req, SV.normalizePath); // a request that may allow

test(`identity-flag fuzz: ${C.length} corpus values through every decision export and guard`, async () => {
  const findings = [], st = { corpus: C.length, calls: 0, legit_allowed: 0 };
  const chk = async (name, req, fn, mayAllow) => { st.calls++; const o = await out(fn); if (o.e === 'TIMEOUT') findings.push(`${name}: TIMEOUT`); else if (!o.e && allowShaped(o.v)) { if (mayAllow) st.legit_allowed++; else findings.push(`${name}: ALLOWED for ${JSON.stringify(req).slice(0, 120)}`); } };
  for (const c of C) {
    for (const req of [asObj(c), { resource: c }]) {
      const ok = legit(req);
      for (const [pn, p] of Object.entries(POLICIES)) await chk(`self-verify.evaluate (${pn})`, req, () => SV.evaluate(p, { address: A, held: ['GOODTOKEN'], now: Date.parse(p.issued_at) + 60e3, ...req }), ok);
      for (const [pn, p] of Object.entries(LIVE)) {
        const pass = SV.issuePass({ sub: A, h: ['GOODTOKEN'], k: p.mode === 'registered_keys' ? 'k1' : null, n: 'n', s: 's', i: T - 1000, e: T + 3600e3 }, SECRET);
        await chk(`self-verify.verifyLocalPass (${pn})`, req, () => SV.verifyLocalPass(pass, { passSecret: SECRET, policy: SV.localPolicy(p), ...req }), ok);
      }
      for (const m of ['index', 'next', 'express']) {
        const calls = []; const o = { secretKey: SK, fetch: permissiveFetch(calls), cache: false };
        await chk(`${m}.verifyPass`, req, () => MOD[m].verifyPass(PASS, { ...o, ...req }), false === true || strictIdentity(req));
        await chk(`${m}.getPass`, req, () => MOD[m].getPass({ headers: { cookie: 'tokenlock_pass=' + PASS } }, { ...o, ...req }), strictIdentity(req));
      }
    }
    // c as the request argument (client APIs whose argument IS the request: { identityOnly: true } or { path, method })
    const argOk = strictIdentity(asObj(c)) && c && !Array.isArray(c) && typeof c === 'object';
    const argRes = c && typeof c === 'object' && !Array.isArray(c) && validResourceRequest({ resource: c }, SV.normalizePath);
    for (const m of ['index', 'next', 'express']) {
      const calls = []; const o = { secretKey: SK, fetch: permissiveFetch(calls), cache: false };
      await chk(`${m}.authorize`, c, () => MOD[m].authorize({ headers: { cookie: 'tokenlock_pass=' + PASS } }, c, o), argRes);
      await chk(`${m}.TokenlockClient#verifyPass`, c, () => new MOD[m].TokenlockClient(o).verifyPass(PASS, c), argOk || argRes);
      await chk(`${m}.validateResource`, c, () => { const r = MOD[m].validateResource(c); return r === null ? { allowed: true } : { allowed: true }; }, argOk || argRes);
      await chk(`${m}.authorizeResource`, c, () => { const r = MOD[m].authorizeResource(c); return r === 'bad_path' ? { allowed: false } : { allowed: true }; }, argRes);
    }
    const f0 = globalThis.fetch; const calls = []; globalThis.fetch = permissiveFetch(calls);
    try { await chk('cf.verify', c, () => MOD.cf.verify(PASS, { TOKENLOCK_SECRET_KEY: SK, TOKENLOCK_SITE_KEY: 'pk_x' }, c), argOk || argRes); } finally { globalThis.fetch = f0; }
    await chk('cf.strictCheck', c, () => MOD.cf.strictCheck({ valid: true, allowed: true, address: A, site_id: 's1', expires_at: iso(Date.now() + 3600e3) }, c), argOk);
  }
  console.log(JSON.stringify({ ...st, findings: findings.length }));
  if (process.env.FUZZ_REPORT) writeFileSync(process.env.FUZZ_REPORT, JSON.stringify({ stats: st, findings }, null, 1));
  assert.deepEqual(findings, []);
});
test('identity-flag fuzz: every function export, corpus value in each of the first 3 argument positions', async () => {
  const DECISION = new Set(['evaluate', 'verifyLocalPass', 'verifyPass', 'getPass', 'authorize', 'validateResource', 'authorizeResource', 'verify', 'strictCheck', 'verifySignIn']);
  const findings = [], review = [], st = { functions: 0, calls: 0 };
  for (const [mn, m] of Object.entries(MOD)) for (const [fn, f] of Object.entries(m)) {
    if (typeof f !== 'function' || /^[A-Z]/.test(fn)) continue; // classes / components covered above or not decision code
    st.functions++;
    for (const c of C.slice(0, 120)) for (let pos = 0; pos < 3; pos++) {
      const args = [undefined, undefined, undefined]; args[pos] = c; st.calls++;
      const o = await out(() => f(...args));
      if (!o.e && allowShaped(o.v)) (DECISION.has(fn) ? findings : review).push(`${mn}.${fn} arg${pos} ${JSON.stringify(c).slice(0, 80)}`);
    }
  }
  console.log(JSON.stringify({ ...st, decision_findings: findings.length, other_allow_shaped: review.length, other_examples: [...new Set(review.map((r) => r.split(' ')[0]))] }));
  assert.deepEqual(findings, []);
});
