// RC4 (review): identity-only is selected ONLY by the top-level identityOnly: true with no resource (contract §2
// step 1). RC3 evaluate() took { resource: { identityOnly: true } } as an identity-only check (validateResource returns
// null for that form, and evaluate() went on as identity-only), so an active key with empty grants was allowed.
//   S1 the review's reproduction (token-mode and registered-key policies)
//   S2 every identity-flag variant x { token-mode, registered key with empty grants, registered key with normal grants }
//   S3 verifyLocalPass, S4 the Cloudflare worker (verify, strictCheck), S5 hosted-client exports (permissive fake API)
//   P-ID property: every request that is not exactly { identityOnly: true } and is not a valid { resource } is denied
//   (exhaustive over top-level key sets of size <= 2 and a value pool, x 3 fixed policies + 300 generator bases).
import test from 'node:test';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { mulberry32, genBase, SEEDS, BASES_PER_SEED } from './vectors/prop-gen.mjs';

const ROOT = process.env.TL_PKG_ROOT ? pathToFileURL(process.env.TL_PKG_ROOT.replace(/\/?$/, '/')) : new URL('../', import.meta.url);
const SV = await import(new URL('dist/self-verify.js', ROOT));
const IX = await import(new URL('dist/index.js', ROOT));
const CF = await import(new URL('examples/cloudflare-worker/worker.js', ROOT));
import { NOW, iso, A, pol, POLICIES, VARIANTS, requests, strictIdentity, validResourceRequest } from './vectors/identity-cases.mjs';
const ev = (p, req) => SV.evaluate(p, { address: A, held: ['GOODTOKEN'], now: NOW, ...req });

test('S1 review: evaluate({ resource: { identityOnly: true } }) is denied (bad_resource) for token-mode and registered-key policies', () => {
  for (const [name, p] of Object.entries(POLICIES)) assert.deepEqual({ ...ev(p, { resource: { identityOnly: true } }), key: undefined }, { allowed: false, reason: 'bad_resource', key: undefined }, name);
});
test('S2 every identity-flag variant is denied (bad_resource) on every policy; top-level identityOnly: true still works', () => {
  const fails = [];
  for (const [pn, p] of Object.entries(POLICIES)) {
    for (const [vn, req] of VARIANTS) { const r = ev(p, req); if (r.allowed !== false || r.reason !== 'bad_resource') fails.push(`${pn} / ${vn}: ${JSON.stringify({ allowed: r.allowed, reason: r.reason })}`); }
    const c = ev(p, { identityOnly: true }); if (c.allowed !== true) fails.push(`${pn} / control identityOnly: ${c.reason}`);
  }
  const res = { resource: { path: '/api/x', method: 'GET' } };
  assert.equal(ev(POLICIES['token mode'], res).reason, 'policy_required');
  assert.equal(ev(POLICIES['registered, empty grants'], res).allowed, false);
  assert.equal(ev(POLICIES['registered, normal grants'], res).allowed, true);
  assert.deepEqual(fails, []);
});
test('S3 verifyLocalPass refuses every variant (token-mode and registered); top-level identityOnly: true still works', async () => {
  const SECRET = 's'.repeat(40);
  const fails = [];
  const T = Date.now(); // localPolicy().get() checks the policy window against the real clock
  for (const [pn, p0] of Object.entries(POLICIES)) {
    const p = { ...p0, issued_at: iso(T - 60e3), expires_at: iso(T + 3600e3) };
    const pass = SV.issuePass({ sub: A, h: ['GOODTOKEN'], k: p.mode === 'registered_keys' ? 'k1' : null, n: 'n', s: 's', i: T - 1000, e: T + 3600e3 }, SECRET);
    for (const [vn, req] of VARIANTS) { const r = await SV.verifyLocalPass(pass, { passSecret: SECRET, policy: SV.localPolicy(p), ...req }); if (r.valid || r.allowed) fails.push(`${pn} / ${vn}: ${JSON.stringify(r).slice(0, 120)}`); }
    const c = await SV.verifyLocalPass(pass, { passSecret: SECRET, policy: SV.localPolicy(p), identityOnly: true }); if (!c.valid) fails.push(`${pn} / control: ${c.code}`);
  }
  assert.deepEqual(fails, []);
});
// A permissive fake API answers valid + allowed to anything sent, so a request that is sent instead of refused shows up.
function permissiveFetch(calls) {
  return async (url, init = {}) => {
    const b = JSON.parse(init.body || '{}'); calls.push(b);
    const res = b.identity_only ? undefined : { path: typeof b.path === 'string' ? b.path.toLowerCase() : b.path ?? null, method: b.method ?? null, environment: b.environment ?? null };
    return new Response(JSON.stringify({ valid: true, allowed: true, address: A, site_id: 's1', expires_at: iso(Date.now() + 3600e3), assets_held: ['GOODTOKEN'], ...(res ? { resource: res, access: { mode: 'registered_keys', allowed: true, reason: 'ok', resource: res } } : {}) }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
}
const allowShaped = (v) => !!v && typeof v === 'object' && (v.valid === true || v.allowed === true || v.ok === true);
async function refused(fn) { try { return !allowShaped(await fn()); } catch { return true; } }
test('S4 Cloudflare worker: verify() and strictCheck() refuse every variant as the request; { identityOnly: true } still works', async () => {
  const SK = 'sk_' + 'f'.repeat(40), PASS = 'pp1.' + 'A'.repeat(40) + '.' + 'B'.repeat(43);
  const calls = [], f0 = globalThis.fetch; globalThis.fetch = permissiveFetch(calls);
  const fails = [];
  try {
    for (const [vn, req] of VARIANTS) {
      const before = calls.length;
      if (!(await refused(() => CF.verify(PASS, { TOKENLOCK_SECRET_KEY: SK, TOKENLOCK_SITE_KEY: 'pk_x' }, req)))) fails.push(`verify / ${vn}`);
      if (calls.length !== before) fails.push(`verify / ${vn}: request sent`);
      const ans = { valid: true, allowed: true, address: A, site_id: 's1', expires_at: iso(Date.now() + 3600e3) };
      if (!(await refused(() => CF.strictCheck(ans, req)))) fails.push(`strictCheck / ${vn}`);
    }
    const c = await CF.verify(PASS, { TOKENLOCK_SECRET_KEY: SK, TOKENLOCK_SITE_KEY: 'pk_x' }, { identityOnly: true }); if (!c.ok) fails.push('control verify identityOnly: ' + c.code);
  } finally { globalThis.fetch = f0; }
  assert.deepEqual(fails, []);
});
test('S5 hosted-client exports (verifyPass, getPass, authorize, TokenlockClient#verifyPass) refuse every variant before any request', async () => {
  const SK = 'sk_' + 'f'.repeat(40), PASS = 'pp1.' + 'A'.repeat(40) + '.' + 'B'.repeat(43);
  const req = { headers: { cookie: 'tokenlock_pass=' + PASS } };
  const fails = [];
  for (const [vn, v] of VARIANTS) {
    const calls = []; const o = { secretKey: SK, fetch: permissiveFetch(calls), cache: false };
    if (!(await refused(() => IX.verifyPass(PASS, { ...o, ...v })))) fails.push(`verifyPass / ${vn}`);
    if (!(await refused(() => IX.getPass(req, { ...o, ...v })))) fails.push(`getPass / ${vn}`);
    if (!(await refused(() => IX.authorize(req, v, o)))) fails.push(`authorize / ${vn}`);
    if (!(await refused(() => new IX.TokenlockClient(o).verifyPass(PASS, v)))) fails.push(`TokenlockClient#verifyPass / ${vn}`);
    if (calls.length) fails.push(`${vn}: ${calls.length} request(s) sent`);
  }
  assert.deepEqual(fails, []);
});

test('P-ID property: a request that is neither exactly { identityOnly: true } nor a valid { resource } is always denied', () => {
  const REQ = requests();
  const bases = Object.values(POLICIES).map((p) => ({ p, held: ['GOODTOKEN'], address: A }));
  for (const seed of SEEDS) { const rnd = mulberry32(seed); for (let b = 0; b < BASES_PER_SEED; b++) { const x = genBase(rnd); bases.push({ p: pol({ mode: 'registered_keys', settings: x.state.settings, orgs: x.state.orgs, revoked_assets: x.state.revoked_assets, keys: [x.key] }), held: x.held, address: x.address }); } }
  const st = { requests: REQ.length, bases: bases.length, evaluations: 0, malformed: 0, strict_identity_allowed: 0, violations: 0, examples: [] };
  for (const r of REQ) {
    const malformed = !strictIdentity(r) && !validResourceRequest(r, SV.normalizePath);
    if (malformed) st.malformed++;
    for (const B of bases) {
      st.evaluations++;
      const d = SV.evaluate(B.p, { address: B.address, held: B.held, now: NOW, ...r });
      if (malformed && d.allowed !== false) { st.violations++; if (st.examples.length < 8) st.examples.push({ request: r, reason: d.reason }); }
      if (strictIdentity(r) && d.allowed) st.strict_identity_allowed++;
    }
  }
  console.log(JSON.stringify(st));
  assert.equal(st.violations, 0, JSON.stringify(st.examples));
  assert.ok(st.malformed > 0 && st.strict_identity_allowed > 0, 'non-vacuous');
});
