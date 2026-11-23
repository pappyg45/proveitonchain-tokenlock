// AUTHORIZATION-CONTRACT.md v1: the shared test vectors (docs/authorization-vectors-v1.json) and the property-based
// monotonicity tests (test/vectors/prop-gen.mjs), run against Node self-verify evaluate() and the Cloudflare worker's
// strictCheck(). PHP: php/test/authz-contract.php. Hosted: the site repo's tests/tokenlock-authz-contract.test.mjs.
// TL_PKG_ROOT=<package root> runs against an installed package (the vectors are read from that package's docs/).
// TL_VECTORS=<file> overrides the vector file (used to run v1 vectors against older packages that do not ship it).
// AUTHZ_RESULTS=<dir> writes per-vector decisions and property statistics as JSON for the equivalence matrix.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { runProperties } from './vectors/prop-gen.mjs';

const ROOT = process.env.TL_PKG_ROOT ? pathToFileURL(process.env.TL_PKG_ROOT.replace(/\/?$/, '/')) : new URL('../', import.meta.url);
const SV = await import(new URL('dist/self-verify.js', ROOT));
const CF = await import(new URL('examples/cloudflare-worker/worker.js', ROOT));
const VERSION = JSON.parse(readFileSync(new URL('package.json', ROOT), 'utf8')).version;
const vfile = process.env.TL_VECTORS || (existsSync(fileURLToPath(new URL('docs/authorization-vectors-v1.json', ROOT))) ? fileURLToPath(new URL('docs/authorization-vectors-v1.json', ROOT)) : fileURLToPath(new URL('../docs/authorization-vectors-v1.json', import.meta.url)));
const V = JSON.parse(readFileSync(vfile, 'utf8'));
const OUT = process.env.AUTHZ_RESULTS;
const save = (name, data) => { if (OUT) { mkdirSync(OUT, { recursive: true }); writeFileSync(`${OUT}/${name}.json`, JSON.stringify(data, null, 1)); } };
const ms = (iso) => Date.parse(iso);

export function nodeDecide(x) {
  const now = ms(x.now);
  const policy = { v: 1, typ: 'tokenlock.policy', site_id: 'site_vectors', seq: 1, issued_at: new Date(now - 60e3).toISOString(), expires_at: new Date(now + 3600e3).toISOString(),
    mode: x.policy_mode === 'token' ? 'token' : 'registered_keys', settings: x.state.settings, orgs: x.state.orgs, revoked_assets: x.state.revoked_assets, keys: x.key === undefined ? [] : [x.key] };
  const r = SV.evaluate(policy, { address: x.address, held: x.held, ...x.request, now });
  return { allowed: r.allowed === true, reason: r.reason };
}
const want = (vec, platform) => vec.expect.platform_reason?.[platform] ?? vec.expect.reason;

test(`contract v${V.contract_version}: ${V.vectors.length} vectors, Node self-verify ${VERSION}`, () => {
  const results = {}, fails = [];
  for (const vec of V.vectors) {
    const d = nodeDecide({ ...vec, now: V.now });
    results[vec.id] = d;
    if (d.allowed !== vec.expect.allowed || d.reason !== want(vec, 'node')) fails.push(`${vec.id} ${vec.title}: got ${JSON.stringify(d)}, want ${JSON.stringify({ allowed: vec.expect.allowed, reason: want(vec, 'node') })}`);
  }
  save('node-selfverify', { platform: 'node-selfverify', version: VERSION, vectors_sha256: null, results });
  assert.deepEqual(fails, [], fails.join('\n'));
});

// The worker does not evaluate permissions: it enforces the hosted answer. For each vector, the answer the hosted API gives
// for the expected decision must come out of strictCheck() with the same allow/deny; and a tampered answer (wrong
// environment / path / method echoed, allowed without access, allowed with a denied reason) must never be accepted.
function hostedAnswer(vec, decision) {
  const res = vec.request.resource;
  const echo = res && typeof res.path === 'string' ? { path: res.path, method: String(res.method).toUpperCase(), environment: res.environment ?? null } : null;
  const base = { address: vec.address, site_id: 'site_vectors', assets_held: vec.held, expires_at: new Date(Date.now() + 3600e3).toISOString() };
  const access = { mode: 'registered_keys', allowed: decision.allowed, reason: decision.reason, ...(echo ? { resource: echo } : {}) };
  // contract 1.2.0 (token mode): hosted answers an allowed identity check without an access block, and a denial with
  // access.mode "token" (0.5.0 verifyPass / checkPass).
  if (vec.policy_mode === 'token') {
    if (!decision.allowed) return { valid: false, allowed: false, code: decision.reason, ...base, access: { ...access, mode: 'token' }, ...(echo ? { resource: echo } : {}) };
    return { valid: true, ...base };
  }
  if (!decision.allowed) return { valid: false, allowed: false, code: decision.reason, ...base, access, ...(echo ? { resource: echo } : {}) };
  return { valid: true, ...(echo ? { allowed: true } : {}), ...base, access, ...(echo ? { resource: echo } : {}) };
}
const workerResource = (req) => (req.identityOnly === true && req.resource === undefined ? null : req.resource ? { ...req.resource, ...(typeof req.resource.path === 'string' ? { path: req.resource.path.toLowerCase() } : {}), ...(typeof req.resource.method === 'string' ? { method: req.resource.method.toUpperCase() } : {}) } : req);
test(`contract v${V.contract_version}: Cloudflare worker strictCheck enforces the hosted decision for every vector`, () => {
  const results = {}, fails = [];
  for (const vec of V.vectors) {
    const r = CF.strictCheck(hostedAnswer(vec, vec.expect), workerResource(vec.request));
    results[vec.id] = { allowed: r.ok === true, reason: r.ok ? 'ok' : r.code };
    if (results[vec.id].allowed !== vec.expect.allowed) fails.push(`${vec.id}: worker ${JSON.stringify(results[vec.id])} vs expected ${JSON.stringify(vec.expect)}`);
    if (vec.expect.allowed && vec.request.resource) {
      const good = hostedAnswer(vec, vec.expect);
      const tamper = {
        'echo environment changed': (a) => { a.resource = { ...a.resource, environment: 'tampered' }; a.access.resource = a.resource; },
        'echo environment dropped from a restricted request': (a) => { if (vec.request.resource.environment) { a.resource = { ...a.resource, environment: null }; a.access.resource = a.resource; } else a.resource = { ...a.resource, environment: 'production' }; },
        'echo path changed': (a) => { a.resource = { ...a.resource, path: '/elsewhere' }; a.access.resource = a.resource; },
        'echo method changed': (a) => { a.resource = { ...a.resource, method: 'PATCH' }; a.access.resource = a.resource; },
        'no access block': (a) => { delete a.access; },
        'access denied but valid': (a) => { a.access.allowed = false; a.access.reason = 'route_not_allowed'; },
        'allowed missing': (a) => { delete a.allowed; },
      };
      for (const [name, f] of Object.entries(tamper)) { const a = structuredClone(good); f(a); const t = CF.strictCheck(a, workerResource(vec.request)); if (t.ok) fails.push(`${vec.id}: tampered answer accepted (${name})`); }
    }
  }
  save('cf-worker', { platform: 'cf-worker', version: VERSION, input: 'hosted answer for the expected decision', results });
  assert.deepEqual(fails, [], fails.join('\n'));
});

test('properties P1 removal, P2 corruption, P3 narrowing never allow more (Node self-verify)', () => {
  const st = runProperties(nodeDecide);
  save('properties-node-selfverify', { platform: 'node-selfverify', version: VERSION, ...st });
  assert.equal(st.violations_total, 0, `${st.violations_total} violations, e.g.\n` + st.violations.slice(0, 8).map((x) => JSON.stringify(x)).join('\n'));
  assert.ok(st.bases === 300 && st.evaluations > 1e6, 'ran the full seeded set');
});
