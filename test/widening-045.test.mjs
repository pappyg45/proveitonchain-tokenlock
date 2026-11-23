// Widening test (RC3 review): environments [] -> ["production"] is a WIDENING under contract 1.1 (§3: [] grants
// no environment; §5), so it is tested here rather than in P3 narrowing. It checks that the newly granted production
// access works, and only in production:
//   W1 explicit example; W2 every generator base with environments [] (test/vectors/prop-gen.mjs, same seeds):
//   base [] denies every resource request; widened ["production"] decides every production request exactly as the same
//   key with ["*"] (so other restrictions still apply), denies staging and an omitted environment, and leaves
//   identity-only checks unchanged. Non-vacuous: at least one newly allowed production request.
import test from 'node:test';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { mulberry32, genBase, REQUESTS, NOW, SEEDS, BASES_PER_SEED } from './vectors/prop-gen.mjs';

const ROOT = process.env.TL_PKG_ROOT ? pathToFileURL(process.env.TL_PKG_ROOT.replace(/\/?$/, '/')) : new URL('../', import.meta.url);
const SV = await import(new URL('dist/self-verify.js', ROOT));
const ms = (iso) => Date.parse(iso);
function decide(x, request) {
  const now = ms(NOW);
  const policy = { v: 1, typ: 'tokenlock.policy', site_id: 'site_vectors', seq: 1, issued_at: new Date(now - 60e3).toISOString(), expires_at: new Date(now + 3600e3).toISOString(),
    mode: 'registered_keys', settings: x.state.settings, orgs: x.state.orgs, revoked_assets: x.state.revoked_assets, keys: [x.key] };
  const r = SV.evaluate(policy, { address: x.address, held: x.held, ...request, now });
  return { allowed: r.allowed === true, reason: r.reason };
}
const withEnv = (b, e) => { const c = JSON.parse(JSON.stringify(b)); c.key.permissions.environments = e; return c; };
const res = (path, method, environment) => ({ resource: environment === undefined ? { path, method } : { path, method, environment } });

test('W1 widening [] -> ["production"]: production now allowed; staging and omitted environment still denied; other grants still apply', () => {
  const base = { state: { settings: { require_org: false }, orgs: [], revoked_assets: [] }, address: 'bc1qwideningkey0000000000000000000000000000', held: ['GOODTOKEN'],
    key: { id: 'key_widening01', address: 'bc1qwideningkey0000000000000000000000000000', status: 'active', owner_type: 'agent', org_id: null, assets: [], expires_at: null, permissions: { routes: ['/api/*'], methods: ['GET'], environments: [] } } };
  for (const e of ['production', 'staging', undefined]) assert.deepEqual(decide(base, res('/api/x', 'GET', e)), { allowed: false, reason: 'environment_not_allowed' }, `[] denies ${e}`);
  const w = withEnv(base, ['production']);
  assert.deepEqual(decide(w, res('/api/x', 'GET', 'production')), { allowed: true, reason: 'ok' });
  assert.deepEqual(decide(w, res('/api/x', 'GET', 'staging')), { allowed: false, reason: 'environment_not_allowed' });
  assert.deepEqual(decide(w, res('/api/x', 'GET')), { allowed: false, reason: 'environment_not_allowed' });
  assert.equal(decide(w, res('/other', 'GET', 'production')).allowed, false, 'route still restricted');
  assert.equal(decide(w, res('/api/x', 'POST', 'production')).allowed, false, 'method still restricted');
});

test('W2 widening [] -> ["production"] over every generator base with environments []', () => {
  const st = { bases: 0, empty_env_bases: 0, evaluations: 0, newly_allowed_production: 0, failures: [] };
  const fail = (f) => { if (st.failures.length < 10) st.failures.push(f); st.failures_total = (st.failures_total || 0) + 1; };
  for (const seed of SEEDS) { const rnd = mulberry32(seed); for (let b = 0; b < BASES_PER_SEED; b++) {
    const base = genBase(rnd); st.bases++;
    if (base.key.permissions.environments.length !== 0) continue;
    st.empty_env_bases++;
    const w = withEnv(base, ['production']), star = withEnv(base, ['*']);
    for (const request of REQUESTS) {
      st.evaluations++;
      const d0 = decide(base, request), dw = decide(w, request);
      if (request.identityOnly) { if (dw.allowed !== d0.allowed) fail({ seed, b, request, w: dw, base: d0, rule: 'identity-only unchanged' }); continue; }
      if (d0.allowed) fail({ seed, b, request, base: d0, rule: '[] grants nothing' });
      const env = request.resource.environment;
      if (env === 'production') { const ds = decide(star, request); if (dw.allowed !== ds.allowed) fail({ seed, b, request, w: dw, star: ds, rule: 'production decided as with ["*"]' }); if (dw.allowed) st.newly_allowed_production++; }
      else if (dw.allowed) fail({ seed, b, request, w: dw, rule: 'not production -> deny' });
    }
  } }
  console.log(JSON.stringify(st));
  assert.deepEqual(st.failures, [], JSON.stringify(st.failures));
  assert.ok(st.empty_env_bases > 0 && st.newly_allowed_production > 0, 'non-vacuous');
});
