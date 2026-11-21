// Property-based authorization tests (AUTHORIZATION-CONTRACT.md §8). No dependencies. Deterministic: mulberry32 PRNG with
// fixed seeds; the same algorithm is ported to PHP (php/test/lib/prop-gen.php) and copied into the hosted repo, and each
// platform prints a digest of the generated cases so identical inputs can be confirmed.
// Properties, for every generated base (key, state, held) and every request in a fixed universe of 64 requests:
//   P1 removal:    deleting required authorization information never allows a request the base denied.
//   P2 corruption: replacing an authorization field with a wrong-typed / malformed value never allows more.
//   P3 narrowing:  narrowing the grant (fewer routes/methods/environments, asset restriction, revoked asset, earlier
//                  expiry, non-active status, suspended organization, require_org) never allows more.
// decide(input) must return { allowed, reason } for input = { state, key, address, held, request, now }.
import { createHash } from 'node:crypto';

export const SEEDS = [4572833, 4572834];
export const BASES_PER_SEED = 150;
export const NOW = '2026-11-19T12:00:00.000Z';
export const ADDR = 'bc1qpropertykey00000000000000000000000000000';
export function mulberry32(seed) {
  let a = seed >>> 0;
  return () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const ROUTE_POOL = ['*', '/*', '/api/*', '/api/x', '/api/', '/admin/*', '/admin', '/'];
const METHOD_POOL = ['*', 'GET', 'POST', 'DELETE'];
const PATHS = ['/', '/api', '/api/x', '/api/x/y', '/admin', '/admin/users', '/other'];
const METHODS = ['GET', 'POST', 'DELETE'];
const ENVS = [null, 'production', 'staging'];
export const REQUESTS = (() => {
  const out = [];
  for (const p of PATHS) for (const m of METHODS) for (const e of ENVS) out.push({ resource: e === null ? { path: p, method: m } : { path: p, method: m, environment: e } });
  out.push({ identityOnly: true });
  return out;
})();
const clone = (x) => JSON.parse(JSON.stringify(x));
export function genBase(rnd) {
  const int = (n) => Math.floor(rnd() * n);
  const subset = (arr) => arr.filter(() => rnd() < 0.5);
  const routes = subset(ROUTE_POOL), methods = subset(METHOD_POOL);
  const ec = int(4);
  const environments = ec === 0 ? ['*'] : ec === 1 ? [] : ec === 2 ? subset(['production', 'staging']) : ['production'];
  const assets = int(3) === 0 ? ['GOODTOKEN'] : [];
  const org_id = int(2) === 0 ? null : 'org_ok';
  const ex = int(5);
  const expires_at = ex === 0 ? '2026-11-19T13:00:00.000Z' : ex === 1 ? '2026-11-19T11:00:00.000Z' : null; // 1 = already expired
  const held = int(5) === 0 ? ['GOODTOKEN', 'OTHERTOKEN'] : ['GOODTOKEN'];
  const status = int(6) === 0 ? 'revoked' : 'active';
  return {
    state: { settings: { require_org: false }, orgs: [{ id: 'org_ok', status: 'approved' }, { id: 'org_sus', status: 'suspended' }], revoked_assets: ['REVOKEDTOKEN'] },
    key: { id: 'key_property01', address: ADDR, status, owner_type: 'agent', org_id, assets, expires_at, permissions: { routes, methods, environments } },
    address: ADDR, held,
  };
}
const ABSENT = '__absent__';
function setPath(obj, path, val) {
  const o = clone(obj); let cur = o;
  for (let i = 0; i < path.length - 1; i++) { if (cur[path[i]] === null || typeof cur[path[i]] !== 'object') return null; cur = cur[path[i]]; }
  if (val === ABSENT) delete cur[path.at(-1)]; else cur[path.at(-1)] = val;
  return o;
}
/** Every mutation of a base: [category, label, mutatedCase]. Deterministic order. */
export function mutations(base) {
  const out = [];
  const add = (cat, label, c) => { if (c) out.push([cat, label, c]); };
  const K = (path, val) => { const k = setPath(base.key, path, val); return k && { ...clone(base), key: k }; };
  // P1 removal of required information
  for (const p of [['permissions'], ['permissions', 'routes'], ['permissions', 'methods'], ['permissions', 'environments'], ['status'], ['id'], ['address']]) add('removal', 'delete key.' + p.join('.'), K(p, ABSENT));
  // P2 corruption (wrong type or malformed; valid values like [] / null are not corruption)
  const LIST_BAD = [null, '', 0, 5, true, {}, 'x', '*', [5], [null], [true], [{}], [['*']]];
  for (const f of ['routes', 'methods', 'environments']) LIST_BAD.forEach((v, i) => add('corruption', `key.permissions.${f} = ${JSON.stringify(v)}`, K(['permissions', f], v)));
  [null, '', 0, true, 'all', [], [{}], ['*']].forEach((v) => add('corruption', `key.permissions = ${JSON.stringify(v)}`, K(['permissions'], v)));
  [null, '', 0, 'ACTIVE', 'active ', true, 'approved'].forEach((v) => add('corruption', `key.status = ${JSON.stringify(v)}`, K(['status'], v)));
  ['garbage', 5, 99999, 1e15, true, {}, [], '2999'].forEach((v) => add('corruption', `key.expires_at = ${JSON.stringify(v)}`, K(['expires_at'], v)));
  ['GOODTOKEN', 5, true, {}, [5], [null]].forEach((v) => add('corruption', `key.assets = ${JSON.stringify(v)}`, K(['assets'], v)));
  [5, true, {}, [], ['org_ok']].forEach((v) => add('corruption', `key.org_id = ${JSON.stringify(v)}`, K(['org_id'], v)));
  [null, 'GOODTOKEN', [5], [null], {}].forEach((v) => add('corruption', `held = ${JSON.stringify(v)}`, { ...clone(base), held: v }));
  // P3 narrowing
  const pm = base.key.permissions;
  pm.routes.forEach((r, i) => add('narrowing', `remove route ${r}`, K(['permissions', 'routes'], pm.routes.filter((_, j) => j !== i))));
  pm.methods.forEach((m, i) => add('narrowing', `remove method ${m}`, K(['permissions', 'methods'], pm.methods.filter((_, j) => j !== i))));
  pm.routes.forEach((r, i) => { if (r === '*' || r === '/*') add('narrowing', `replace route ${r} with /api/*`, K(['permissions', 'routes'], pm.routes.map((x, j) => (j === i ? '/api/*' : x)))); });
  pm.methods.forEach((m, i) => { if (m === '*') add('narrowing', 'replace method * with GET', K(['permissions', 'methods'], pm.methods.map((x, j) => (j === i ? 'GET' : x)))); });
  const envs = pm.environments;
  // contract 1.1 (RC3): [] grants no environment, so [] -> ["production"] is a broadening, not a narrowing; any list -> [] narrows.
  if (envs.includes('*')) add('narrowing', `environments ${JSON.stringify(envs)} -> ["production"]`, K(['permissions', 'environments'], ['production']));
  if (envs.length) add('narrowing', `environments ${JSON.stringify(envs)} -> []`, K(['permissions', 'environments'], []));
  if (envs.filter((e) => e !== '*').length >= 2) envs.forEach((e, i) => add('narrowing', `remove environment ${e}`, K(['permissions', 'environments'], envs.filter((_, j) => j !== i))));
  if (!base.key.assets.length) { add('narrowing', 'key.assets [] -> ["GOODTOKEN"]', K(['assets'], ['GOODTOKEN'])); add('narrowing', 'key.assets [] -> ["OTHERTOKEN"]', K(['assets'], ['OTHERTOKEN'])); }
  add('narrowing', 'revoke GOODTOKEN site-wide', { ...clone(base), state: { ...clone(base.state), revoked_assets: ['REVOKEDTOKEN', 'GOODTOKEN'] } });
  add('narrowing', 'expires_at -> past', K(['expires_at'], '2026-11-19T11:00:00.000Z'));
  if (base.key.expires_at === null) add('narrowing', 'expires_at null -> later today', K(['expires_at'], '2026-11-19T12:30:00.000Z'));
  for (const s of ['revoked', 'pending_approval']) add('narrowing', `status -> ${s}`, K(['status'], s));
  add('narrowing', 'org_id -> suspended org', K(['org_id'], 'org_sus'));
  if (base.key.org_id === null) add('narrowing', 'require_org on', { ...clone(base), state: { ...clone(base.state), settings: { require_org: true } } });
  return out;
}
/** Runs P1–P3 with `decide`. Returns stats + up to 20 violations + digests (inputs; base decisions as allow bits). */
export function runProperties(decide, { seeds = SEEDS, basesPerSeed = BASES_PER_SEED } = {}) {
  const st = { seeds, bases_per_seed: basesPerSeed, requests: REQUESTS.length, bases: 0, mutations: 0, evaluations: 0, base_allowed: 0, by_category: {}, violations_total: 0, violations_by_mutation: {}, violations: [] };
  const hIn = createHash('sha256'), hOut = createHash('sha256');
  for (const seed of seeds) {
    const rnd = mulberry32(seed);
    for (let b = 0; b < basesPerSeed; b++) {
      const base = genBase(rnd); st.bases++;
      hIn.update(JSON.stringify(base));
      const allowedBase = REQUESTS.map((request) => decide({ ...base, request, now: NOW }).allowed === true);
      st.evaluations += REQUESTS.length; st.base_allowed += allowedBase.filter(Boolean).length;
      hOut.update(allowedBase.map((x) => (x ? '1' : '0')).join(''));
      for (const [cat, label, c] of mutations(base)) {
        st.mutations++; const s = (st.by_category[cat] ||= { mutations: 0, evaluations: 0, violations: 0 }); s.mutations++;
        hIn.update(cat + label);
        REQUESTS.forEach((request, i) => {
          s.evaluations++; st.evaluations++;
          let d; try { d = decide({ ...c, request, now: NOW }); } catch (e) { d = { allowed: false, reason: 'threw:' + (e?.message || e) }; }
          if (d.allowed === true && !allowedBase[i]) { s.violations++; st.violations_total++; st.violations_by_mutation[label] = (st.violations_by_mutation[label] || 0) + 1; if (st.violations.length < 20) st.violations.push({ seed, base: b, category: cat, mutation: label, request, reason: d.reason, base_key: base.key }); }
        });
      }
    }
  }
  st.input_digest = hIn.digest('hex'); st.base_decision_digest = hOut.digest('hex');
  return st;
}
