// Builds docs/authorization-vectors-v1.json, the normative cross-platform test vectors for AUTHORIZATION-CONTRACT.md.
// Every vector is self-contained (full key, full state, held assets, request, expected decision). A field that is
// "absent" is simply not in the JSON. Run: node test/vectors/build-vectors.mjs  (deterministic; no randomness, no clock).
import { writeFileSync } from 'node:fs';

const NOW = '2026-11-19T12:00:00.000Z';
const ADDR = 'bc1qvectorkey000000000000000000000000000000';
const OTHER = 'bc1qnotregistered0000000000000000000000000';
const baseKey = () => ({ id: 'key_vector0001', address: ADDR, status: 'active', owner_type: 'agent', org_id: null, assets: [], expires_at: null,
  permissions: { routes: ['/api/*'], methods: ['GET'], environments: ['*'] } });
const baseState = () => ({ settings: { require_org: false }, orgs: [{ id: 'org_ok', status: 'approved' }, { id: 'org_sus', status: 'suspended' }], revoked_assets: ['REVOKEDTOKEN'] });
const ABSENT = Symbol('absent');
function patch(obj, p) {
  const o = structuredClone(obj);
  for (const [k, v] of Object.entries(p)) {
    if (v === ABSENT) delete o[k];
    else if (v && typeof v === 'object' && !Array.isArray(v) && v.__merge) { const { __merge, ...rest } = v; o[k] = patch(o[k] && typeof o[k] === 'object' ? o[k] : {}, rest); }
    else o[k] = v;
  }
  return o;
}
const P = (perm) => ({ permissions: { __merge: true, ...perm } });
const GET = (path, extra = {}) => ({ resource: { path, method: 'GET', ...extra } });
const vectors = [];
// v(id, title, { key patch, state patch, held, request, address }, expect, notes)
function v(id, title, o, expect, extra = {}) {
  const key = o.keyRaw !== undefined ? o.keyRaw : patch(baseKey(), o.key || {});
  vectors.push({ id, title, state: patch(baseState(), o.state || {}), key, address: o.address || ADDR, held: o.held || ['GOODTOKEN'], request: o.request || GET('/api/reports'), expect, ...extra });
}
const ok = { allowed: true, reason: 'ok' };
const deny = (reason, alt) => ({ allowed: false, reason, ...(alt ? { platform_reason: alt } : {}) });
const HOSTED_INVALID = { hosted: 'access_data_invalid' };

// --- G: explicit grants
v('G01', 'explicit route + method grant', {}, ok);
v('G02', 'route outside the grant', { request: GET('/admin') }, deny('route_not_allowed'));
v('G03', 'method outside the grant', { request: { resource: { path: '/api/reports', method: 'DELETE' } } }, deny('method_not_allowed'));
v('G04', 'explicit "*" routes and methods', { key: P({ routes: ['*'], methods: ['*'] }), request: { resource: { path: '/private/admin', method: 'DELETE' } } }, ok);
v('G05', 'explicit "/*" route is a wildcard', { key: P({ routes: ['/*'] }), request: GET('/anything/deep') }, ok);
v('G06', 'routes [] grants nothing', { key: P({ routes: [] }) }, deny('route_not_allowed'));
v('G07', 'methods [] grants nothing', { key: P({ methods: [] }) }, deny('method_not_allowed'));
v('G08', 'prefix "/api/*" also covers "/api" itself', { request: GET('/api') }, ok);
v('G09', 'prefix "/api/*" does not cover "/apix"', { request: GET('/apix') }, deny('route_not_allowed'));
v('G10', 'trailing slash "/api/" is an exact route, not a prefix (RC2)', { key: P({ routes: ['/api/'] }), request: GET('/api/reports') }, deny('route_not_allowed'), { changed_in: '0.4.5-rc2' });
v('G11', 'trailing slash "/api/" matches "/api"', { key: P({ routes: ['/api/'] }), request: GET('/api') }, ok);
v('G12', 'paths are case-insensitive (one identity)', { request: GET('/API/Reports') }, ok);
v('G13', 'request method case is normalized', { request: { resource: { path: '/api/reports', method: 'get' } } }, ok);
v('G14', 'a lowercase method in the key never matches (no normalization of grants)', { key: P({ methods: ['get'] }) }, deny('method_not_allowed'));
v('G15', '"/api*" is not a glob', { key: P({ routes: ['/api*'] }), request: GET('/api/reports') }, deny('route_not_allowed'));
v('G16', 'exact route', { key: P({ routes: ['/api/reports'] }) }, ok);
v('G17', 'exact route does not cover children', { key: P({ routes: ['/api/reports'] }), request: GET('/api/reports/q3') }, deny('route_not_allowed'));
v('G18', 'methods ["*"] with a narrow route', { key: P({ methods: ['*'] }), request: { resource: { path: '/api/x', method: 'DELETE' } } }, ok);
v('G19', 'route "" grants nothing', { key: P({ routes: [''] }) }, deny('route_not_allowed'));
v('G20', 'route without a leading slash grants nothing', { key: P({ routes: ['api/*'] }) }, deny('route_not_allowed'));

// --- M: missing / malformed permissions (never a grant)
const M = [
  ['M01', 'no permissions field', { permissions: ABSENT }],
  ['M02', 'permissions null', { permissions: null }],
  ['M03', 'permissions {}', { permissions: {} }],
  ['M04', 'routes missing', { permissions: { methods: ['*'], environments: ['*'] } }],
  ['M05', 'methods missing', { permissions: { routes: ['/*'], environments: ['*'] } }],
  ['M06', 'environments missing (RC2)', { permissions: { routes: ['/*'], methods: ['*'] } }, '0.4.5-rc2'],
  ['M07', 'routes null', { permissions: { routes: null, methods: ['*'], environments: ['*'] } }],
  ['M08', 'methods null', { permissions: { routes: ['/*'], methods: null, environments: ['*'] } }],
  ['M09', 'environments null (RC2)', { permissions: { routes: ['/*'], methods: ['*'], environments: null } }, '0.4.5-rc2'],
  ['M10', 'routes and methods null', { permissions: { routes: null, methods: null, environments: ['*'] } }],
];
for (const [id, title, p, ch] of M) v(id, title, { key: p }, deny('policy_invalid'), ch ? { changed_in: ch } : {});
// Malformed (wrong type): self-verify refuses the whole policy (policy_invalid); hosted refuses the key (policy_invalid).
const MAL = [
  ['M11', 'routes "*" (string)', { permissions: { routes: '*', methods: ['*'], environments: ['*'] } }],
  ['M12', 'methods "GET" (string)', { permissions: { routes: ['/*'], methods: 'GET', environments: ['*'] } }],
  ['M13', 'environments "production" (string)', { permissions: { routes: ['/*'], methods: ['*'], environments: 'production' } }],
  ['M14', 'routes [5]', { permissions: { routes: [5], methods: ['*'], environments: ['*'] } }],
  ['M15', 'routes [null]', { permissions: { routes: [null], methods: ['*'], environments: ['*'] } }],
  ['M16', 'routes {} (object)', { permissions: { routes: {}, methods: ['*'], environments: ['*'] } }],
  ['M17', 'permissions [] (array)', { permissions: [] }],
  ['M18', 'permissions "all" (string)', { permissions: 'all' }],
  ['M19', 'permissions true', { permissions: true }],
  ['M20', 'environments [5]', { permissions: { routes: ['/*'], methods: ['*'], environments: [5] } }],
];
// PHP decodes JSON objects to arrays (json_decode(..., true), as for real bundles), so {} arrives as an empty list there.
for (const [id, title, p] of MAL) v(id, title, { key: p, request: { resource: { path: '/private/admin', method: 'DELETE' } } }, deny('policy_invalid', id === 'M16' ? { php: 'route_not_allowed' } : undefined));

// --- E: environments
const ENV = (envs, env, exp, title, ch) => ({ envs, env, exp, title, ch });
const E = [
  ['E01', ENV(['production'], 'production', ok, 'restricted key, matching environment')],
  ['E02', ENV(['production'], undefined, deny('environment_not_allowed'), 'restricted key, request has no environment (RC2)', '0.4.5-rc2')],
  ['E03', ENV(['production'], 'staging', deny('environment_not_allowed'), 'restricted key, other environment')],
  ['E04', ENV(['production'], 'Production', deny('environment_not_allowed'), 'environment names are case-sensitive')],
  ['E05', ENV(['*'], undefined, ok, 'explicit "*" environments, request has none')],
  ['E06', ENV(['*'], 'anything', ok, 'explicit "*" environments, any environment')],
  ['E07', ENV([], undefined, deny('environment_not_allowed'), 'environments [] grants no environment (RC3; RC2 and earlier read [] as "any")', '0.4.5-rc3')],
  ['E08', ENV([], 'staging', deny('environment_not_allowed'), 'environments [] with a request environment grants nothing (RC3)', '0.4.5-rc3')],
  ['E09', ENV(['production', '*'], 'qa', ok, '"*" inside a list')],
  ['E10', ENV(['production', 'staging'], 'staging', ok, 'second listed environment')],
  ['E11', ENV(['production', 'staging'], undefined, deny('environment_not_allowed'), 'multi-environment key, request has none (RC2)', '0.4.5-rc2')],
];
for (const [id, e] of E) v(id, e.title, { key: P({ environments: e.envs }), request: GET('/api/reports', e.env === undefined ? {} : { environment: e.env }) }, e.exp, e.ch ? { changed_in: e.ch } : {});
for (const [id, title, env] of [['E12', 'request environment "" (empty)', ''], ['E13', 'request environment null', null], ['E14', 'request environment 5', 5], ['E15', 'request environment with a space', 'prod uction'], ['E16', 'request environment 31 characters', 'p'.repeat(31)], ['E17', 'request environment padded', ' production']])
  v(id, title, { key: P({ environments: ['production'] }), request: { resource: { path: '/api/reports', method: 'GET', environment: env } } }, deny('bad_resource'));
v('E18', 'identity-only does not read environments', { key: P({ environments: ['production'] }), request: { identityOnly: true } }, ok);
v('E19', 'restricted key, request environment matches but route does not', { key: P({ environments: ['production'] }), request: GET('/admin', { environment: 'production' }) }, deny('route_not_allowed'));

// --- K: key status, expiry, organization, entitlement
v('K01', 'key revoked', { key: { status: 'revoked' } }, deny('key_revoked'));
v('K02', 'key pending approval', { key: { status: 'pending_approval' } }, deny('pending_approval'));
v('K03', 'unknown key status', { key: { status: 'disabled' } }, deny('policy_invalid', HOSTED_INVALID));
v('K04', 'key status missing', { key: { status: ABSENT } }, deny('policy_invalid', HOSTED_INVALID));
v('K05', 'key expired', { key: { expires_at: '2026-11-19T11:59:59.000Z' } }, deny('key_expired'));
v('K06', 'key expires later', { key: { expires_at: '2026-11-19T13:00:00.000Z' } }, ok);
v('K07', 'key expires_at unparseable', { key: { expires_at: 'tomorrow' } }, deny('policy_invalid', { hosted: 'key_expired' }));
v('K08', 'key organization suspended', { key: { org_id: 'org_sus' } }, deny('org_not_approved'));
v('K09', 'key organization unknown', { key: { org_id: 'org_missing' } }, deny('org_not_approved'));
v('K10', 'organization approved', { key: { org_id: 'org_ok' } }, ok);
v('K11', 'require_org, key has no organization', { state: { settings: { require_org: true } } }, deny('org_required'));
v('K12', 'key assets exclude the held token', { key: { assets: ['OTHERTOKEN'] } }, deny('entitlement_revoked'));
v('K13', 'key assets include the held token', { key: { assets: ['GOODTOKEN'] } }, ok);
v('K14', 'held token revoked site-wide', { held: ['REVOKEDTOKEN'] }, deny('entitlement_revoked'));
v('K15', 'holds nothing', { held: [] }, deny('not_holder'));
v('K16', 'wallet is not a registered key', { address: OTHER }, deny('not_registered'));
v('K17', 'key assets "GOODTOKEN" (string)', { key: { assets: 'GOODTOKEN' } }, deny('policy_invalid', HOSTED_INVALID));
v('K18', 'revoked key with wildcard grants', { key: { status: 'revoked', permissions: { routes: ['*'], methods: ['*'], environments: ['*'] } } }, deny('key_revoked'));
v('K19', 'identity-only for a key without permissions', { key: { permissions: ABSENT }, request: { identityOnly: true } }, ok);
v('K20', 'identity-only for a revoked key', { key: { status: 'revoked' }, request: { identityOnly: true } }, deny('key_revoked'));

// --- L: verification-side outcomes of the key lifecycle (contract 1.1 §6.3-6.5). Keys as the hosted API stores and
// serializes them after each transition: a recovery hold is stored and serialized as pending_approval; a reactivated
// key carries only the grants confirmed at reactivation (the historical grants are not kept as grants).
const L = { changed_in: '0.4.5-rc3' };
v('L01', 'recovery hold (serialized pending_approval) with historical wildcard grants', { key: { status: 'pending_approval', permissions: { routes: ['*'], methods: ['*'], environments: ['*'] } }, request: { resource: { path: '/private/admin', method: 'DELETE' } } }, deny('pending_approval'), L);
v('L02', 'recovery hold, identity-only', { key: { status: 'pending_approval' }, request: { identityOnly: true } }, deny('pending_approval'), L);
v('L03', 'reactivated key, request inside the newly confirmed grants', { key: P({ routes: ['/api/read'], methods: ['GET'], environments: ['production'] }), request: GET('/api/read', { environment: 'production' }) }, ok, L);
v('L04', 'reactivated key, request only the historical grant allowed', { key: P({ routes: ['/api/read'], methods: ['GET'], environments: ['production'] }), request: GET('/api/reports', { environment: 'production' }) }, deny('route_not_allowed'), L);
v('L05', 'reactivated key with a confirmed expiry already past', { key: { expires_at: '2026-11-19T11:00:00.000Z' } }, deny('key_expired'), L);

// --- F: each authorization field independently: omitted, empty, null, malformed, unknown (contract 1.1 §3, §5).
// A permissions object is closed: a field other than routes / methods / environments makes the key invalid (RC3), so a
// misspelled or newer restriction is never silently ignored. Restriction fields (assets, org_id, expires_at) absent,
// null or empty mean "no such restriction"; a malformed one is invalid. Other top-level key fields are metadata.
const F = { changed_in: '0.4.5-rc3' };
const ALL = { routes: ['/*'], methods: ['*'], environments: ['*'] };
const WIDE = { resource: { path: '/private/admin', method: 'DELETE' } };
v('F01', 'unknown permission field beside full grants', { key: { permissions: { ...ALL, deny_routes: ['/private/*'] } }, request: WIDE }, deny('policy_invalid'), F);
v('F02', 'misspelled permission field ("route") beside routes', { key: { permissions: { ...ALL, route: ['/api/*'] } }, request: WIDE }, deny('policy_invalid'), F);
v('F03', 'unknown permission field with null value', { key: { permissions: { ...ALL, max_requests: null } }, request: WIDE }, deny('policy_invalid'), F);
v('F04', 'unknown permission field, otherwise narrow grants', { key: P({ scope: 'read' }) }, deny('policy_invalid'), F);
v('F05', 'methods [5]', { key: { permissions: { routes: ['/*'], methods: [5], environments: ['*'] } }, request: WIDE }, deny('policy_invalid'));
v('F06', 'methods {} (object)', { key: { permissions: { routes: ['/*'], methods: {}, environments: ['*'] } }, request: WIDE }, deny('policy_invalid', { php: 'method_not_allowed' }));
v('F07', 'environments {} (object)', { key: { permissions: { routes: ['/*'], methods: ['*'], environments: {} } }, request: WIDE }, deny('policy_invalid', { php: 'environment_not_allowed' }));
v('F08', 'environments [""]', { key: P({ environments: [''] }), request: GET('/api/reports', { environment: 'production' }) }, deny('environment_not_allowed'));
v('F09', 'assets omitted (no asset restriction)', { key: { assets: ABSENT } }, ok);
v('F10', 'assets null (no asset restriction)', { key: { assets: null } }, ok);
v('F11', 'assets [5]', { key: { assets: [5] } }, deny('policy_invalid', HOSTED_INVALID));
v('F12', 'org_id omitted', { key: { org_id: ABSENT } }, ok);
v('F13', 'expires_at omitted', { key: { expires_at: ABSENT } }, ok);
v('F14', 'expires_at 99999 (number)', { key: { expires_at: 99999 } }, deny('policy_invalid', { hosted: 'key_expired' }));
v('F15', 'expires_at true', { key: { expires_at: true } }, deny('policy_invalid', { hosted: 'key_expired' }));
v('F16', 'unknown top-level key field is metadata', { key: { note: 'imported' } }, ok);
v('F17', 'key status "Active" (case)', { key: { status: 'Active' } }, deny('policy_invalid', HOSTED_INVALID));

// --- R: the authorization request
const R = [
  ['R01', 'resource without method', { resource: { path: '/api/reports' } }, 'bad_resource'],
  ['R02', 'resource without path', { resource: { method: 'GET' } }, 'bad_resource'],
  ['R03', 'unknown resource field', { resource: { path: '/api/reports', method: 'GET', pth: '/x' } }, 'bad_resource'],
  ['R04', 'relative path', { resource: { path: 'api/reports', method: 'GET' } }, 'bad_path'],
  ['R05', 'traversal', { resource: { path: '/api/../admin', method: 'GET' } }, 'bad_path'],
  ['R06', 'encoded traversal', { resource: { path: '/api/%2e%2e/admin', method: 'GET' } }, 'bad_path'],
  ['R07', 'identity-only combined with a resource', { identityOnly: true, resource: { path: '/api/reports', method: 'GET' } }, 'bad_resource'],
  ['R08', 'no resource and no identity-only', {}, 'bad_resource'],
  ['R09', 'method with digits', { resource: { path: '/api/reports', method: 'G3T' } }, 'bad_resource'],
  ['R10', 'path array', { resource: { path: ['/api/reports'], method: 'GET' } }, 'bad_resource'],
];
for (const [id, title, request, reason] of R) v(id, title, { request, key: P({ routes: ['*'], methods: ['*'] }) }, deny(reason));

// --- I: the identity selector (RC4 review). Identity-only is selected ONLY by the top-level request field
// identityOnly: true with no resource (contract §2 step 1). A resource is a plain object with own fields path, method and
// optional environment and nothing else, so { resource: { identityOnly: true } } is a malformed resource (bad_resource),
// never an identity-only check. Each request runs against a key with empty grants and a key with normal grants.
const I = { changed_in: '0.4.5-rc4' };
const EMPTY_GRANTS = P({ routes: [], methods: [], environments: [] });
const NORMAL_GRANTS = P({ routes: ['*'], methods: ['*'], environments: ['*'] });
const IV = [
  ['nested identityOnly: true', { resource: { identityOnly: true } }],
  ['nested identity_only: true', { resource: { identity_only: true } }],
  ['nested identityOnly: "true"', { resource: { identityOnly: 'true' } }],
  ['nested identityOnly: 1', { resource: { identityOnly: 1 } }],
  ['top-level identityOnly: "true"', { identityOnly: 'true' }],
  ['top-level identityOnly: 1', { identityOnly: 1 }],
  ['top-level identityOnly: false', { identityOnly: false }],
  ['top-level identity_only: true (snake case)', { identity_only: true }],
  ['identityOnly nested two levels', { resource: { resource: { identityOnly: true } } }],
  ['identityOnly nested inside path', { resource: { path: { identityOnly: true }, method: 'GET' } }],
  ['identityOnly nested inside a list', { resource: [{ identityOnly: true }] }],
  ['nested identityOnly with path and method', { resource: { identityOnly: true, path: '/api/reports', method: 'GET' } }],
  ['nested identityOnly with an unknown resource key', { resource: { identityOnly: true, extra: 1 } }],
  ['resource null', { resource: null }],
  ['resource {}', { resource: {} }],
  ['resource []', { resource: [] }],
  ['resource string', { resource: 'identityOnly' }],
  ['resource number', { resource: 1 }],
  ['resource true', { resource: true }],
  ['top-level identityOnly + nested identityOnly resource', { identityOnly: true, resource: { identityOnly: true } }],
  ['top-level identityOnly + resource null', { identityOnly: true, resource: null }],
  ['top-level identityOnly + resource {}', { identityOnly: true, resource: {} }],
  ['top-level identityOnly + resource []', { identityOnly: true, resource: [] }],
  ['top-level identityOnly + resource string', { identityOnly: true, resource: 'x' }],
  ['top-level identityOnly + resource 0', { identityOnly: true, resource: 0 }],
  ['top-level identityOnly + unknown option', { identityOnly: true, extra: 1 }],
];
let iN = 0;
const iid = () => 'I' + String(++iN).padStart(2, '0');
// PHP takes ONE request array, which is itself the resource, and array('identity_only' => true) is PHP's own top-level
// identity selector (contract §1.1). Two Node shapes therefore land on PHP's valid selector and are not malformed there;
// for those, php_resource gives the PHP-native malformed equivalent of the same intent (PHP harness only).
const PHP_FORM = {
  'nested identity_only: true': { php_resource: { resource: { identity_only: true } }, php_note: 'Node resource { identity_only: true } is PHP\'s own selector; PHP-native nested form used' },
  'top-level identity_only: true (snake case)': { php_resource: { identityOnly: true }, php_note: 'snake case is PHP\'s own top-level selector; the wrong-case PHP form (camelCase) is used' },
};
for (const [t, request] of IV) {
  v(iid(), `${t}, key with empty grants`, { key: EMPTY_GRANTS, request }, deny('bad_resource'), { ...I, ...(PHP_FORM[t] || {}) });
  v(iid(), `${t}, key with normal grants`, { key: NORMAL_GRANTS, request }, deny('bad_resource'), { ...I, ...(PHP_FORM[t] || {}) });
}
v(iid(), 'control: top-level identityOnly: true, key with empty grants', { key: EMPTY_GRANTS, request: { identityOnly: true } }, ok, I);
v(iid(), 'control: top-level identityOnly: true, key with normal grants', { key: NORMAL_GRANTS, request: { identityOnly: true } }, ok, I);

// --- T: token mode (contract 1.2.0, 0.5.0 RC7 Q1). The policy / site is in token mode (no route policy; keys are ignored):
// a path/method request is policy_required (checked first), a wallet whose every held asset is revoked for the site is
// entitlement_revoked, none held is not_holder. Hosted enforces this on verify and sign-in from 0.5.0 (evaluateToken);
// before, hosted answered 200 for a revoked token in token mode while self-verify denied it. Malformed revoked_assets:
// self-verify refuses the policy (policy_invalid), hosted refuses the stored state (access_data_invalid).
const T = { policy_mode: 'token', changed_in: '0.5.0-rc7' };
const ID = { identityOnly: true };
v('T01', 'token mode: holder of an accepted token, identity check', { request: ID }, ok, T);
v('T02', 'token mode: every held token revoked for the site (Q1)', { held: ['REVOKEDTOKEN'], request: ID }, deny('entitlement_revoked'), T);
v('T03', 'token mode: one held token revoked, another still accepted', { held: ['REVOKEDTOKEN', 'GOODTOKEN'], request: ID }, ok, T);
v('T04', 'token mode: nothing held', { held: [], request: ID }, deny('not_holder'), T);
v('T05', 'token mode: a path/method request needs a route policy', { request: GET('/api/reports') }, deny('policy_required'), T);
v('T06', 'token mode: revoked token and a path/method request (the request is checked first)', { held: ['REVOKEDTOKEN'], request: GET('/api/reports') }, deny('policy_required'), T);
v('T07', 'token mode: revoked_assets malformed (a string, not a list)', { held: ['REVOKEDTOKEN'], state: { revoked_assets: 'REVOKEDTOKEN' }, request: ID }, deny('policy_invalid', HOSTED_INVALID), T);
v('T08', 'token mode: a key in the record does not matter (keys are ignored)', { held: ['REVOKEDTOKEN'], key: { status: 'revoked' }, request: ID }, deny('entitlement_revoked'), T);

const out = {
  contract: 'tokenlock-authorization', contract_version: '1.2.0', sdk_version: '0.5.0', now: NOW,
  how_to_run: 'PHP: a vector with php_resource passes that value as the request argument (the PHP-native form of the same request). Self-verify (Node/PHP): policy = { v:1, typ:"tokenlock.policy", site_id:"site_vectors", seq:1, issued_at: now-60s, expires_at: now+3600s, mode:"registered_keys", settings: state.settings, orgs: state.orgs, revoked_assets: state.revoked_assets, keys:[key] }; evaluate(policy, { address, held, ...request, now }). Hosted: evaluate({ state, key: key.address === address ? key : null, held, ...request, now }). Token mode (contract 1.2.0): a vector with policy_mode "token" uses mode:"token" in the self-verify policy, and hosted evaluateToken({ state, held, ...request, now }) (the rule hosted verify and sign-in apply to token-mode sites from 0.5.0). Cloudflare worker: strictCheck(hosted answer, request.resource). A decision is equivalent when allowed matches; reason must equal expect.reason, or expect.platform_reason[platform] where listed.',
  vectors,
};
writeFileSync(new URL('../../docs/authorization-vectors-v1.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
console.log(`wrote ${vectors.length} vectors`);
