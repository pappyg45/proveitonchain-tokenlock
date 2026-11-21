// Shared identity-selector cases (RC4): used by test/identity-selector-045.test.mjs and test/fuzz-identity-045.test.mjs.
import { NOW as PNOW } from './prop-gen.mjs';
export const NOW = Date.parse(PNOW);
export const iso = (ms) => new Date(ms).toISOString();
export const A = 'bc1qidentityselector000000000000000000000000';
export const pol = (o) => ({ v: 1, typ: 'tokenlock.policy', site_id: 'local', seq: 1, issued_at: iso(NOW - 60e3), expires_at: iso(NOW + 3600e3), orgs: [], revoked_assets: [], keys: [], ...o });
const key = (permissions) => ({ id: 'k1', address: A, status: 'active', owner_type: 'agent', org_id: null, assets: [], expires_at: null, permissions });
export const POLICIES = {
  'token mode': pol({ mode: 'token' }),
  'registered, empty grants': pol({ mode: 'registered_keys', keys: [key({ routes: [], methods: [], environments: [] })] }),
  'registered, normal grants': pol({ mode: 'registered_keys', keys: [key({ routes: ['*'], methods: ['*'], environments: ['*'] })] }),
};
export const VARIANTS = [
  ['nested identityOnly: true', { resource: { identityOnly: true } }],
  ['nested identity_only: true', { resource: { identity_only: true } }],
  ['nested identityOnly: "true"', { resource: { identityOnly: 'true' } }],
  ['nested identityOnly: 1', { resource: { identityOnly: 1 } }],
  ['top-level identityOnly: "true"', { identityOnly: 'true' }],
  ['top-level identityOnly: 1', { identityOnly: 1 }],
  ['top-level identityOnly: false', { identityOnly: false }],
  ['top-level identity_only: true', { identity_only: true }],
  ['identityOnly nested two levels', { resource: { resource: { identityOnly: true } } }],
  ['identityOnly nested inside path', { resource: { path: { identityOnly: true }, method: 'GET' } }],
  ['identityOnly nested inside a list', { resource: [{ identityOnly: true }] }],
  ['nested identityOnly with path and method', { resource: { identityOnly: true, path: '/api/x', method: 'GET' } }],
  ['nested identityOnly with an unknown resource key', { resource: { identityOnly: true, extra: 1 } }],
  ['resource null', { resource: null }], ['resource {}', { resource: {} }], ['resource []', { resource: [] }],
  ['resource string', { resource: 'identityOnly' }], ['resource number', { resource: 1 }], ['resource true', { resource: true }],
  ['top-level identityOnly + nested identityOnly resource', { identityOnly: true, resource: { identityOnly: true } }],
  ['top-level identityOnly + resource null', { identityOnly: true, resource: null }],
  ['top-level identityOnly + resource {}', { identityOnly: true, resource: {} }],
  ['top-level identityOnly + resource []', { identityOnly: true, resource: [] }],
  ['top-level identityOnly + resource string', { identityOnly: true, resource: 'x' }],
  ['top-level identityOnly + resource 0', { identityOnly: true, resource: 0 }],
  ['top-level identityOnly + valid resource', { identityOnly: true, resource: { path: '/api/x', method: 'GET' } }],
  ['top-level identityOnly + unknown option', { identityOnly: true, extra: 1 }],
  ['empty request', {}],
];
// ---- P-ID property
export const KEYS = ['identityOnly', 'resource', 'identity_only', 'extra'];
export const POOL = [true, false, 'true', 1, 0, null, '', 'x', {}, [], { identityOnly: true }, { identity_only: true }, { identityOnly: 'true' },
  { path: '/api/x', method: 'GET' }, { path: '/api/x', method: 'GET', environment: 'production' }, { identityOnly: true, path: '/api/x', method: 'GET' },
  { path: '/api/x', method: 'GET', extra: 1 }, { resource: { identityOnly: true } }, [{ identityOnly: true }], { path: { identityOnly: true }, method: 'GET' }, { path: 'api/x', method: 'GET' }];
export function requests() {
  const out = [{}];
  for (let i = 0; i < KEYS.length; i++) for (const a of POOL) out.push({ [KEYS[i]]: a });
  for (let i = 0; i < KEYS.length; i++) for (let j = i + 1; j < KEYS.length; j++) for (const a of POOL) for (const b of POOL) out.push({ [KEYS[i]]: a, [KEYS[j]]: b });
  return out;
}
const plain = (x) => x !== null && typeof x === 'object' && !Array.isArray(x) && Object.getPrototypeOf(x) === Object.prototype;
const okStr = (s) => typeof s === 'string' && s !== '' && s.trim() === s;
export const strictIdentity = (r) => Object.keys(r).length === 1 && r.identityOnly === true;
// independent oracle for a valid resource request (contract §2 step 1); a path is valid only if canonical.
export function validResourceRequest(r, canonical) {
  if (Object.keys(r).length !== 1 || !plain(r.resource)) return false;
  const x = r.resource, ks = Object.keys(x);
  if (!ks.every((k) => ['path', 'method', 'environment'].includes(k)) || !ks.includes('path') || !ks.includes('method')) return false;
  if (!okStr(x.path) || !okStr(x.method) || !/^[A-Za-z]{1,10}$/.test(x.method)) return false;
  if (ks.includes('environment') && (!okStr(x.environment) || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,29}$/.test(x.environment))) return false;
  return x.path.startsWith('/') && canonical(x.path) !== null;
}
