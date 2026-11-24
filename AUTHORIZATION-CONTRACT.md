# TOKENLOCK authorization contract

**Version 1.2.0** (TOKENLOCK SDK 0.5.0, now published as @tokenlock/sdk / TOKENLOCK PHP 0.5.0; 1.1.0 was introduced in 0.4.5). Status: normative.

This document defines when TOKENLOCK allows an action. Every implementation must give the same decision for the same input:
- Node self-verify (`evaluate`, `verifyLocalPass`, `checkPass`)
- PHP self-verify (`tokenlock_sv_evaluate`)
- the hosted API (`/api/v1/gate/verify` and gate sign-in; `access.evaluate`, and `access.evaluateToken` for token-mode sites since 1.2.0)
- the Cloudflare Worker, which enforces the hosted answer

The test vectors in [`docs/authorization-vectors-v1.json`](docs/authorization-vectors-v1.json) are part of this contract. Where this text and a vector disagree, the vector wins, and the text is a bug.

> **Invariant.** Missing, malformed or ambiguous authorization information never increases access. Removing a field, corrupting a field, or narrowing a grant can only keep a decision the same or turn an allow into a deny.

The key words MUST, MUST NOT and SHOULD are used as in RFC 2119.

## 1. Inputs

| Input | What it is | Where it MUST come from |
|---|---|---|
| `key` | The registered key for the signing wallet: `status`, `permissions`, and optional `assets`, `org_id`, `expires_at` | The site's access store (hosted) or a signed / local policy (self-verify). Never from the request. |
| `state` | `settings.require_org`, `orgs[]` (`id`, `status`), `revoked_assets[]` | Same as `key` |
| `held` | Assets the wallet holds | A holdings lookup made by TOKENLOCK or the site's server (cached per `recheck_holdings_s`). Never from the request. |
| `request` | Exactly one of: `resource: { path, method, environment? }` or `identityOnly: true` | The site's own server. See §1.1. |

### 1.1 Trusted request context, especially the environment

The `environment` in a request is a claim about where the request is served (for example `production`). It decides whether an environment-restricted key may act, so it MUST NOT come from the agent or client that presents the pass.

| Integration | Source of `environment` | Can the requesting agent set it? |
|---|---|---|
| Node guard / middleware (`tokenlock()` for Next and Express, `createGuard`) | `opts.environment` in the server's own configuration | No |
| Node `verifyPass` / `TokenlockClient` | Argument from the site's server code, sent with the secret key | Only if the integrator copies it from the request (documented as wrong) |
| PHP drop-in | `$cfg['environment']` (`config.php` or `TOKENLOCK_ENVIRONMENT`) | No |
| Cloudflare Worker | The `TOKENLOCK_ENVIRONMENT` binding | No |
| Hosted `/api/v1/gate/verify` | The request body. **Since contract 1.0.0, a resource check (path, method or environment) is answered only with the site's secret key** (`Authorization: Bearer sk_…`). Without the key the answer is `secret_key_required`. | No: only the site's server holds the secret key |

No implementation reads the environment from request headers. Before 1.0.0, the hosted API answered resource checks for anyone holding a pass, against the pass's own site, with the caller's environment.

## 2. Decision procedure

The steps run in this order. The first step that fails decides, so a later step never overrides an earlier denial.

1. **Request shape.** The request must be exactly `{ resource }` or `{ identityOnly: true }`.
   - `resource` must be a plain object with own fields `path` and `method`, plus an optional `environment`, and nothing else.
   - Identity-only is selected **only** by the top-level `identityOnly: true` with no `resource`. An identity flag anywhere else (`resource: { identityOnly: true }`, `identity_only`, `"true"`, `1`, nested deeper, or beside a resource or an unknown field) is a malformed request (`bad_resource`), never an identity-only check (RC4 clarification; vector group I). PHP's request argument is itself the resource, so its selector is exactly `array('identity_only' => true)`.
   - `method`: 1-10 letters, normalized to upper case.
   - `environment`: 1-30 characters from `[A-Za-z0-9_.-]`, case-sensitive.
   - `path`: an absolute canonical path (TOKENLOCK path rules v1.1). No dot segments, no encoded separators.
   - Failure → `bad_resource` (or `bad_path` for a path that cannot be made canonical).
2. **Held assets.** `held` must be a list of strings, else `bad_input`.
3. **Policy shape** (self-verify only). A malformed policy or key field gives `policy_invalid` for the whole policy; an expired policy gives `policy_expired`.
4. **Mode.** A token-mode site has no route rules, so a resource request gives `policy_required`. An identity-only request goes to step 6 (holdings), with no key (keys are ignored in token mode). Since 1.2.0 this applies to the hosted API too: before 0.5.0 hosted verify and sign-in did not apply step 6 to token-mode sites, so a token whose entitlement the admin had revoked was still accepted there (vectors T01-T08).
5. **Key.**
   - No key for the address → `not_registered`.
   - `status`: `revoked` → `key_revoked`; `pending_approval` → `pending_approval`; any other value except `active` → deny.
   - `expires_at`: absent, `null` or `""` means no expiry. Otherwise it MUST be an ISO 8601 date-time string; non-ISO or past → deny (`key_expired`).
   - `org_id`: if set, the org must exist with status `approved`, else `org_not_approved`. If not set and `require_org` is on → `org_required`.
6. **Entitlement.** At least one held asset must be neither in `revoked_assets` nor outside a non-empty `key.assets`. Otherwise `entitlement_revoked`, or `not_holder` when nothing is held.
7. **Grants** (resource requests only; identity-only stops before this step). See §3. Order: grant shape → environment → route → method.

Allowed = every step passed: `{ allowed: true, reason: 'ok' }`.

### 2.1 Equivalent reasons

`allowed` MUST be identical everywhere. `reason` MUST be identical except for these documented platform aliases, which the vectors record as `platform_reason`. Each pair below is the same denial.

| Contract reason | Alias | Where |
|---|---|---|
| `policy_invalid` (bad key status / assets) | `access_data_invalid` | hosted (stored data is validated per key, not as a policy) |
| `policy_invalid` (token mode, malformed `revoked_assets`) | `access_data_invalid` | hosted (since 1.2.0; a live verify answers `503` for such stored state) |
| `policy_invalid` (unparseable `expires_at`) | `key_expired` | hosted |
| `policy_invalid` (`routes: {}`) | `route_not_allowed` | PHP (`json_decode(..., true)` turns `{}` into an empty list) |

## 3. Grants (`key.permissions`)

`permissions` MUST be an object with exactly three fields: `routes`, `methods` and `environments`, all required. It is a **closed object** (since 1.1.0): any other field (a misspelling such as `route`, or a restriction this version does not know) makes the key `policy_invalid`, so a restriction is never silently ignored.

| Field value | Meaning |
|---|---|
| missing, `null`, not a list, or a list containing a non-string | **`policy_invalid`**: the key is refused for every resource. It still works for identity-only checks. |
| `[]` (routes / methods) | Grants nothing (`route_not_allowed` / `method_not_allowed`) |
| `[]` (environments) | Grants no environment (`environment_not_allowed`). Since 1.1.0; see §5. |
| `["*"]` | Wildcard. A wildcard exists only when written explicitly. |

- **routes.**
  - `*` and `/*` match every path.
  - `/x/*` matches `/x` and everything under `/x/`, but not `/xy`.
  - Any other pattern is an exact path. **A trailing slash does not make a prefix:** `/x/` matches only `/x`.
  - Patterns are case-insensitive. An empty pattern, or one without a leading `/`, matches nothing. There is no other glob syntax.
- **methods.** `*`, or exact upper-case names. A lower-case name in a key matches nothing, because grants are never normalized.
- **environments.**
  - A list containing `*` → any environment, including none.
  - A non-empty list without `*` → the request MUST name one of the listed environments (case-sensitive). **An omitted environment is denied** (`environment_not_allowed`), the same as a mismatched one.
  - `null`, `""`, a number, a padded string and similar request values are malformed (`bad_resource`, step 1).

## 4. Optional key restrictions

These fields are restrictions. Absent means "no restriction of this kind" (they are not grants):
- `assets`: absent, `null` or `[]` → any accepted token.
- `org_id`: absent, `null` or `""` → no org, unless `require_org` is on.
- `expires_at`: absent, `null` or `""` → no expiry.

A malformed value is refused, never treated as absent:
- `assets: "X"`, `assets: [5]` → `policy_invalid` / `access_data_invalid`.
- `expires_at: 99999`, `true` → `policy_invalid` / `key_expired`.
- `status` other than the exact lower-case names (`"Active"`) → `policy_invalid` / `access_data_invalid`.

Other top-level key fields (`label`, `note`, timestamps) are metadata and never affect a decision. The hosted API refuses malformed restriction values on write (`400 bad_assets`, `400 bad_expiry`), so they can only appear in hand-written or corrupted data.

## 5. Legacy forms and migration

- `environments: []` grants no environment since 1.1.0 (1.0.0 honored it as "no restriction"). The hosted API has not created it since 1.0.0; an owner who meant "any environment" writes `["*"]`. Treating an empty list as a wildcard was an implicit grant, which this contract does not allow (§3), so the change was made in a minor version as a new denial (§10).
- A key missing `environments` is refused for resources (`policy_invalid`). RC1's hosted API always stored a list, so this affects only hand-written policies.
- Stored data is never rewritten silently. See `MIGRATION` in the 0.4.5 CHANGELOG.

## 6. Hosted admin API (key lifecycle)

1. **Create** (`POST /keys`). `routes`, `methods` and `environments` are each REQUIRED, given either top-level or as `permissions: {…}`.
   - Missing, `null`, a blank string or `environments: []` → `400 permissions_required`.
   - A wrong type (number, object, a list with non-strings) → `400 bad_permissions`.
   - `"*"` is stored only when sent. `routes: []` / `methods: []` are accepted and grant nothing.
   - A `permissions` object with any other field → `400 bad_permissions` (since 1.1.0; also on update, approve and rotate).
   - `expires_at` must be an ISO 8601 date-time or `null` (`99999`, `true`, `"2999"` → `400 bad_expiry`). `assets` must be a list of strings, a comma-separated string, or `null` (anything else → `400 bad_assets`; it was silently dropped before 1.1.0, which removed the restriction).
2. **Update** (`POST /keys/:id`). Update never changes `status`. A field not sent keeps the stored value only if the stored value is a valid list (a non-empty list for environments). Otherwise → `400 permissions_required`. Nothing is filled in.
3. **Approve request** (`POST /requests/:id/approve`).
   - New address: same rules as create (the dashboard asks for the grants).
   - Existing key paused because its token moved (`pending_approval`, no hold): approved with its stored grants unchanged.
   - Revoked key: never revived (`409 key_revoked`). Key on recovery hold or in any other non-active status: `409 key_on_hold`. Reactivate such a key on the key itself (§6.3).
4. **Rotate** (`POST /keys/:id/rotate`). Only an `active` key can be rotated (`409 key_not_active`). The new key's grants are the request's (permissions object or top-level fields), falling back to the old key's valid stored lists, under the same rules as update.
5. **Revoke.** Immediate on the hosted API. Self-verify sees it at the next policy refresh (signed policy: 60 s refresh, 600 s maximum TTL). Success semantics are in §6.4.
6. **Serialization** into the signed policy carries stored values as-is (absent → `null` / `[]`). A corrupt value is never turned into "no restriction"; the verifier refuses it. A key on recovery hold is serialized as `pending_approval`, so every self-verify client denies it with no client change.
7. **Concurrency (since 1.1.0).** Admin changes, verify-time pauses and restores for a site are serialized by a per-site lock (`409 site_busy` if it cannot be taken within a few seconds; the change was not made, retry). Inside the lock every write is also checked against what was read: a key carries a version `rev`, the site state a `version` (`409 key_changed` / `409 state_changed`). A key edit may send `if_rev` to fail if the key changed since the admin loaded it. A pause made by a verify that read the key before a revocation or a narrowing never replaces it. If the lock holder dies, the lock expires (15 s by default) and nothing partial is visible: see the write order in §6.4.

### 6.3 Reactivation requires explicit grants (since 1.1.0)

`POST /keys/:id/approve` on a key that is `revoked`, on recovery hold, or in any status other than `active` / `pending_approval` reactivates it only with values the administrator confirms in the same request:
- `routes`, `methods` and `environments`, under the create rules (§6, item 1). Missing → `400 permissions_required`.
- `expires_at`: REQUIRED as a key. An ISO 8601 date-time, or `null` for no expiry. Missing → `400 expiry_required`.

Stored grants and the stored expiry are **never** reused for a reactivation. They remain visible in the admin view as the key's previous grants, for reference only; the dashboard shows them as text and starts every input empty. The reactivated key records `reactivated_at`, `reactivated_from` (`revoked`, `recovery_hold`, …) and `last_revoked_at`. No other path turns a revoked key active: request approval answers `409` (§6, item 3), rotate needs an active key (§6, item 4), create answers `409 key_exists` for an address that already has a key, update never sets `status`, and recovery never reactivates (§6.5).

A key in `pending_approval` without a hold (its token moved, then came back) is approved with its stored grants unchanged, as in 1.0.0.

### 6.4 Durability of changes (since 1.1.0)

The hosted access store (live) is backed by three durable stores, each sealed with authenticated encryption bound to the site:
- an append-only **journal** of changes;
- a full **snapshot**;
- a **revocation ledger**, kept apart from the snapshot and journal and never restored from them: for every key the highest key version `rev` and its status at that version, and the highest site-state version. A restore of an older snapshot and journal cannot roll it back.

Every change gets the next value of a per-site change sequence; the journal event and the snapshot both carry it, and a snapshot is never replaced by one with a lower sequence. Ledger entries only move forward.

**Write order of a change** (under the site lock, §6, item 7): (1) for a revocation only, a ledger tombstone: the key's next `rev` with status `revoked`; (2) the live store; (3) the change sequence; (4) the ledger entry for every changed key and the state version; (5) the journal; (6) the snapshot. A recovery hold is written the same way.

| Journal | Snapshot | Ledger | Response | Live state | What recovery restores |
|---|---|---|---|---|---|
| ok | ok | ok | `200` | changed | the change |
| failed | ok | any | `503 not_durable` | changed | the change (from the snapshot) |
| ok | failed | any | `503 not_durable` | changed | the change (journal replayed on the snapshot) |
| failed | failed | ok | `503 not_durable` | changed | the previous durable state; a key the ledger shows changed later is revoked (latest status `revoked`) or held; if the state is not established for another reason (e.g. a journal gap), every non-revoked key is held (§6.5) |
| failed | failed | failed | `503 not_durable` | changed | the previous durable state, **on recovery hold** if a later change is recorded only in the journal (§6.5); the change itself is not guaranteed |
| ok | ok | failed | `503 not_durable` | changed | the change (snapshot + journal) |

- **`200` means the journal, the snapshot and the ledger all hold the change**, so any recovery preserves it. In particular, a revocation answered `200` survives every recovery path, including a restore of an older snapshot + journal pair (the ledger revokes it again).
- **Process termination** between any two writes never leaves broader access: before the live write nothing changed in the live store (a revocation's tombstone may already be in the ledger, so a later restore denies the key); after the live write the live store denies; a restore from durable stores that missed the change denies through the ledger tombstone or a hold.
- **`503 not_durable`** means the change is in effect on the live store now (a revocation denies immediately) but is not guaranteed to survive a loss of the live store. The client MUST treat it as "not done" and repeat the same request until it answers `200`. Repeating is safe: revoke, approve and update are idempotent on the resulting state. The admin view reports `durability.pending: true` until a later change is fully durable.
- A site without a configured backup has no recovery; its changes answer `200` with `journal_ok: false, backup_ok: false`, and a lost live store answers `503` (fail closed) instead of restoring.

### 6.5 Recovery (since 1.1.0)

When the live store is empty, the hosted API restores from the durable stores before answering anything:

1. Read the snapshot. Missing, unreadable, or not decryptable → no restore; every request for the site answers `503 access_unavailable` (fail closed). An admin change on a site whose live store is lost restores first, and answers `503 access_unavailable` if it cannot (it never starts a fresh, empty state).
2. Read the journal and replay, in sequence order, every event with a sequence above the snapshot's.
3. Read the ledger and reconcile each key: if the ledger's `rev` for the key is higher than the restored key's (or names another key id), the restored copy is older than the latest change. If the ledger's latest status for the key is `revoked`, the key is revoked (`revoke_reason: 'revocation ledger (restored copy was older)'`); any other later change holds it. A ledger state version above the restored state's holds every key.
4. The latest state is **established** only if all of the following hold; otherwise each failing condition is recorded as a problem:

| Problem | Condition |
|---|---|
| `snapshot_unverifiable` | the snapshot is not sealed (authenticated encryption) |
| `snapshot_without_sequence` | the snapshot predates sequences (written before 1.1.0) |
| `journal_missing` | no journal |
| `journal_unreadable` | the journal cannot be read, decrypted or parsed, or only a stale copy is available |
| `journal_gap` | the journal's events after the snapshot are not consecutive from the snapshot's sequence |
| `ledger_missing` | no ledger, for a snapshot written with sequences |
| `ledger_unreadable` | the ledger cannot be read, decrypted or parsed |
| `state_behind_ledger` | the ledger records a site-state version newer than the restored state (an entitlement revocation, org or setting change was lost) |
| `key_behind_ledger` | the ledger records a later change to a key than the restored copy (this problem holds only those keys) |

5. **Established** → the restored state is used as-is. **Not established** → every key that is not `revoked` is put on **recovery hold**: `status: pending_approval`, `hold: 'recovery'`, `paused_reason: 'recovery_unverified'`. Hosted verify and every self-verify client deny it (`pending_approval`). A revoked key stays revoked in both cases. When the state is not established, a key the ledger records as revoked is held too, with `held_from: 'revoked'` (denied either way; both need §6.3 to reactivate). `key_behind_ledger` alone holds only the affected keys.
6. A held key leaves the hold only by an explicit reactivation (§6.3). Request approval answers `409 key_on_hold`.
7. The restore is itself recorded as a change (journal + snapshot), so a second loss restores the same state, holds included. The admin view shows `recovery: { at, established, problems, held, revoked_by_ledger }`. A hold is never removed by a restart or a later restore: holds are stored with a new `rev` and recorded in the ledger.

**States and transitions.**

| From | Action | To |
|---|---|---|
| (none) | create with explicit grants | `active` |
| `active` | token moved (verify) | `pending_approval` (paused) |
| `pending_approval` (paused) | approve | `active`, grants unchanged |
| any | revoke | `revoked` |
| `revoked` | approve with explicit grants + `expires_at` | `active` (new grants) |
| `active`, `pending_approval` | recovery not established | `pending_approval` + recovery hold |
| recovery hold | approve with explicit grants + `expires_at` | `active` (new grants) |
| `revoked` | any recovery | `revoked` |
| `active`, `pending_approval` | recovery finds a later revocation in the ledger (state otherwise established) | `revoked` |
| `active`, `pending_approval` | recovery finds any other later change in the ledger | `pending_approval` + recovery hold (that key only) |
| any | restart, cache expiry, later restore | unchanged (a hold or denial is never lifted by recovery) |

**Caches.** Hosted allowed answers are cached at most 5 s (§7). The service keeps no policy cache: the signed policy is built from the live store on every fetch, so a held or revoked key is denied in the next policy a client fetches (self-verify refreshes within 60 s, 600 s at most; §6, item 5).

**Limits.** A change answered `503 not_durable` and never retried can be lost if the live store is lost before a later change is fully durable; this is the documented meaning of `503` (a revocation's ledger tombstone still denies the key on restore). A rollback of all three durable stores together to an earlier consistent set cannot be detected by the service; the ledger lives under its own object name so an ordinary backup restore of the snapshot and journal does not include it. Writes are serialized per site and version-checked (§6, item 7).

### 6.6 Administrative recovery procedure (since 1.1.0)

1. **See the state.** `GET /admin/access` shows `recovery` (problems, held count, keys revoked by the ledger) and `durability.pending`. Every held key shows `hold: 'recovery'`, `held_from` and its previous grants (read-only).
2. **Do not bulk-approve.** There is no "release all" action. For each held key, decide from your own records whether it should still have access.
3. **Reactivate** a key that should: `POST /keys/:id/approve` with `routes`, `methods`, `environments` and `expires_at` confirmed now (§6.3). A key that should not keep access: revoke it, or leave it held (it is denied).
4. **Repeat any change answered `503 not_durable`** until it answers `200`.
5. **`503 access_unavailable`** (no usable snapshot): the site's keys stay denied. Restore the snapshot object from your storage backup if one exists; on the next request the service restores and reconciles against the ledger (keys changed later are held or revoked again, never widened). Otherwise re-create the keys with explicit grants after the operator resets the site's access store.
6. **Ledger missing or unreadable:** every key is held (fail closed) and step 3 applies; the next change re-seeds the ledger from the live store.

## 7. Caching

- **Cache keys.** Every cache keys on site key, pass, mode, method, canonical path and environment, so one resource's answer is never reused for another.
- **Hosted:** allowed answers carry `cache_max_s: 5`, denials `0`.
- **Self-verify policies** are bounded by `expires_at` and refuse sequence rollback.

## 8. Conformance

An implementation conforms when all of the following hold:
- It decides every vector in `docs/authorization-vectors-v1.json` as `expect` says. `allowed` must be equal; `reason` must be equal, or equal to the vector's `platform_reason` for that platform.
- Its property tests (§9) report zero violations.
- It passes the shared regression suites.

The CF Worker conforms when it allows exactly the hosted decisions it is given, and refuses tampered answers (wrong path, method or environment echo, missing `allowed`).

| Runner | Command |
|---|---|
| Node | `node --test test/authz-contract.test.mjs` (also part of `npm test`) |
| PHP | `php php/test/authz-contract.php` |
| Hosted + CF on hosted answers | `node tests/tokenlock-authz-contract.test.mjs` (site repo) |

Each runner writes per-vector results with `AUTHZ_RESULTS=<dir>`.

## 9. Property tests

The generator lives in-repo (`test/vectors/prop-gen.mjs`, ported byte-for-byte to `php/test/lib/prop-gen.php`):
- No dependencies.
- PRNG mulberry32, seeds `4572833` and `4572834`, 150 base keys per seed.
- 64 requests per base.

For every base key and every mutation, the allowed set after the mutation MUST be a subset of the allowed set before it:
- **P1 removal:** delete any permission field, `permissions`, `status`, or a list element.
- **P2 corruption:** set fields to `null`, strings, numbers, objects or wrong-type elements; corrupt `expires_at` (`99999`, `"2999"`, `5`, `true`, `{}`).
- **P3 narrowing:** remove a route, method or environment; replace `*` with a concrete value; add `assets`, `org_id` or an earlier `expires_at`.

The input digest and decision digest MUST be identical across implementations.

## 10. Versioning

- **MAJOR:** a decision changes from deny to allow, or an input's meaning changes. This needs an advisory.
- **MINOR:** new denials or new vectors. Also: removing an implicit grant that this contract already disallows (1.1.0: `environments: []`; unknown permission fields, which were ignored).
- **PATCH:** text only.

| Version | Change |
|---|---|
| 1.2.0 (0.5.0 RC7) | Hosted applies §2 steps 4 and 6 to token-mode sites (verify and gate sign-in): a wallet whose every held token is revoked for the site is denied `entitlement_revoked`, as self-verify already did. New vectors T01-T08 (`policy_mode: "token"`). A new denial on hosted, so a minor version. |
| 1.1.0 (0.4.5 RC3) | `environments: []` grants no environment (was the deprecated legacy "any"); reactivating a revoked or held key requires explicit grants and `expires_at` (§6.3); `200` means the change is in both durable stores, otherwise `503 not_durable` (§6.4); recovery that cannot establish the latest state holds non-revoked keys (§6.5). Vectors E07/E08 changed to deny; new vectors L01-L05. |
| 1.0.0 (0.4.5 RC2) | First normative version. Changes from 0.4.5 RC1: `environments` required; a restricted key denies an omitted environment; trailing slash is exact; strict ISO `expires_at` on the hosted API; hosted resource checks need the secret key; no implicit wildcards in the hosted admin API. |
