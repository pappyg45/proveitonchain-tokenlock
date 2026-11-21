# Upgrading to TOKENLOCK 0.4.5 (compatibility note)

0.4.5 is a security patch for `@proveitonchain/tokenlock` and TOKENLOCK PHP. It adds no features. It removes every implicit
authorization default, so a few setups that worked by accident now deny. Normative rules:
[AUTHORIZATION-CONTRACT.md](AUTHORIZATION-CONTRACT.md) (version 1.1.0). Check each item below before you upgrade.

**Order.** The hosted service is updated before the 0.4.5 packages are published, so an upgraded client always talks to a
service that already enforces the same rules. You can upgrade clients at any time after that.

## 1. Environments are required

| Situation | 0.4.4 / RC1 | 0.4.5 | What to do |
|---|---|---|---|
| A key has no `environments`, or `null` | any environment | `policy_invalid` for that key (any request with a resource) | Add `environments` (hand-written policies only; the hosted API always stored a list) |
| `environments: []` | any environment | **no environment** (`environment_not_allowed`) | Write `['*']` for any environment, or list them |
| A key restricted to e.g. `['production']`, request names no environment | allowed | `environment_not_allowed` | Set the environment in **server configuration**: guard `environment`, PHP `'environment'` / `TOKENLOCK_ENVIRONMENT`, worker `TOKENLOCK_ENVIRONMENT` |
| `['*']` | any environment | unchanged | none |

Take the environment from your own deployment configuration, never from the request or the agent (contract §1.1).

## 2. Grants are explicit everywhere

| Operation (hosted admin API and dashboard) | 0.4.5 |
|---|---|
| Create a key (`POST /keys`) | `routes`, `methods`, `environments` required (`400 permissions_required`). `'*'` is stored only when you send it. |
| Approve a wallet's request for a new address | Same as create; the dashboard asks for the grants. |
| Approve a key paused because its token moved | Unchanged grants (it was never revoked). |
| **Reactivate a revoked key** (`POST /keys/:id/approve`) | `routes`, `methods`, `environments` **and** `expires_at` (ISO date, or `null` for no expiry) required. Previous grants are shown for reference only and are never reapplied. |
| Reactivate a key on recovery hold | Same as a revoked key. |
| Approve a request for a revoked or held address | `409 key_revoked` / `409 key_on_hold`: reactivate the key itself. |
| Rotate | Only an active key. |

Self-verify: a policy key needs explicit `routes`, `methods` and `environments` lists. `[]` grants nothing; `'*'` is a
wildcard only when written. `permissions` may contain only those three fields: any other field (a misspelling such as
`route`, or a custom field) makes the key `policy_invalid` everywhere (0.4.4 ignored it and kept the other grants).

Stricter input checks on the hosted admin API (nothing changes for valid input):

| Input | 0.4.4 | 0.4.5 |
|---|---|---|
| `permissions` with an unknown field | field ignored | `400 bad_permissions` |
| `expires_at` not an ISO date-time (`99999`, `true`, `"2999"`) | some accepted | `400 bad_expiry` |
| `assets` not a list or a string (`5`, `{}`) | silently dropped (no restriction) | `400 bad_assets` |

### Identity-only requests (RC4)

`evaluate(policy, { address, held, identityOnly: true })` is the only identity-only form. `evaluate(policy, { address, held, resource: { identityOnly: true } })` and every other placement or spelling of the flag are refused with `bad_resource`. Client APIs (`verifyPass`, `getPass`, `TokenlockClient#verifyPass`, the Cloudflare worker's `verify`) keep taking `{ identityOnly: true }` as their request argument; PHP keeps `array('identity_only' => true)`.

## 3. Routes: a trailing slash is exact

`'/api/'` matches only `/api` (RC1 read it as `/api/*`). Write `'/api/*'` for a prefix.

## 4. Hosted verify with a resource needs the secret key

`POST /api/v1/gate/verify` with `path`, `method` or `environment` is answered only with `Authorization: Bearer sk_…`
(otherwise `secret_key_required`). The SDK and the PHP drop-in always send it; only code calling the endpoint directly from
a browser or with a pass alone is affected. Identity-only checks are unchanged.

## 5. Revocation and other changes: error semantics

| Response | Meaning | What to do |
|---|---|---|
| `200` | The change is live and recorded in every durable store (journal, snapshot, revocation ledger); any recovery preserves it. | none |
| `503 not_durable` | The change is live now (a revoked key is denied immediately) but not yet durable. | Repeat the same request until it answers `200`. The dashboard shows a warning until then. |
| `400 permissions_required` / `expiry_required` | A reactivation without explicit grants or expiry. Nothing changed. | Send the grants and `expires_at`. |
| `409 key_changed` / `state_changed` | The key or site changed while your request was in flight (or since you loaded it, with `if_rev`). Nothing changed. | Reload and retry. |
| `409 site_busy` | Another change for the site was in progress. Nothing changed. | Retry. |
| `503 access_unavailable` | The access store cannot be read or restored; every request for the site is denied. | Retry later; contact support if it persists. |

After a restore that cannot establish the latest state, keys that were not revoked are **held** (`pending_approval`,
shown as "recovery hold") and denied by the hosted API and by every self-verify client (no client change needed). Review
each key and re-approve it with explicit grants (contract §6.6). Revoked keys stay revoked, and restoring an older backup
cannot bring back access revoked later: a separate revocation ledger revokes or holds those keys again.

Self-verify clients see a revocation or a hold at their next policy refresh (60 s; at most the policy TTL, 600 s). If that
window matters, use hosted verification for the affected routes.

## 6. Checklist

- [ ] No key with `environments: []` that you meant as "any" (use `['*']`).
- [ ] Every environment-restricted integration sets its environment in server configuration.
- [ ] No route written `'/x/'` meant as a prefix.
- [ ] Direct calls to hosted verify with a resource send the secret key from your server.
- [ ] Admin automation that reactivates keys sends `routes`, `methods`, `environments` and `expires_at`.
- [ ] Admin automation treats `503 not_durable` as "repeat", not as success, and retries `409 site_busy`.
- [ ] No hand-written policy key has extra fields inside `permissions`.
