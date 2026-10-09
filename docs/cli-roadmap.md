# hailp CLI roadmap

## Goal and boundaries

Make `hailp` a practical HTTPS account client for developers, people and agents,
without requiring a UI, provider SSH access or database credentials for normal
use. Native provider CLIs and applications may use the same account API.
Federation remains the interoperable protocol boundary; the reference account
API is not yet a mandatory cross-provider client API standard.

Support explicit owner-controlled identity and managed identity custody. The
preferred managed profile keeps the top PLC recovery key with the owner.
Custody must never be inferred from whether a caller is human or an agent, or
silently changed when a signing device is unavailable. Revocation stays a
signed terminal revision; the optional unsigned local-blocking feature is
excluded.

This roadmap records priorities and acceptance conditions, not release dates.
Use [CLI workflows](cli-workflows.md) for commands available today. Proposed
commands below are design examples, not implemented interfaces.

## Implemented local baseline

Baseline: client `5cc0960`, provider `19a9313`, provider migration 33. These
commits are tested local implementation, not proof of VPS rollout or production
readiness. Check deployment separately before trying a new API on a live host.

- [x] Unified `hailp` executable, JSON results/errors and private credential files.
- [x] Vault creation and resumable private-PLC account signup with explicit
  owner-controlled or managed custody; owner-controlled top recovery in both.
- [x] Account details and scoped credential creation/revocation with inherited
  permissions, hashing, expiry and account isolation.
- [x] Grant create/list/show/submit/revoke, local owner signatures or explicit
  managed signing, with retained artifacts for retries.
- [x] Text send, invited reply, message submit/status and scoped inbox list/show,
  stable sender-scoped message IDs and bounded pagination.
- [x] HTTPS verification, redirect rejection, input/response bounds, fences and
  exact-retry integration proofs. Recorded gates: 161 provider tests, including
  53 PostgreSQL integrations, and 3 client tests; typechecks/builds passed.

Current limits: self-service signup is opt-in private PLC only; API credentials
expire after 30 days and must be rotated while valid; messages accept text
files up to 64 KiB; Grant/inbox lists return at most 50 items. The reference
vault still unlocks identity and recovery keys together. Public onboarding,
expired-credential login/recovery, binding renewal and managed migration are
not implemented.

## Prioritized milestones

### 1. Validate and release the current slice

- [ ] Rehearse migrations 32–33 against restored deployment copies and verify
  compatible images, backup retention and provider-local credential behavior.
- [ ] Roll providers individually, verify readiness, then exercise disposable
  owner-controlled and managed CLI accounts on the POC's real HTTPS endpoints.
- [ ] Verify signup interruption, credential isolation, Grant retries, send/
  inbox/reply and source fencing across process restarts; retain evidence.
- [ ] Review current authorization, validation and error boundaries before
  expanding the externally exposed API; calibrate limits for the target host.

**Acceptance:** a fresh CLI installation can complete the documented workflows
against the deployed private POC without disabling TLS verification or exposing
user recovery material. No claim of independent production monitoring follows
from a same-VPS demonstration.

### 2. Separate routine signing from recovery

- [ ] Add an identity-only vault unlock/signing path for routine owner-controlled
  Grant actions; keep recovery-key unlocking explicit for reviewed recovery/
  onboarding/transfer operations.
- [ ] Define convenient device-keystore protection without assuming a WebAuthn
  credential can directly produce Hail's raw Ed25519 signatures.
- [ ] Add backup verification/import workflows and prove restoration on a second
  installation/device, independent of provider-held data.

**Acceptance:** ordinary Grant actions never decrypt/load the PLC recovery key;
losing one client installation does not destroy the only recoverable identity.
The vault format remains an implementation detail, not a protocol requirement.

### 3. Complete credential and account access lifecycle

- [ ] Design authenticated login/recovery after credentials expire, including
  managed accounts whose active identity key is provider-held. Keep account
  access recovery distinct from PLC identity recovery and custody changes.
- [ ] Add credential inventory and deliberate narrower-scope issuance; ensure
  an agent or read-only credential cannot gain additional authority.
- [ ] Improve rotation workflows and expiry visibility while preserving private
  outputs and exact recovery from interrupted issuance.

**Acceptance:** an authorized owner can restore account access without silently
replacing top recovery authority, reviving revoked credentials or importing an
owner's recovery private key into the provider. Scope escalation is rejected.

### 4. Address renewal and complete Grant revisions

- [ ] Implement signed Address Binding renewal, expiry visibility/reminders and
  safe publication retries; retain the current 90-day maximum unless the
  specification is explicitly revised.
- [ ] Add active Grant updates: category changes, explicit renewal and consent
  refresh. Support multiple selected categories without introducing wildcards.
- [ ] Require fresh verified evidence/consent for expanded authorization; retain
  prior consent for restrictions/revocation without relying on sender availability.
- [ ] Define historical-key reconciliation before supporting identity rotation
  over unacknowledged predecessor revisions.

**Acceptance:** expired signers/permissions do not cause silent renewal;
restrictions remain unilateral; conflicting revisions never overwrite signed
history. Existing DID-bound Grants are not transferred or revoked merely
because an address binding expires or an address changes holder.

### 5. Bring transfer and custody transitions into hailp

- [ ] Integrate the existing owner-controlled reference transfer tools into
  cohesive API-driven commands for Offer review, address selection, status,
  exact cutover signing and completion. Example: `hailp account transfer …`.
- [ ] Design explicit owner-controlled ↔ managed custody changes and managed
  provider migration, including removal/rotation of an old provider's identity
  authority and preservation of Grant/binding historical evidence.
- [ ] Prove return to a former provider with retained retired history and
  coordinated post-export recovery/rollback before enabling those paths.

**Acceptance:** one active owner remains; accepted message/status/outbox
responsibilities survive; expiry alone never releases an exported fence or
submitted reservation. Existing owner-controlled transfer proof is not proof
of managed migration. Credentials remain provider-local and are not forwarded
to a target learned from a redirect.

### 6. Stabilize developer and agent operation

- [ ] Define/version the account API and CLI JSON/error contract; add command-
  specific help and strict invalid-option behavior, plus reliable version reporting.
- [ ] Add deliberate provider/account selection without leaking credentials to
  another origin; retain private files and useful noninteractive operation.
- [ ] Add bounded status waiting and pagination convenience without converting
  indeterminate receipts into acceptance promises or retrying with new IDs.
- [ ] Document/install a reproducible CLI package with pinned dependencies and
  a smoke test for a fresh environment. Consider standalone distribution only
  if users need it; Bun-based operation is the current baseline.

**Acceptance:** people and agents use the same authorization rules, stable
machine-readable results and actionable errors. Untrusted message content
does not become signing authority; raw private keys are not model/tool output.

### 7. Production federation gate

- [ ] Complete reviewed managed-profile specification/conformance rules and
  public `plc.directory` onboarding with non-disposable identity/recovery material.
- [ ] Provision independent monitor/read paths and verified bootstrap checkpoints;
  test alerts, disagreements, gaps and recovery within PLC's recovery window.
- [ ] Prove cross-host recovery, historical signed-object audit behavior, load
  limits and restoration with real independently operated infrastructure.

**Acceptance:** portable/managed claims match tested custody and recovery
guarantees. Private PLC, local backup flags and provider-hosted monitors are
never relabeled as independent production evidence.

## How to work through this roadmap

Ship one coherent API-plus-CLI slice at a time, reusing existing provider
services and signing primitives. Each milestone needs focused regression proof,
the nearest affected typecheck/build/test gates and updated workflow docs.
Reuse still-current verification results; do not expand scope after acceptance
passes. Commit working slices separately from deployment changes.

Dependencies:

- [Provider account API](https://github.com/j4crev/hail-server-ts#hailp-account-api).
- [Custody and implementation decisions](https://github.com/j4crev/hailproto/blob/main/docs/production-portable-custody.md).
- [Authoritative onboarding rules](https://github.com/j4crev/hailproto/blob/main/spec/account-onboarding.md).
- [Grant lifecycle](https://github.com/j4crev/hailproto/blob/main/spec/grants.md).
- [Address Bindings](https://github.com/j4crev/hailproto/blob/main/spec/address-binding.md).
