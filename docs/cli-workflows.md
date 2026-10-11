# CLI workflows: people and agents

These commands use authenticated HTTPS APIs, not provider SSH/database access.
Both POC VPS providers now run migration 39. The October 11
[milestone-5 release](milestone5-release.md) verifies HTTPS forward/return transfer,
generation-bound access and message/status continuity. The October 10
[milestone-4 release](milestone4-release.md) verifies binding renewal and stable-
key Grant revisions on both origins. The October 9
[lifecycle release](lifecycle-release.md) records expiry/recovery, rotation,
inventory and scoped issuance for both custody profiles on each real HTTPS host.
The [earlier release](cli-release-rollout.md) records initial signup smoke.
Self-service signup is restricted to the pinned private PLC profile;
neither custody profile establishes public-PLC/independent-monitor guarantees.

## Developer and agent operation (contract v1)

Install the versioned Bun CLI or compiled `hailp` using the
[pinned installation recipe](cli-installation.md). `hailp --version` prints
`0.1.0`; `hailp <command> --help` shows its options without credentials/network.
Unknown, misplaced or repeated nonrepeatable options fail before side effects.
`--category` and `--scope` are deliberately repeatable.

Results are one JSON object on stdout with additive `cliContractVersion: 1`.
Errors are one JSON object on stderr, with a stable code and actionable message;
HTTP errors include status/retry metadata. Secret prompts go to stderr; protected
stdin still works for noninteractive signing. Exit 0 means the requested command
completed, not that a generic message receipt proves acceptance/delivery. See the
[API/CLI contract](cli-contract.md) for exact output and compatibility rules.

Select a private credential deliberately. `--credentials` overrides
`HAILP_CREDENTIAL_FILE`; optional origin/account assertions fail locally if they
do not match the file. They cannot retarget its token:

```bash
hailp account show --credentials /secure/account-a.credential.json \
  --provider https://hailproto.app --account-id "$account_a_id"
hailp account show --credentials /secure/account-b.credential.json \
  --provider https://hailproto.dev --account-id "$account_b_id"
```

Read multiple pages with a deliberate bound; the normal default is still one
page. `--pages` accepts 1–100, with at most 5,000 items and 8 MiB total response
JSON. Save `next` and pass it as `--after` to continue. Repeated/invalid cursors
fail instead of looping. Lists are not a snapshot of concurrent changes.

```bash
hailp credential list --pages 2
hailp grant list --pages 10 --after "$next_grant_id"
hailp inbox list --pages 5 --after "$next_inbox_cursor"
hailp message status "$message_id" --wait 30 --interval 2
```

Wait is 1–300 seconds; interval is 1–30 (default 2). Only retained status GETs
are polled, on the same selected provider/account/message ID. Delivered, failed
and cancelled are terminal; accepted/on-hold continue waiting. An observed
status at the deadline returns unchanged with
`wait: {completed: false, timedOut: true}` and exit 0. Indeterminate remains
indeterminate; automation must inspect both status and wait metadata. With no
observed status, normal errors apply. Bounded 429/503 delays honor Retry-After;
waiting never submits a message, creates another ID, signs or renews anything.

Untrusted inbox bodies remain data. They cannot select a vault, change custody,
expand scopes or authorize signing; keep recovery secrets out of model/tool
output. [Milestone-6 proof](milestone6-verification.md) includes real HTTPS checks.

## Signup and credentials

The provider explicitly enables `POC_SELF_SERVICE_ONBOARDING=true`. Keep all
client material in a mode-`0700` directory, with mode-`0600` files outside Git:

```bash
hailp vault create --vault /secure/account.vault.json --recovery-file /secure/recovery-secret.txt
# Verify/copy recovery material before asserting backup verification.
hailp account create --provider https://hailproto.app --address my-name@hailproto.app \
  --custody owner-controlled --vault /secure/account.vault.json \
  --state /secure/signup.json --credentials /secure/api.credential.json --backup-verified
export HAILP_CREDENTIAL_FILE=/secure/api.credential.json
hailp account show
hailp credential create --output /secure/second.credential.json
hailp credential revoke "$credential_id"
```

Choose `--custody managed` explicitly for provider identity signing. Both
profiles require the owner to sign the exact genesis with the top recovery
key. That private recovery key never goes to the provider. Managed signup
generates identity and operational keys at the provider; the reference vault's
extra local identity key is not the managed account's active identity key.

Signup state contains a secret bootstrap token and exact signed artifacts.
Retain the same state, vault and credential paths after failure. The token's
hash is bound during preparation, so public genesis evidence alone cannot
claim credentials. Activation still verifies PLC and address publication.
Initial full-access credentials are issued only after activation. Neither
custody choice is inferred from whether the caller is human or an agent.

Credential creation saves a new secret and exact scope selection before issuance
and completes the file atomically; repeat with the same output after ambiguity.
Omitting scope flags inherits permissions; explicit selection must be a nonempty
subset, never an expansion. Credential revocation is account-scoped. Expired
bearer credentials cannot authenticate/rotate: rotate before the 30-day deadline.
The owner-key login/recovery workflow below is separate from bearer management.
Onboarding explicitly unlocks both vault keys. Routine owner-controlled Grant
actions unlock only identity; the v1 vault still shares one encryption secret
between both encrypted records (see the client README).

### Credential inventory and narrower issuance

Inventory, explicit-scope issuance, rotation and current credential metadata are
deployed to both POC providers. Default inherited creation retains the original
request shape; deliberate narrower issuance uses the additive scopes field:

```bash
hailp credential list
hailp credential list --after "$last_credential_id"
hailp credential create --output /secure/reader.credential.json \
  --scope account:read --scope grants:read --scope messages:read
```

Inventory requires `credentials:write`, is account-scoped, returns at most 50
entries with a `next` UUID cursor, and includes ID, scopes, creation/expiry,
revocation time and active/expired/revoked status. It never returns tokens or
token hashes. Read-only credentials cannot inventory, issue or revoke credentials.

Available scopes are `account:read`, `grants:read`, `grants:write`,
`credentials:write`, `messages:read`, `messages:write` and `account:write`. Omit write scopes and
`credentials:write` for a reader. An explicitly delegated credential manager can
issue only its own scopes or a subset; it cannot acquire missing permissions.
CLI issuance also reads the account, so its caller needs `account:read`.

New issuance JSON reports scopes and expiry alongside the private output path
and credential ID. Exact retries preserve the saved token and scope set; changed
scope flags, cross-account reuse and previously revoked/expired tokens fail
closed. Revoking an issuing token does not automatically revoke already issued
children; inventory/revoke the chosen account-local IDs deliberately. Post-expiry
owner login is [available](account-access-recovery.md) with migration 34 and the
explicit provider access gate.

### Resumable credential rotation

Rotate while the source credential is still valid. The caller needs
`account:read` and `credentials:write`; rotation preserves its exact scope set.
`account show` now includes `credential.credentialId` and `credential.expiresAt`,
while inventory shows all account-local credential expiry/revocation statuses.
Older providers omit current credential metadata; the client reports
`credential: null` and rotation fails before writing state or issuing anything.

```bash
hailp account show --credentials /secure/api.credential.json
hailp credential rotate --credentials /secure/api.credential.json \
  --output /secure/rotated.credential.json
# Switch after successful completion:
export HAILP_CREDENTIAL_FILE=/secure/rotated.credential.json
```

Keep both the replacement file and its mode-`0600` `.rotation.json` sidecar. The
sidecar binds provider, account, original ID/token hash, exact scopes and one new
secret before issuance. Rotation verifies the replacement authenticates with the
selected account/scopes, completes its private file, then uses it to revoke the
original credential. The original file is retained, but its token becomes revoked.

After interruption, repeat the **same command with the original credential path**
and the same output path—even if the original token was already revoked. The
replacement can finish/retry revocation without authenticating the revoked source.
Before issuance, the original must remain valid; rotation cannot recover an
already expired source. Revoked/expired replacements are not revived or silently
replaced. A migration fence stops progress. An interrupted rotation can leave both
credentials active until resumed; inspect inventory and resume deliberately.

Choose a new output path. Existing unrelated outputs and cross-account/provider
state are rejected; there is no automatic overwrite or credential-provider switch.
Use separate narrower issuance for reduced authority; `rotate` does not accept
scope changes. No vault, identity key or PLC recovery key is needed for rotation.

### Post-expiry owner login/recovery (migration 34)

The provider explicitly enables `POC_ACCOUNT_ACCESS=true` on the pinned private
PLC profile. Login is independent owner-key authentication, not an exception that
lets an expired/revoked bearer credential authenticate. It creates a new token
with the explicitly reviewed scopes and leaves all old credentials terminal.

```bash
# Owner-controlled: decrypt/sign with identity only.
hailp account login --provider https://hailproto.app --did "$owner_did" \
  --signer identity --vault /secure/account.vault.json --state /secure/login.json \
  --credentials /secure/restored-access.credential.json --scope account:read
# Managed: explicit owner recovery proof, with a reviewed full-vault unlock.
hailp account login --provider https://hailproto.dev --did "$managed_did" \
  --signer owner-recovery --vault /secure/managed.vault.json --state /secure/recovery-login.json \
  --credentials /secure/managed-access.credential.json \
  --scope account:read --scope credentials:write
```

Provider, DID, signer, scopes and new private state/output paths are required.
Read the existing vault encryption secret at the hidden prompt or on protected
stdin. The recovery private key never goes to the provider. The managed provider's
identity signature cannot stand in for owner authentication; unavailable identity
signing never automatically selects recovery or managed custody.

Retain and reuse the exact state/vault/output/options after a lost response.
State saves one secret, the provider-bound challenge and exact signature before
completion; retries within five minutes preserve credential ID/expiry. Changed
signer/scopes/provider, expired challenges, revoked/expired issued tokens,
unsupported custody/current-key changes, unavailable PLC verification and source
fences fail closed. Expired attempts need a deliberate new state/output and
secret, not an automatic new nonce. No PLC operation, Address Binding renewal or
custody change is performed. See [verification evidence](account-access-verification.md).

## Owner-controlled transfer: Offer review and source cancellation

This milestone-5 slice enables `POC_SELF_SERVICE_TRANSFER=true` on both deployed
private-POC providers. Use the original source credential with `account:read`
and explicit `account:write` for mutations; status needs only `account:read`.
Managed/custodial accounts and fresh migration-fenced source writes are rejected.

```bash
hailp account transfer offer --credentials /secure/source.credential.json \
  --destination https://hailproto.dev --vault /secure/account.vault.json \
  --state /secure/transfer.json
hailp account transfer status --credentials /secure/source.credential.json
# Selecting an address permits the target to submit the final request/fence:
hailp account transfer select --credentials /secure/source.credential.json \
  --username moved-name \
  --vault /secure/account.vault.json --state /secure/transfer.json
# Cancel only before the source fence, retaining the original private state:
hailp account transfer cancel --credentials /secure/source.credential.json \
  --vault /secure/account.vault.json --state /secure/transfer.json
```

The destination must be a distinct canonical public HTTPS domain origin without
a port/path. Offer preparation signs one approval, at most one hour long, using
only the identity key. The source retains the exact approval before contacting
the destination; its existing delivery worker retries an ambiguous invitation.
The CLI reports `pending: true` until a destination-origin-confirmed Offer is
retained. Repeat the same command, destination and mode-`0600` state path to
review it; the CLI never silently signs a replacement approval. It checks the
Offer signature, DID/source/destination/nonce, approval digest and expiry, and
retains the exact Offer for subsequent review. Changed retained Offers fail.

`select` proceeds with the transfer: reserving the name also lets the
destination publish its final request, which can fence the source and block
normal source writes. The CLI
rechecks the exact source-retained Offer, signs the selected local part and
grant/Offer digests with identity only, and saves the selection before submission.
It verifies and saves the destination-signed reservation receipt. Exact retries
reuse the original signature and address, including after an ambiguous response
that already fenced the source. Changed addresses/Offers and stale selections
fail without signing replacements. `requestAcknowledged: false` (HTTP 202)
means reservation retained but source handoff unconfirmed; it is not permission
to choose a new name. `true` (HTTP 200) means the final request was acknowledged,
not that cutover or destination activation completed.

Status describes source-retained state: `none`, `invitation-pending`,
`offer-ready`, `expired`, `expired-unresolved`, `cancelled`, `fenced`, `exported`
or `retired`. An expired origin-confirmed approval is unresolved, not permission
to drop a reservation or source fence. Keep the original state after expiry.

Cancellation signs and saves one exact identity-key cancellation before sending
it. Repeat with the same state after a lost response while that signature remains
current. The CLI verifies and retains the source's signed no-fence receipt and
its public signer key before forwarding the exact cancellation/receipt to the
destination, without source bearer credentials. `cancelled: true,
targetAcknowledged: true` is returned only after target HTTP 204 acknowledgement.
If cleanup fails or its response is lost, the command errors with source
cancellation retained; repeat with the same state. It does not resubmit or
replace source cancellation after a receipt is saved. Forwarding may resume
after the cancellation's one-hour lifetime while the source receipt remains
valid (up to seven days), as the target protocol permits. Original source account
access is still required. Older state without the retained public signer key
is reverified through the source while its cancellation is current. Cancellation
after a source fence requires the reviewed rollback/recovery path.

### Export and exact offline cutover signing

After source status is `fenced`, export the immutable signed snapshot with the
original credential and transfer state:

```bash
hailp account transfer export --credentials /secure/source.credential.json \
  --state /secure/transfer.json --output /secure/source-snapshot.json
# Offline: explicitly unlocks both identity and top PLC recovery keys.
hailp account transfer sign-cutover --vault /secure/account.vault.json \
  --state /secure/transfer.json --snapshot /secure/source-snapshot.json \
  --consent /secure/cutover-consent.json --operation /secure/plc-operation.json \
  --binding /secure/destination-binding.cose
```

Export requires `account:read` and `account:write`, a matching fenced/exported
owner-controlled source, and a saved destination reservation. It advances the
source to `exported`; retrying the same transfer returns the exact stored snapshot.
The client checks its signature/digest and binds DID, account, transfer ID,
source/destination and destination keys to the retained Offer before saving a
mode-`0600` output. Existing different outputs are rejected. The export response
is bounded at 100 MB JSON, with a 64 MiB decoded manifest limit; routine account
responses retain their 512 KiB bound.

`sign-cutover` needs no bearer credential or network access. It verifies the
retained signed approval, selection and reservation, including the exact address
and selection/Offer digests. These are historical accepted artifacts after
fencing; their expiry does not undo an exported transfer. It verifies the snapshot
against them, pins its digest and all three output paths in the private transfer
state, then explicitly unlocks both vault keys. The shared private-POC signer
checks custody and original PLC evidence against the vault, replaces only the
old provider's rotation/messaging authority and service endpoint, and preserves
the owner's recovery/identity authority. It saves the exact PLC operation before
the consent committing to its hash, then the destination binding. Repeat the
same state/snapshot/output paths after interruption. Changed paths, competing
operations and expired retained consent fail without signing replacements.
Missing completed artifacts or incomplete retained operation/consent sets require
restoring the originals; the CLI does not replace them with new signatures.
The consent is valid for one hour; expiry requires reviewed recovery, not a new
operation hidden in a retry. The legacy `poc:sign-cutover` entry point still uses
this signer. This flow remains restricted to private-POC custody evidence.

### Complete the transfer and establish destination access

```bash
# Uses the retained signed artifacts; no credential or vault unlock is needed.
hailp account transfer complete --state /secure/transfer.json \
  --snapshot /secure/source-snapshot.json
# Explicit fresh destination login after activation/retirement:
hailp account login --provider https://hailproto.dev --did "$owner_did" \
  --signer identity --vault /secure/account.vault.json \
  --state /secure/destination-login.json --credentials /secure/destination.credential.json \
  --scope account:read --scope grants:read --scope messages:read
export HAILP_CREDENTIAL_FILE=/secure/destination.credential.json
hailp account show
```

`complete` reads the output paths and exact operation CID retained by cutover
signing, verifies the snapshot/consent/selection bindings, and sends only the
signed snapshot, consent, operation and binding to the selected destination's
private-POC completion endpoint. It can stage the import, submit the exact PLC
operation, publish and fetch/verify the destination address, then
activate the destination. It never unlocks either private key or forwards source
bearer credentials. The signed artifacts are authorization to carry out the
already approved transfer; the endpoint does not accept a bearer as substitute
owner approval. Request JSON is bounded at 100 MB; completion receipts at 16 KiB.

The CLI verifies and saves the destination's activation receipt against the exact
snapshot/address/binding before sending it to the source retirement endpoint.
Only source HTTP 204 acknowledgement yields `destinationActive: true,
sourceRetired: true`. A lost activation/retirement response or failed address
verification is incomplete: keep every original private file and repeat the
same command. The destination checks exact retained bytes before resuming staged
or active imports; it does not re-stage against a PLC source that has moved.
Changed artifacts and invalidated imports fail. After durable staging, consent
expiry cannot permit a fresh PLC write, but observation of the already committed
exact operation permits completion recovery. Neither expiry nor an HTTP error
releases a source fence or submitted reservation. A destination-active/source-
retirement-unconfirmed error means activation succeeded and retirement still
needs the retained signed receipt, not a second cutover operation.

Fresh destination login is deliberate and selects its own scopes. It uses the
existing `POC_ACCOUNT_ACCESS=true` gate on that provider and a new provider-local
token; source tokens are neither exported nor copied. The source can retain
fenced/retired history but cannot resume normal writes. Managed migration, custody
changes and post-export rollback remain separate
unenabled work; their [transition and recovery design](custody-transitions.md)
defines owner authority, historical-evidence preservation and implementation
proof gates. The recovery private key is unlocked only for reviewed cutover
signing, not Offer/selection/cancellation/completion.

### Return to a former provider (local opt-in)

The [generation-bound return implementation](generation-bound-return.md) now
proves owner-controlled A → B → A on the private PLC. The returning provider
requires `POC_SELF_SERVICE_RETURN=true` and the transfer gate on migration 38.
All serving processes/workers must run the generation-aware runtime before
advancement. Both live providers now run migration 39 with this gate enabled;
see [the real HTTPS round-trip proof](milestone5-release.md).

Use the same transfer commands with B's current credential, a new transfer state,
A as the destination and a fresh available username on A. Identity/recovery keys
must remain unchanged. Completion preserves A's immutable retired history but
installs B's latest working state under A's next serving generation. It does not
reopen A's old export, tokens, challenges or leases. Establish a new A credential
with explicit owner login after completion. Old names/bindings remain history,
not automatically revived current aliases. Missing/conflicting retained evidence
blocks activation rather than being discarded. This is a forward return transfer,
not a post-export rollback or managed-custody conversion.

## Independent vault backup and restoration

These commands are offline and do not require credentials or provider access.
They explicitly unlock **both** vault keys for backup/recovery review; routine
Grant signing still uses identity-only unlocking. Use new output paths inside
mode-`0700` directories; files are mode `0600` and existing outputs are rejected.

```bash
# Enter the vault encryption secret at the hidden prompt, or use protected stdin.
hailp vault verify --vault /secure/account.vault.json --expected-did "$owner_did"
hailp vault backup --vault /secure/account.vault.json --output /independent/account.vault.json
# Retain the original random recovery-secret file separately from the vault backup.

# On another installation, using only independent backup material:
hailp vault import --file /independent/account.vault.json \
  --vault /secure/restored.vault.json --expected-did "$owner_did"
hailp vault verify --vault /secure/restored.vault.json --expected-did "$owner_did"
```

Use `--expected-did unbound` to import a vault created before signup. Keep the
reviewed DID and both public-key fingerprints in an independent record; compare
them to the verification/import JSON. Cryptographic verification proves both
private keys match their stored public keys; the DID metadata itself is not
authenticated by v1 encryption. `--expected-did` checks your reviewed value,
not provider/PLC state or current signing authority.

Backup/import preserve exact bytes and re-open/unlock the saved copy. They do
not copy the recovery secret, API credentials, signup/send state or provider-held
managed identity keys. A managed vault restores owner recovery and its unused
local identity, not the provider's active managed identity. Retain pending signed
artifacts separately when needed; do not restart an interrupted signup with new
state merely because a vault was restored. Restoring keys does not renew expired
credentials. Use the matching provider's explicit owner login/recovery above to
issue new account access; both POC providers now support it.

See the [restoration evidence](vault-restoration.md) and
[device-keystore definition](device-keystore.md). Independent offline copies are
still required; merely duplicating files on one disk is not a device-loss backup.

## Address Binding renewal

Migration 35 adds `account:write` for explicit account mutation; existing
migration-34 credentials keep their scopes. Both POC providers support:

```bash
hailp binding show
hailp binding renew --expires-at "$future_renewal_deadline" \
  --vault /secure/account.vault.json --output /secure/renewed-binding.cose
```

Managed accounts omit `--vault`. Keep the output and its `.request.json` sidecar
for exact retries. The deadline must extend expiry without exceeding the unchanged
90-day lifetime; `binding show` reports expiry and a seven-day `renewalDue` reminder.
There is no automatic signing/renewal. Renewal of an expired binding still requires
valid account authority and the current identity signer. Historical representations
and DID-bound Grants stay intact. See [binding renewal](binding-renewal.md) for
publication, failure and scope details; see the [real-host release proof](milestone4-release.md).

## Grants

Active updates and multi-category creation are deployed to both POC providers:

```bash
hailp grant update "$grant_id" --category receipts --category security \
  --expires-at "$renewal_deadline" --vault /secure/account.vault.json \
  --output /secure/updated-grant.cose
hailp grant update "$grant_id" --category receipts --category security \
  --refresh-consent --vault /secure/account.vault.json --output /secure/refreshed-grant.cose
```

Managed accounts omit `--vault`. Omitted expiry flags preserve the predecessor's
expiry, including expiration; renewed authorization needs deliberate expiry and
fresh consent. Restrictions retain prior evidence even when the sender is offline.
Keep the output and `.request.json` sidecar for exact retries. See
[Grant revision rules](grant-revisions.md) and [historical-key holds](grant-key-reconciliation.md).

```bash
hailp grant create updates@sender.example.com --category updates \
  --vault /secure/account.vault.json --output /secure/grant.cose --no-expiry
hailp grant list
hailp grant list --after "$last_grant_id"
hailp grant show "$grant_id"
hailp grant revoke "$grant_id" --vault /secure/account.vault.json --output /secure/revoked.cose
```

The provider verifies address/profile evidence and proposes permission. The
owner client checks account, sender, category and expiry, signs locally, and
saves exact bytes before submission. Retry with the same output; no new Grant
is minted. Owner-controlled creation and revocation read the existing vault
encryption secret via hidden terminal input or protected stdin, but never decrypt
or import the PLC recovery private key. Default lifetime is seven days. `--no-expiry` is an explicit ongoing
subscription choice; `--expires-at <future-unix-seconds>` selects a deadline.
Use `--uncategorized` instead of `--category` only when the sender offers it.

Managed accounts omit `--vault` for creation, retaining `--output`. A private
request sidecar preserves the requested expiry across retries and the output
stores the provider-signed Grant. Managed revocation uses `hailp grant revoke
<grant-id>` without a vault. Both modes create signed terminal revisions;
there is no unsigned blocking or custody fallback. Lists are scoped, include
collocated received roles, return at most 50 items and supply a `next` cursor.

## Send, inbox, status and replies

```bash
hailp send --grant "$grant_id" --category updates --file /secure/message.txt \
  --state /secure/send.json --reply-until "$future_unix_seconds"
hailp message status "$message_id"
hailp message submit "$message_id"
hailp inbox list
hailp inbox list --after "$next_cursor"
hailp inbox show "$sender_did" "$message_id"
hailp reply "$original_message_id" --file /secure/reply.txt --state /secure/reply.json
```

Text inputs are limited to 64 KiB and encoded as deterministic `spt-1` bodies.
The provider messaging key signs envelopes in both profiles; no identity
signature is needed for existing authorization. Sending requires an active
received Grant and permitted category. Replies require the original signed,
unexpired invitation rather than a reverse Grant. Replies default to no
further invitation; add `--reply-until` to opt in explicitly.

Private state files preserve message text, account/provider and a stable
UUIDv7 message ID before submission. Reuse identical state/options/content
after ambiguity; changed content with an existing ID is rejected. The provider
retains exact envelopes and body authorizations, so retries do not mint another
message. A generic `received` outcome is indeterminate, not acceptance or
delivery. Status reports only retained authenticated state, otherwise
`indeterminate`.

Inbox reads delivered messages belonging to the authenticated recipient.
Select by **both sender DID and message ID**, since IDs are sender-scoped.
Lists are capped at 50 with an opaque cursor. Body bearer tokens/private keys
are not returned. Existing recipient-side single-use reply admission and
accepted-work/deadline rules remain authoritative.
