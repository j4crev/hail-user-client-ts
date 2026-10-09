# CLI workflows: people and agents

These commands use authenticated HTTPS APIs, not provider SSH/database access.
Both POC VPS providers now run migration 34. The October 9
[lifecycle release](lifecycle-release.md) records expiry/recovery, rotation,
inventory and scoped issuance for both custody profiles on each real HTTPS host.
The [earlier release](cli-release-rollout.md) records initial signup smoke.
Self-service signup is restricted to the pinned private PLC profile;
neither custody profile establishes public-PLC/independent-monitor guarantees.

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
`credentials:write`, `messages:read` and `messages:write`. Omit write scopes and
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

## Grants

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
