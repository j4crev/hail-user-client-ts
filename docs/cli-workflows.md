# CLI workflows: people and agents

These commands use authenticated HTTPS APIs, not provider SSH/database access.
The local implementation requires migration 33. It is not yet deployed to the
POC VPS. Self-service signup is restricted to the pinned private PLC profile;
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

Credential creation saves a new secret before issuance and completes the file
atomically; repeat with the same output after ambiguity. Permissions are
inherited, never expanded. Credential revocation is account-scoped. Expired
credentials cannot log in/rotate: rotate before the 30-day deadline. A future
account-recovery/login workflow is separate from this authenticated management.
The combined identity/recovery vault unlock limitation remains documented in
the client README.

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
is minted. Default lifetime is seven days. `--no-expiry` is an explicit ongoing
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
