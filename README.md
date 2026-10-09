# Hail User-Key Reference Client

Platform-specific **reference client and test driver** for the portable
custody outcomes in `../hailproto/spec/account-onboarding.md`. Future mobile,
browser and hardware-backed clients may implement the same signed objects and
recovery semantics using their own secure storage. No Hail protocol rule
requires Bun, a desktop OS or this vault-file format.

The client generates the user's top PLC P-256 recovery key and distinct
Ed25519 `#hail-identity` key locally. It encrypts both private keys using
AES-256-GCM with a uniformly generated 256-bit recovery secret, separate
nonces and role-bound authenticated data. No user private key is transmitted
to or stored at a Hail provider. A provider's independent lower-priority PLC
and messaging keys belong on its own host. The user must retain an independent
copy of the encrypted vault and verify recovery with the random secret on
another installation before public account activation.

This is not a finished production client: there is no OS-keystore or hardware
integration, authenticated multi-device transfer, public PLC write-registry
ceremony, Grant/Address Binding review UI, or independently provisioned
monitor. The original Alice/Bob POC DIDs were created custodially in a private
directory; creating this vault does not convert them. Fresh user-key-held
private-PLC DIDs have completed onboarding, Grant signing and provider transfer
with pending-message continuity. The same-VPS POC monitor proves functionality,
not independent monitoring or public portable custody.

Deployment instructions are in the [provider runbook](https://github.com/j4crev/hail-server-ts/blob/main/deploy/poc/README.md)
and [monitor runbook](https://github.com/j4crev/hail-plc-monitor-ts/blob/main/deploy/poc/README.md).
Run this client on the user device, not in either provider container; only
reviewed public/signed artifacts are transferred to providers. See the
[recovery checkpoints](https://github.com/j4crev/hailproto/blob/main/docs/production-portable-custody.md#resuming-a-private-plc-poc-ceremony)
before retrying an interrupted transfer.

### Reference vault limitation: separate routine signing from recovery

**Follow-up before production:** `unlockUserVault()` currently decrypts and
loads both the `#hail-identity` key and the top PLC recovery key, even for a
routine Grant signature or revocation. Only the identity key signs those
objects, but the recovery key is still present in memory. This reference/test
vault behavior does not meet the production requirement to keep PLC recovery
authority offline during routine Grant signing (`spec/account-onboarding.md`,
User Key Storage And Recovery).

Add a separate identity-only unlock/signing path, with convenient device
keystore protection, and keep PLC recovery unlocking explicit for reviewed
onboarding, transfer or recovery. Do not solve this by giving either private
key to the provider. The vault format remains a reference implementation
detail; provider-independent backup and second-device recovery still need
their own proof.

See the [custody and offline-operation reference](https://github.com/j4crev/hailproto/blob/main/docs/production-portable-custody.md#key-custody-in-plain-language)
for signing-role tables, Grant/binding renewal requirements and the verification
plan. Routine provider messaging does not require the user signer to stay
online; fresh consent and Address Bindings still require its signature.

## hailp Account CLI

The first API-driven slice is available as `hailp` in this repository. It uses
the provider's authenticated account API over HTTPS, returns JSON on stdout,
and emits JSON errors on stderr with a nonzero exit. It currently operates on
existing active accounts and opt-in **private-PLC self-service signup**. Grant
creation/listing, credential management, sending, inbox reads and invited replies
are implemented. See [CLI workflows](docs/cli-workflows.md) for both custody
profiles. Public-PLC onboarding, expired-token recovery and binding renewal
remain separate work.

See the [CLI roadmap](docs/cli-roadmap.md) for the implemented baseline,
prioritized milestones and acceptance conditions for remaining work.

After building the sibling libraries and installing dependencies as below,
either invoke `bun run hailp -- ...` or install the local executable:

```bash
bun link
hailp --help
```

For this bootstrap slice, the provider operator issues a mode-`0600` credential
file with `account:credential-create` (see the provider README), then transfers
it privately to the account owner. The file binds a random bearer credential
to one provider HTTPS origin and account; only its hash is stored in the
provider database. Credentials expire after 30 days. Read access is the default;
Grant submission/revocation requires the explicit `--write-grants` issuance
option. `--full-access` operator issuance or self-service signup also grants
message and credential-management scopes. Full-access clients can create and
revoke credentials through the API; rotate before expiry. This is not an
expired-token recovery/login mechanism. Treat the file as a secret; do not pass its token
value as a command-line argument or put it in a URL.

```bash
export HAILP_CREDENTIAL_FILE=/secure/user-controlled/api.credential.json
# Alternatively add --credentials /secure/user-controlled/api.credential.json.
hailp account show
hailp grant show "$grant_id"
hailp grant show "$grant_id" --output /secure/user-controlled/current.grant.cose
hailp grant submit /secure/user-controlled/user-signed.grant.cose
hailp grant revoke "$grant_id" \
  --vault /secure/user-controlled/alice.vault.json \
  --output /secure/user-controlled/revoked.grant.cose
```

`grant show --output` creates a new immutable private file and refuses to
overwrite an existing path. Displayed Grant JSON is diagnostic; the retained
COSE bytes are the signed representation. Read-only display checks format,
ID and digest against the authenticated provider response; revocation also
verifies the identity signature locally against the vault. A token does not
authorize changing an unrelated account's Grant, and a local grantee copy is
not authority to revoke the grantor's lineage.

For revocation, enter the vault recovery secret through the existing hidden
terminal prompt or protected stdin. The CLI obtains the current signed Grant,
checks the authenticated account/vault/Grant relationship, saves its signed
terminal successor **before** submission and sends only those bytes. If a
response is lost, repeat the same command and output path: the CLI can match
the provider's already committed terminal revision and reuse the saved bytes.
Conflicting output files or a changed identity key fail closed. The current
reference vault still loads both user keys; the identity-only unlock caveat
above remains applicable.

A successful submission reports `publication: "durable"`: local signed state
and publication responsibility are retained, not necessarily acknowledged by
the sender yet. Publication retries are handled by the provider. Bearer
credentials do not replace identity signatures in owner-controlled accounts.
Explicit managed accounts request provider identity signatures instead; there
is no unsigned blocking or automatic custody fallback.

Requests use the credential file's origin with certificate validation, no
redirects and a 20-second request deadline. Responses are bounded at 512 KiB;
signed Grants at 256 KiB. Moving providers requires a new provider-local
credential, not forwarding a token to an endpoint supplied by a redirect.
Keep vaults, credentials and signed artifacts in private storage outside Git.

## Local Reference Flow

Build the sibling codec and pinned PLC library, then install and test:

```bash
bun run --cwd ../hailproto/packages/hail-codec-ts build
pnpm --dir ../did-method-plc build
bun install
bun run typecheck
bun run test
```

Generate a new vault **outside** any provider checkout. The command creates
one encrypted mode-`0600` file and prints the random 256-bit recovery secret
once to the user's terminal. The secret is not stored with the ciphertext:

```bash
bun run vault:create -- /secure/user-controlled/alice.vault.json
bun run vault:verify -- /secure/user-controlled/alice.vault.json
```

`vault:verify` prompts without echo on a terminal; it can also read the
recovery secret on protected stdin. Never put the secret on the shell command
line, send it to a provider, or store the only backup on the provider. Copy
the encrypted vault independently and repeat verification on another device
before publishing a DID. The library signs regular PLC creation or migration
operations with the user recovery key and Grants, Address Bindings and
portable-migration consent with the separate user identity key. It also signs
a short-lived, destination-scoped **Transfer Grant** before the old provider
can offer a transfer to the new provider:

```bash
bun run transfer:grant -- /secure/user-controlled/alice.vault.json \
  https://old.example.com/hail new.example.com \
  /secure/user-controlled/alice.transfer-grant.json
```

The current reference CLI takes the previous service base as an argument; the
operator must supply it from validated current PLC state. It does not perform
automatic provider discovery. In a finished client, that value should come
from DID resolution rather than free-form user input. The user chooses the
destination domain `new.example.com`; the CLI derives its well-known invitation
endpoint and `/hail` service.
Submit the same signed grant to the current source (or repeat after `202`
until the origin-verified Offer is available):

```bash
bun run transfer:submit-grant -- \
  /secure/user-controlled/alice.transfer-grant.json \
  /secure/user-controlled/alice.transfer-offer.json
```

The source verifies and stores the grant and sends its signed invitation to
the named domain; the target returns an inactive Transfer Offer over the
source's authenticated HTTPS connection. Once the user chooses a username,
the client signs an exact Address Selection and sends it directly to the
new provider's fixed reservation endpoint:

```bash
bun run transfer:select -- /secure/user-controlled/alice.vault.json \
  /secure/user-controlled/alice.transfer-grant.json \
  /secure/user-controlled/alice.transfer-offer.json alice \
  /secure/user-controlled/alice.selection.json \
  /secure/user-controlled/alice.reservation.json
```

The destination address is `alice@new.example.com`. The same operation is
used for a third-party provider or a user-operated Hail server on that domain.
The target atomically reserves it and pushes the final signed request to the
old provider; the old provider freezes the DID only after validation.
Reservation does **not** yet publish a WebFinger binding or move the DID.
The grant by itself cannot move the DID or release account state.
`transfer:grant` prompts for the vault recovery secret and writes the grant
to a new mode-`0600` file.

To cancel **before** the old provider fences the DID, the client signs an
exact cancellation, obtains the old provider's signed no-fence receipt and
forwards both records to the target. Repeat the same command and files if
the target was temporarily unreachable; it must never release a possibly
fenced transfer merely because a local expiry elapsed:

```bash
bun run transfer:cancel -- /secure/user-controlled/alice.vault.json \
  /secure/user-controlled/alice.transfer-grant.json \
  /secure/user-controlled/alice.cancellation.json \
  /secure/user-controlled/alice.source-receipt.json
```
This reference CLI has no full provider discovery or
review UI: verify the selected domain and exact Offer through an authenticated
client channel before approving a real transfer. Tests verify
those signatures against the pinned PLC and Hail codec implementations.

The local file format is **not** a mandatory Hail wire profile. A mobile
client may keep the same signing authorities in a hardware-backed secure
store, use a different provider-independent recovery UX and produce identical
signed PLC and Hail objects. The user-controlled client must still review the
exact complete state, consent digests, keys, endpoints and alias preservation
before signing; the test-oriented library is not that review interface.

## Private PLC POC Ceremony

For disposable test identities, `poc:create-disposable-vault` writes a private
vault and a separate mode-`0600` recovery-secret file on the user device;
`poc:verify-vault-copy` verifies a copied vault locally. This same-device check
does not prove independent-device backup or production recovery. Keep the
ceremony directory mode `0700`, and never send either file to the VPS.

POC-only provider migration can use **new** DIDs in the existing private
PLC directory, with no public `plc.directory` registration. Once a vault is
created and its recovery material has been independently checked, a POC
provider gives the user a private preparation file containing the address,
their public keys and the provider-owned operational public keys. The client
signs the exact genesis and initial Address Binding with the user-held keys:

```bash
bun run poc:sign-onboarding -- /secure/user-controlled/alice.vault.json \
  /secure/user-controlled/source-preparation.json \
  /secure/user-controlled/alice.signed-onboarding.json
```

This atomically binds the vault to its new DID; retrying with the same signed
output preserves the DID if the vault-file update was interrupted. The source
provider registers **those exact signed bytes** in the internal POC PLC and
verifies the address externally over HTTPS. The provider never receives the
user recovery secret or either private user key.

After the source has fenced the account, exported its signed snapshot, and
the client has reviewed the target Offer and address-reservation receipt,
the client signs the exact full-state cutover PLC operation, consent and
destination Address Binding:

```bash
bun run poc:sign-cutover -- /secure/user-controlled/alice.vault.json \
  /secure/user-controlled/source.snapshot.json \
  /secure/user-controlled/target.offer.json \
  /secure/user-controlled/target.reservation.json \
  /secure/user-controlled/alice.consent.json \
  /secure/user-controlled/alice.plc-operation.json \
  /secure/user-controlled/alice.binding.cose
```

The destination stages these signed artifacts while inactive, submits the
user-signed update only to the POC's **private PLC**, publishes the pending
binding on its own Hail domain, and activates only after the exact private
PLC log and address verify. The POC monitor profile is explicitly local and
does not demonstrate independent monitoring or public PLC finality.

Retry `poc:sign-cutover` with the same input/output paths to verify and reuse a
complete artifact set byte-for-byte. Do not discard signed outputs to generate
a new PLC operation after one may have been submitted. If only part of the
artifact set exists, inspect the interruption before continuing. Target
activation and source retirement can recover a completed result with the exact
signed receipt; post-export cancellation is not an automated rollback.

For a user-key-controlled POC recipient, the source provider can propose
one Grant after verifying the sender's Hail address and Sender Profile. The
client reviews **both addresses**, signs with its own `#hail-identity` and
returns the COSE representation for import/publication:

```bash
bun run poc:sign-grant -- /secure/user-controlled/alice.vault.json \
  /secure/user-controlled/grant-proposal.json \
  alice@hailproto.dev sender@hailproto.app \
  /secure/user-controlled/alice-to-sender.grant.cose
```

The provider cannot decrypt the user identity key to author a Grant; it
rechecks current destination evidence against the consent hashes before
accepting the exact signed bytes.

### Revoke a user-signed Grant

Use the exact **current** signed Grant retained on the user device (or obtained
over an authenticated channel from the current provider). Review its Grant ID
and the sender address recorded in its consent context:

```bash
bun run poc:revoke-grant -- /secure/user-controlled/alice.vault.json \
  /secure/user-controlled/current.grant.cose \
  "$grant_id" "$reviewed_sender_address" \
  /secure/user-controlled/revoked.grant.cose
```

The client verifies the prior Grant under its vault identity key, checks the
reviewed relationship, carries forward scope/expiration/consent, increments
the revision, binds the exact predecessor digest and signs `status: revoked`.
An identical retry with the same paths reuses the signed output bytes. A
tampered prior Grant, mismatched relationship or conflicting output is rejected.
A prior Grant signed with a different identity key requires historical-key
reconciliation; this CLI fails closed rather than trusting provider metadata.

Send **only** the signed revocation to the current provider:

```bash
bun run poc:grant-import -- "$own_address" "$reviewed_sender_address" revoked.grant.cose
```

That command runs in `hail-server-ts` with the current provider's environment.
It verifies current identity authority and atomically stores the terminal
revision with a publication job. New acceptance stops at that commit; sender
notification may retry independently. Revocation needs no live sender address,
profile or acknowledgement, and may revoke an already expired Grant. Previously
accepted messages retain their delivery responsibility. If the provider has a
newer revision, reconcile it instead of overwriting the chain. After transfer,
import at the new provider, not the fenced/retired source.
