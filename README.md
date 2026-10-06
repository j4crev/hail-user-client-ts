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
monitor. The current public POC DIDs were created custodially in a private
directory; creating this vault does not convert those DIDs to the public
portable-custody profile.

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

The previous service base is obtained by the client from the DID's current
PLC service, **not typed by the user**. The user chooses only `new.example.com`;
the client derives its well-known invitation endpoint and `/hail` service.
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
