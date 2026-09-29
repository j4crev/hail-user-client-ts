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
portable-migration consent with the separate user identity key. Tests verify
those signatures against the pinned PLC and Hail codec implementations.

The local file format is **not** a mandatory Hail wire profile. A mobile
client may keep the same signing authorities in a hardware-backed secure
store, use a different provider-independent recovery UX and produce identical
signed PLC and Hail objects. The user-controlled client must still review the
exact complete state, consent digests, keys, endpoints and alias preservation
before signing; the test-oriented library is not that review interface.
