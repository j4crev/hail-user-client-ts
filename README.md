# Hail user client

`hailp` is the Hail Protocol reference CLI for account setup, credentials,
Grants, messages, vault backups, and provider transfers. It talks to a
provider's account API over HTTPS and keeps user signing keys on the client.

This repository is a reference implementation, not a finished consumer app.
The file-based vault, Bun toolchain, private-PLC POC, and local monitor setup
are implementation and test choices—not requirements of the Hail protocol.

## Start here

- [Install or build `hailp`](docs/cli-installation.md)
- [Follow task-based CLI workflows](docs/cli-workflows.md)
- [Look up automation and output rules](docs/cli-contract.md)
- [Browse design notes and release evidence](docs/README.md)

The CLI also has authoritative, command-specific help:

```bash
hailp --help
hailp grant create --help
hailp account transfer --help
```

## Build for development

The sibling `hailproto` and `did-method-plc` repositories must be beside this
checkout because they are local dependencies.

```bash
bun run --cwd ../hailproto/packages/hail-codec-ts build
pnpm --dir ../did-method-plc --filter @did-plc/lib build
bun install --frozen-lockfile
bun run typecheck
bun run test
```

Run from source:

```bash
bun run hailp -- --help
```

Or build the self-contained Linux executable:

```bash
bun run build
bun run smoke -- dist/hailp
install -Dm755 dist/hailp "$HOME/.local/bin/hailp"
```

## Use an existing account

Set the path to a private credential file issued for the account. The token
stays in the file; never put it on the command line or in a URL.

```bash
export HAILP_CREDENTIAL_FILE=/secure/account/api.credential.json

hailp account show
hailp grant list
hailp inbox list
```

`--credentials <path>` overrides the environment variable. Add `--provider`
or `--account-id` to assert that the selected credential belongs to the origin
and account you expect; those flags cannot retarget a credential.

All successful results are JSON on stdout. Errors and secret prompts go to
stderr, and failures use a nonzero exit code. For automation, inspect the JSON
result as well as the exit code: an indeterminate message status is still a
successful status query, not proof of delivery.

## Create a test account

Self-service account creation must be enabled by the provider. Keep all files
outside Git in a private directory.

```bash
install -d -m 700 /secure/account

hailp vault create \
  --vault /secure/account/vault.json \
  --recovery-file /secure/account/recovery-secret.txt

# Copy and verify both files independently before continuing.
hailp vault verify --vault /secure/account/vault.json --expected-did unbound

hailp account create \
  --provider https://provider.example \
  --address me@provider.example \
  --custody owner-controlled \
  --vault /secure/account/vault.json \
  --state /secure/account/signup.json \
  --credentials /secure/account/api.credential.json \
  --backup-verified
```

Use `--custody managed` only when provider-held identity signing is intended.
Both profiles keep the top PLC recovery key with the owner. Strict-public
onboarding also requires monitor options; see the
[signup workflow](docs/cli-workflows.md#create-an-account).

## Important file and retry rules

- Vaults, recovery secrets, credentials, state files, and signed artifacts are
  private. Store them outside repositories and provider hosts.
- Enter the vault encryption secret at the hidden prompt or through protected
  stdin. Do not pass it as an argument.
- Commands save state and signed artifacts before network submission. After an
  interrupted or ambiguous request, repeat the same command with the same
  paths and options. Do not delete the files and start over.
- Routine owner-controlled Grant, binding, login, and transfer-approval actions
  unlock only the identity key. Onboarding, vault verification, owner-recovery
  login, and transfer cutover deliberately unlock the recovery key too.
- Provider transfer never forwards a source credential to the destination.
  Issue fresh destination access after activation.

## Scope and limitations

The CLI currently exercises private-PLC deployments and a locally verified
strict-public onboarding subset. It does not by itself establish independent
monitoring, production recovery, hardware-backed key storage, or a public
cross-provider client API standard. See the [roadmap](docs/cli-roadmap.md) for
the remaining production gates and `../hailproto` for normative protocol
specifications.
