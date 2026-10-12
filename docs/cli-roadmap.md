# `hailp` roadmap

This page summarizes capability status. It is not a command guide; use
[CLI workflows](cli-workflows.md) for implemented commands and
`hailp <command> --help` for exact options.

## Goal

Provide a practical HTTPS account client for people, developers, and agents
without provider SSH or database access. Support explicit owner-controlled and
managed identity custody without silently changing custody when a signer is
unavailable.

The reference account API is currently an implementation interface. Hail
federation and the specifications in `../hailproto` remain the interoperable
protocol boundary.

## Implemented

- JSON CLI with strict command-specific options, explicit credential/account
  selection, bounded pagination and status waiting.
- Vault creation, verification, backup, import, and resumable account signup.
- Owner-controlled and managed account profiles with owner-held top PLC
  recovery authority.
- Credential inventory, narrower issuance, rotation, revocation, and explicit
  owner-proof login after bearer expiry.
- Grant creation, inspection, update, submission, and signed revocation.
- Text send, invited reply, inbox reads, resubmission, and retained status.
- Address Binding renewal.
- Owner-controlled provider transfer, cancellation before fencing, exact
  cutover signing, completion, and forward return to a former provider.
- Managed-profile and strict-public onboarding/authority conformance slices
  verified locally through provider migration 44.

The private-PLC deployments and local proof environment do not establish public
production readiness or independent monitoring.

## Remaining production gates

1. Finish review of the managed-custody and PLC read-evidence specifications.
2. Exercise public `plc.directory` onboarding and recovery with non-disposable
   identity and recovery material.
3. Operate monitor/read paths independently from providers and test bootstrap,
   disagreement, gaps, alerts, and recovery inside the PLC recovery window.
4. Complete managed migration and custody-transition workflows while preserving
   historical evidence and rollback safety.
5. Prove cross-host restoration, historical signed-object audits, and load
   limits on independently operated infrastructure.
6. Integrate device-keystore or hardware protection and verify cross-platform
   binary distribution.

## Current constraints

- Self-service private-PLC features are provider opt-ins.
- The v1 vault uses one encryption secret for both encrypted key records, even
  though routine operations load only the identity key.
- API credentials are provider-local and expire; rotate them while valid or use
  explicit owner-proof login.
- Managed provider transfer and automated post-export rollback are not public
  CLI workflows.
- The reference CLI has no finished consumer review UI or automatic provider
  discovery.

## Supporting records

- [Production gate details](milestone7-production-gate.md)
- [Custody-transition design](custody-transitions.md)
- [Device-keystore decision](device-keystore.md)
- [Milestone 6 CLI verification](milestone6-verification.md)
- [Documentation index](README.md)
