#!/usr/bin/env bun
import { parseArgs } from "node:util";
import { decodeBase64Url, toDiagnosticJson } from "@hailproto/codec";
import { AccountApiClient, AccountApiError } from "../account-api.js";
import { privateFile, savePrivateBytes, signGrantRevocation } from "../grant-revocation.js";
import { readRecoverySecret } from "./private-input.js";

const help = `hailp — Hail Protocol account CLI (Bun 1.4+)

  hailp account show
  hailp grant show <grant-id> [--output <new-private-current.cose>]
  hailp grant submit <private-signed-grant.cose>
  hailp grant revoke <grant-id> --vault <private-vault> --output <private-revocation.cose>

Use --credentials <private-credential.json> or HAILP_CREDENTIAL_FILE.
Results are JSON on stdout; errors are JSON on stderr with a nonzero exit.
Revoke reads the vault recovery secret from hidden terminal input or protected stdin.
It saves signed bytes before submission and reuses them on exact retries.`;

try {
  const { values, positionals } = parseArgs({ args: Bun.argv.slice(2), allowPositionals: true,
    options: { credentials: { type: "string" }, vault: { type: "string" }, output: { type: "string" },
      help: { type: "boolean", short: "h" } } });
  if (values.help || !positionals.length) console.info(help);
  else {
    const [group, command, argument] = positionals;
    const valid = group === "account" && command === "show" && positionals.length === 2 ||
      group === "grant" && ["show", "submit", "revoke"].includes(command ?? "") && positionals.length === 3;
    if (!valid || group === "account" && (values.vault || values.output) ||
      command === "submit" && (values.vault || values.output) || command === "show" && values.vault) {
      throw new Error("Invalid command/options; use hailp --help");
    }
    const credential = values.credentials ?? Bun.env.HAILP_CREDENTIAL_FILE;
    if (!credential) throw new Error("Set --credentials or HAILP_CREDENTIAL_FILE");
    const client = await AccountApiClient.fromCredentialFile(credential);
    let result: unknown;
    if (group === "account") result = await client.account();
    else if (command === "submit") result = await client.submit(await privateFile(argument!, 262_144));
    else {
      const account = await client.account();
      if (command === "revoke" && !account.scopes.includes("grants:write")) {
        throw new Error("Credential has no Grant write permission");
      }
      const grant = await client.grant(argument!);
      if (command === "show") {
        if (values.output) await savePrivateBytes(values.output, grant.representation);
        result = { grantId: grant.payload.grant_id, localRole: grant.localRole, digest: grant.digest,
          grant: toDiagnosticJson("hail.grant", grant.payload) };
      } else {
        if (!values.vault || !values.output) throw new Error("Revoke requires --vault and --output for exact retries");
        if (grant.localRole !== "grantor" || grant.payload.grantor !== account.did) {
          throw new Error("Only the authoritative grantor account can revoke this Grant");
        }
        if (account.migrationState) throw new Error("Account is migration-fenced; use the current provider after transfer");
        const secret = decodeBase64Url(await readRecoverySecret());
        try {
          const signed = await signGrantRevocation(values.vault, grant.representation, grant.payload.grant_id,
            grant.payload.consent_context.grantee_address, values.output, secret, account.did);
          result = await client.submit(signed);
        } finally { secret.fill(0); }
      }
    }
    console.info(JSON.stringify(result).replace(/hailp_[A-Za-z0-9_-]{43}/g, "[REDACTED]"));
  }
} catch (error) {
  console.error(JSON.stringify({ error: { code: error instanceof AccountApiError ? `HTTP_${error.status}` : "CLIENT_ERROR",
    message: (error instanceof Error ? error.message : "Client operation failed")
      .replace(/hailp_[A-Za-z0-9_-]{43}/g, "[REDACTED]") } }));
  process.exitCode = 1;
}
