#!/usr/bin/env bun
import { parseArgs } from "node:util";
import { decodeBase64Url, toDiagnosticJson } from "@hailproto/codec";
import { AccountApiClient, AccountApiError } from "../account-api.js";
import { privateFile, savePrivateBytes, signGrantRevocation } from "../grant-revocation.js";
import { readRecoverySecret } from "./private-input.js";
import { createGrant } from "../grant-creation.js";
import { createAccount } from "../account-creation.js";
import { createUserVault } from "../vault.js";
import { encodeBase64Url } from "@hailproto/codec";
import { sendMessage } from "../message-creation.js";
import { copyVerifiedVault, verifyVaultFile } from "../vault-backup.js";
import { createCredential } from "../credential-creation.js";
import { rotateCredential } from "../credential-rotation.js";
import { loginAccount } from "../account-login.js";

const help = `hailp — Hail Protocol account CLI (Bun 1.4+)

  hailp account show
  hailp account login --provider <https-origin> --did <did> --signer <identity|owner-recovery> --vault <vault> --state <private-state> --credentials <new-output> --scope <permission> ...
  hailp vault create --vault <new-vault> --recovery-file <new-secret-file>
  hailp vault verify --vault <private-vault> [--expected-did <did|unbound>]
  hailp vault backup --vault <private-vault> --output <new-backup-vault>
  hailp vault import --file <backup-vault> --vault <new-vault> --expected-did <did|unbound>
  hailp account create --provider <https-origin> --address <address> --custody <owner-controlled|managed> --vault <vault> --state <signup-state> --credentials <new-credential> --backup-verified
  hailp credential list [--after <credential-id>]
  hailp credential create --output <new-credential> [--scope <permission> ...]
  hailp credential rotate --output <new-credential>
  hailp credential revoke <credential-id>
  hailp send --grant <grant-id> [--category <category>] --file <text-file> --state <new-request-state> [--reply-until <unix-seconds>]
  hailp reply <original-message-id> --file <text-file> --state <new-request-state>
  hailp inbox list [--after <cursor>]
  hailp inbox show <sender-did> <message-id>
  hailp message status <message-id>
  hailp message submit <message-id>
  hailp grant list [--after <grant-id>]
  hailp grant create <sender-address> --category <category> [--vault <owner-vault>] --output <grant.cose> [--expires-at <unix-seconds> | --no-expiry]
  hailp grant show <grant-id> [--output <new-private-current.cose>]
  hailp grant submit <private-signed-grant.cose>
  hailp grant revoke <grant-id> [--vault <owner-vault> --output <private-revocation.cose>]

Use --credentials <private-credential.json> or HAILP_CREDENTIAL_FILE.
Results are JSON on stdout; errors are JSON on stderr with a nonzero exit.
Owner-controlled Grant signing reads the vault encryption secret from hidden terminal input or protected stdin.
It decrypts only the identity key, not the PLC recovery private key.
It saves signed bytes before submission and reuses them on exact retries.
Vault verify/backup/import explicitly unlock both keys using protected secret input.`;

try {
  const { values, positionals } = parseArgs({ args: Bun.argv.slice(2), allowPositionals: true,
    options: { credentials: { type: "string" }, vault: { type: "string" }, output: { type: "string" },
      category: { type: "string" }, after: { type: "string" }, "expires-at": { type: "string" },
      "no-expiry": { type: "boolean" }, uncategorized: { type: "boolean" },
      provider:{type:"string"},address:{type:"string"},custody:{type:"string"},state:{type:"string"},
      "backup-verified":{type:"boolean"},"recovery-file":{type:"string"},
      file:{type:"string"},grant:{type:"string"},"reply-until":{type:"string"},"expected-did":{type:"string"},
      scope: { type: "string", multiple: true },
      did: { type: "string" }, signer: { type: "string" },
      help: { type: "boolean", short: "h" } } });
  if (values.help || !positionals.length) console.info(help);
  else {
    const [group, command, argument] = positionals;
    if(group==="vault") {
      const allowed = command === "create" ? ["vault", "recovery-file"] : command === "verify" ? ["vault", "expected-did"] :
        command === "backup" ? ["vault", "output"] : command === "import" ? ["file", "vault", "expected-did"] : [];
      if (positionals.length !== 2 || !allowed.length || Object.keys(values).some(key => !allowed.includes(key))) {
        throw new Error("Invalid vault command/options; use hailp --help");
      }
      if(command==="create") {
      if(!values.vault||!values["recovery-file"])throw new Error("Vault create requires two new private output files");
      const generated=await createUserVault();
      try {await savePrivateBytes(values["recovery-file"],new TextEncoder().encode(encodeBase64Url(generated.recoverySecret)+"\n"));
        await savePrivateBytes(values.vault,new TextEncoder().encode(JSON.stringify(generated.vault)));}
      finally {generated.recoverySecret.fill(0);}
      console.info(JSON.stringify({vaultFile:values.vault,recoveryFile:values["recovery-file"]}));
      } else {
        if (!values.vault || command === "backup" && !values.output ||
          command === "import" && (!values.file || !values["expected-did"])) throw new Error("Vault command requires its private paths and import requires --expected-did");
        const expectedDid = values["expected-did"] === "unbound" ? null : values["expected-did"];
        const secret = decodeBase64Url(await readRecoverySecret());
        try {
          const result = command === "verify" ? await verifyVaultFile(values.vault, secret, expectedDid) :
            await copyVerifiedVault(command === "backup" ? values.vault : values.file!,
              command === "backup" ? values.output! : values.vault, secret, expectedDid);
          console.info(JSON.stringify(result));
        } finally { secret.fill(0); }
      }
    } else if(group==="account"&&command==="login") {
      if (positionals.length !== 2 || Object.keys(values).some(key => !["provider", "did", "signer", "vault", "state", "credentials", "scope"].includes(key)) ||
        !values.provider || !values.did || !["identity", "owner-recovery"].includes(values.signer ?? "") ||
        !values.vault || !values.state || !values.credentials || !values.scope?.length) throw new Error("Login requires explicit provider, DID, signer, private paths and scopes");
      console.info(JSON.stringify(await loginAccount(values.provider, values.did, values.signer as "identity" | "owner-recovery",
        values.scope, values.vault, values.state, values.credentials)).replace(/hailp_[A-Za-z0-9_-]{43}/g, "[REDACTED]"));
    } else if(group==="account"&&command==="create"&&positionals.length===2) {
      if(!values.provider||!values.address||!values.vault||!values.state||!values.credentials||!values["backup-verified"]||
        !["owner-controlled","managed"].includes(values.custody ?? ""))throw new Error("Account create requires explicit custody, provider, outputs and --backup-verified");
      console.info(JSON.stringify(await createAccount(values.provider,values.address,values.custody as "owner-controlled"|"managed",values.vault,values.state,values.credentials)));
    } else {
    const valid = group === "account" && command === "show" && positionals.length === 2 ||
       group === "credential" && ["create", "list", "rotate"].includes(command ?? "") && positionals.length===2 || group==="credential"&&command==="revoke"&&positionals.length===3 ||
      group==="send"&&positionals.length===1||group==="reply"&&positionals.length===2||
      group==="inbox"&&command==="list"&&positionals.length===2||group==="inbox"&&command==="show"&&positionals.length===4||
      group==="message"&&["status","submit"].includes(command ?? "")&&positionals.length===3||
      group === "grant" && command === "list" && positionals.length === 2 ||
      group === "grant" && ["show", "submit", "revoke", "create"].includes(command ?? "") && positionals.length === 3;
    if (!valid || group === "account" && (values.vault || values.output) ||
      command === "submit" && (values.vault || values.output) || command === "show" && values.vault) {
      throw new Error("Invalid command/options; use hailp --help");
    }
    if (group === "credential") {
      const allowed = command === "create" ? ["credentials", "output", "scope"] : command === "rotate" ? ["credentials", "output"] : command === "list" ? ["credentials", "after"] : ["credentials"];
      if (Object.keys(values).some(key => !allowed.includes(key))) throw new Error("Invalid credential command/options; use hailp --help");
    }
    const credential = values.credentials ?? Bun.env.HAILP_CREDENTIAL_FILE;
    if (!credential) throw new Error("Set --credentials or HAILP_CREDENTIAL_FILE");
    const client = await AccountApiClient.fromCredentialFile(credential);
    let result: unknown;
    if (group === "account") result = await client.account();
    else if(group==="send"||group==="reply") {
      if(!values.file||!values.state||(group==="send"&&!values.grant))throw new Error("Send/reply requires file, state and send Grant");
      const until=values["reply-until"]===undefined?undefined:Number(values["reply-until"]);
      if(until!==undefined&&(!Number.isSafeInteger(until)||until<=Math.floor(Date.now()/1000)))throw new Error("Reply deadline must be in the future");
      result=await sendMessage(client,values.file,values.state,group==="send"?values.grant:undefined,values.category,group==="reply"?command:undefined,until);
    }
    else if(group==="inbox")result=await client.request(command==="list"?`/inbox${values.after?`?after=${encodeURIComponent(values.after)}`:""}`:
      `/inbox/${encodeURIComponent(argument!)}/${encodeURIComponent(positionals[3]!)}`);
    else if(group==="message")result=await client.request(`/messages/${encodeURIComponent(argument!)}${command==="submit"?"/submit":""}`,command==="submit"?{}:undefined);
    else if(group==="credential") {
      if(command==="revoke")result=await client.request("/credentials",{revoke:argument!});
      else if(command==="rotate") {
        if(!values.output)throw new Error("Credential rotate requires --output");
        result=await rotateCredential(credential, values.output);
      }
      else if(command==="list")result=await client.request(`/credentials${values.after ? `?after=${encodeURIComponent(values.after)}` : ""}`);
      else {
        if(!values.output)throw new Error("Credential create requires --output");
        result=await createCredential(client, values.output, values.scope);
      }
    }
    else if (command === "list") result = await client.request(`/grants${values.after ? `?after=${encodeURIComponent(values.after)}` : ""}`);
    else if (command === "create") {
      if (!values.output || Boolean(values.category) === Boolean(values.uncategorized) ||
        values["expires-at"] && values["no-expiry"]) throw new Error("Create requires vault/output and exactly one category or --uncategorized");
      const expiry = values["no-expiry"] ? null : values["expires-at"] === undefined ? undefined : Number(values["expires-at"]);
      if (expiry !== undefined && expiry !== null && (!Number.isSafeInteger(expiry) || expiry <= Math.floor(Date.now()/1000))) {
        throw new Error("Grant expiry must be a future Unix timestamp");
      }
      result = await createGrant(client,argument!,values.category ?? null,values.vault ?? "",values.output,expiry);
    }
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
        if(account.custodyProfile==="managed") {
          if(values.vault)throw new Error("Managed signing does not take the owner's identity vault");
          result=await client.request(`/grants/${argument!}/revoke`,{});
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
    }
    console.info(JSON.stringify(result).replace(/hailp_[A-Za-z0-9_-]{43}/g, "[REDACTED]"));
    }
  }
} catch (error) {
  console.error(JSON.stringify({ error: { code: error instanceof AccountApiError ? `HTTP_${error.status}` : "CLIENT_ERROR",
    message: (error instanceof Error ? error.message : "Client operation failed")
      .replace(/hailp_[A-Za-z0-9_-]{43}/g, "[REDACTED]") } }));
  process.exitCode = 1;
}
