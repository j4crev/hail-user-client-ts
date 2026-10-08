#!/usr/bin/env bun
import { parseArgs } from "node:util";
import { decodeBase64Url, toDiagnosticJson } from "@hailproto/codec";
import { AccountApiClient, AccountApiError } from "../account-api.js";
import { privateFile, savePrivateBytes, signGrantRevocation } from "../grant-revocation.js";
import { readRecoverySecret } from "./private-input.js";
import { createGrant } from "../grant-creation.js";
import { createAccount, writeState } from "../account-creation.js";
import { createUserVault } from "../vault.js";
import { randomBytes } from "node:crypto";
import { encodeBase64Url } from "@hailproto/codec";
import { sendMessage } from "../message-creation.js";

const help = `hailp — Hail Protocol account CLI (Bun 1.4+)

  hailp account show
  hailp vault create --vault <new-vault> --recovery-file <new-secret-file>
  hailp account create --provider <https-origin> --address <address> --custody <owner-controlled|managed> --vault <vault> --state <signup-state> --credentials <new-credential> --backup-verified
  hailp credential create --output <new-credential>
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
Revoke reads the vault recovery secret from hidden terminal input or protected stdin.
It saves signed bytes before submission and reuses them on exact retries.`;

try {
  const { values, positionals } = parseArgs({ args: Bun.argv.slice(2), allowPositionals: true,
    options: { credentials: { type: "string" }, vault: { type: "string" }, output: { type: "string" },
      category: { type: "string" }, after: { type: "string" }, "expires-at": { type: "string" },
      "no-expiry": { type: "boolean" }, uncategorized: { type: "boolean" },
      provider:{type:"string"},address:{type:"string"},custody:{type:"string"},state:{type:"string"},
      "backup-verified":{type:"boolean"},"recovery-file":{type:"string"},
      file:{type:"string"},grant:{type:"string"},"reply-until":{type:"string"},
      help: { type: "boolean", short: "h" } } });
  if (values.help || !positionals.length) console.info(help);
  else {
    const [group, command, argument] = positionals;
    if(group==="vault"&&command==="create"&&positionals.length===2) {
      if(!values.vault||!values["recovery-file"])throw new Error("Vault create requires two new private output files");
      const generated=await createUserVault();
      try {await savePrivateBytes(values["recovery-file"],new TextEncoder().encode(encodeBase64Url(generated.recoverySecret)+"\n"));
        await savePrivateBytes(values.vault,new TextEncoder().encode(JSON.stringify(generated.vault)));}
      finally {generated.recoverySecret.fill(0);}
      console.info(JSON.stringify({vaultFile:values.vault,recoveryFile:values["recovery-file"]}));
    } else if(group==="account"&&command==="create"&&positionals.length===2) {
      if(!values.provider||!values.address||!values.vault||!values.state||!values.credentials||!values["backup-verified"]||
        !["owner-controlled","managed"].includes(values.custody ?? ""))throw new Error("Account create requires explicit custody, provider, outputs and --backup-verified");
      console.info(JSON.stringify(await createAccount(values.provider,values.address,values.custody as "owner-controlled"|"managed",values.vault,values.state,values.credentials)));
    } else {
    const valid = group === "account" && command === "show" && positionals.length === 2 ||
      group === "credential" && command === "create" && positionals.length===2 || group==="credential"&&command==="revoke"&&positionals.length===3 ||
      group==="send"&&positionals.length===1||group==="reply"&&positionals.length===2||
      group==="inbox"&&command==="list"&&positionals.length===2||group==="inbox"&&command==="show"&&positionals.length===4||
      group==="message"&&["status","submit"].includes(command ?? "")&&positionals.length===3||
      group === "grant" && command === "list" && positionals.length === 2 ||
      group === "grant" && ["show", "submit", "revoke", "create"].includes(command ?? "") && positionals.length === 3;
    if (!valid || group === "account" && (values.vault || values.output) ||
      command === "submit" && (values.vault || values.output) || command === "show" && values.vault) {
      throw new Error("Invalid command/options; use hailp --help");
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
      else {
        if(!values.output)throw new Error("Credential create requires --output");
        const account=await client.account();
        let token:string;
        try{const saved=JSON.parse(new TextDecoder().decode(await privateFile(values.output,16384)));
          if(saved.provider!==account.provider||saved.accountId!==account.accountId||typeof saved.token!=="string")throw new Error("Credential output belongs to another account");token=saved.token;}
        catch(error){if(!(error instanceof Error&&"code" in error&&error.code==="ENOENT"))throw error;
          token=`hailp_${encodeBase64Url(randomBytes(32))}`;await savePrivateBytes(values.output,new TextEncoder().encode(JSON.stringify({provider:account.provider,accountId:account.accountId,token})));}
        const record=await client.request("/credentials",{token});
        if(record.token!==token)throw new Error("Credential acknowledgement differs");
        await writeState(values.output,record);
        result={credentialId:record.credentialId,credentialFile:values.output};
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
