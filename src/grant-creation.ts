import { decodeBase64Url, inspectSignedPayload, verifySignedPayload, createWebCryptoVerifier, type HailGrant } from "@hailproto/codec";
import { base58btc } from "multiformats/bases/base58";
import { privateFile, savePrivateBytes } from "./grant-revocation.js";
import { unlockUserIdentity, type UserVaultFile } from "./vault.js";
import { readRecoverySecret } from "./cli/private-input.js";
import type { AccountApiClient } from "./account-api.js";

export async function createGrant(client: AccountApiClient, sender: string, category: string | null,
  vaultPath: string, output: string, expiresAt?: number | null) {
  const account = await client.account();
  if (account.migrationState || !account.scopes.includes("grants:write")) throw new Error("Account cannot write Grants");
  if(account.custodyProfile==="managed") {
    const path=`${output}.request.json`;
    let input:{sender:string;category:string|null;expiresAt:number|null};
    try{input=JSON.parse(new TextDecoder().decode(await privateFile(path,16384)));}
    catch(error){if(!(error instanceof Error&&"code" in error&&error.code==="ENOENT"))throw error;
      input={sender,category,expiresAt:expiresAt===undefined?Math.floor(Date.now()/1000)+7*86400:expiresAt};
      await savePrivateBytes(path,new TextEncoder().encode(JSON.stringify(input)));}
    if(input.sender!==sender||input.category!==category||(expiresAt!==undefined&&input.expiresAt!==expiresAt))throw new Error("Managed Grant retry changed requested permission");
    const result=await client.request("/grants/managed",input);
    const grant=await client.grant(result.grantId as string);
    try{await savePrivateBytes(output,grant.representation);}catch(error){if(!(error instanceof Error&&"code" in error&&error.code==="EEXIST"))throw error;
      if(!Buffer.from(await privateFile(output,262144)).equals(Buffer.from(grant.representation)))throw new Error("Managed Grant output conflicts");}
    return result;
  }
  if(!vaultPath)throw new Error("Owner-controlled Grant creation requires --vault");
  let saved: Uint8Array | null = null;
  try { saved = await privateFile(output,262_144); }
  catch (error) { if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error; }
  const expiry = expiresAt === undefined ? saved ? inspectSignedPayload("hail.grant",saved).payload.expires_at :
    Math.floor(Date.now()/1000)+7*86400 : expiresAt;
  const payload = saved ? inspectSignedPayload("hail.grant",saved).payload : await client.propose(sender,category,expiry);
  if (payload.grantor !== account.did || payload.status !== "active" || payload.revision !== 1 || payload.previous !== null ||
    payload.consent_context.grantee_address !== sender.toLowerCase() || payload.expires_at !== expiry ||
    payload.scope.length !== 1 || (category === null ? payload.scope[0].type !== "uncategorized" :
      payload.scope[0].type !== "categories" || payload.scope[0].values.length !== 1 || payload.scope[0].values[0] !== category)) {
    throw new Error("Grant proposal or saved output does not match the requested permission");
  }
  const secret = decodeBase64Url(await readRecoverySecret());
  try {
    const user = await unlockUserIdentity(JSON.parse(new TextDecoder().decode(await privateFile(vaultPath,16_384))) as UserVaultFile,secret);
    if (user.vault.did !== account.did) throw new Error("Vault does not belong to the authenticated account");
    const signed = saved ?? await user.signGrant(payload);
    const publicBytes = base58btc.decode(user.vault.identity.publicDidKey.slice(8));
    await verifySignedPayload("hail.grant",signed,createWebCryptoVerifier(async kid => {
      if (kid !== `${account.did}#hail-identity`) throw new Error("Wrong Grant signer");
      return crypto.subtle.importKey("raw",Uint8Array.from(publicBytes.slice(2)),"Ed25519",false,["verify"]);
    }));
    if (!saved) await savePrivateBytes(output,signed);
    return client.submit(signed);
  } finally { secret.fill(0); }
}
