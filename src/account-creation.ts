import { createHash,randomBytes,randomUUID } from "node:crypto";
import { rename } from "node:fs/promises";
import { encodeBase64Url,decodeBase64Url } from "@hailproto/codec";
import type { Operation } from "@did-plc/lib";
import { AccountApiClient } from "./account-api.js";
import { privateFile,savePrivateBytes } from "./grant-revocation.js";
import { unlockUserVault,type UserVaultFile } from "./vault.js";
import { readRecoverySecret } from "./cli/private-input.js";

export async function writeState(path:string,data:unknown) {
  const temporary=`${path}.tmp-${randomUUID()}`;
  await savePrivateBytes(temporary,new TextEncoder().encode(JSON.stringify(data)));
  await rename(temporary,path);
}
export async function createAccount(provider:string,address:string,custody:"owner-controlled"|"managed",
  vaultPath:string,statePath:string,credentialPath:string,recoveryInput:()=>Promise<string>=readRecoverySecret) {
  let state: {provider:string;address:string;custody:string;token:string;preparation?:Record<string,unknown>;
    operation?:Operation;binding?:string|null;did?:string};
  try {state=JSON.parse(new TextDecoder().decode(await privateFile(statePath,64000)));}
  catch(error) {
    if(!(error instanceof Error&&"code" in error&&error.code==="ENOENT"))throw error;
    state={provider,address,custody,token:`hailp_${encodeBase64Url(randomBytes(32))}`};
    await savePrivateBytes(statePath,new TextEncoder().encode(JSON.stringify(state)));
  }
  if(state.provider!==provider||state.address!==address||state.custody!==custody)throw new Error("Signup state belongs to another request");
  const secret=decodeBase64Url(await recoveryInput());
  try {
    const user=await unlockUserVault(JSON.parse(new TextDecoder().decode(await privateFile(vaultPath,16384))) as UserVaultFile,secret);
    const originallyUnbound=user.vault.did===null;
    const client=AccountApiClient.signup(provider,state.token);
    const prepared=state.preparation ?? await client.request("",{address,recoveryKey:user.vault.recovery.publicDidKey,
      identityKey:user.vault.identity.publicDidKey,custody,backupVerified:true,
      signupHash:encodeBase64Url(new Uint8Array(createHash("sha256").update(state.token).digest()))},"/api/v1/onboarding");
    if(prepared.address!==address.toLowerCase()||prepared.userRecoveryKey!==user.vault.recovery.publicDidKey||prepared.custodyProfile!==custody||
      (custody==="owner-controlled"&&prepared.userIdentityKey!==user.vault.identity.publicDidKey)||
      prepared.sourceServiceBase!==`${provider}/hail`||typeof prepared.accountId!=="string"||
      typeof prepared.providerRotationKey!=="string"||typeof prepared.providerMessagingKey!=="string"||typeof prepared.userIdentityKey!=="string"||
      new Set([prepared.userRecoveryKey,prepared.providerRotationKey,prepared.providerMessagingKey,prepared.userIdentityKey]).size!==4)throw new Error("Signup preparation does not match selected provider, custody and owner recovery");
    state.preparation=prepared;await writeState(statePath,state);
    if(!state.operation) {
      if(user.vault.did)throw new Error("Bound vault requires its original signup state");
      const unsigned={type:"plc_operation" as const,prev:null,rotationKeys:[user.vault.recovery.publicDidKey,prepared.providerRotationKey],
        verificationMethods:{"hail-identity":prepared.userIdentityKey,"hail-messaging":prepared.providerMessagingKey},
        alsoKnownAs:[],services:{hail:{type:"HailMessaging",endpoint:`${provider}/hail`}}};
      const signed=custody==="managed"?await user.signManagedGenesis(unsigned):await user.signPlcOperation(unsigned);
      await user.bindDid(signed.did,signed.operation,custody==="managed");
      state.operation=signed.operation;state.did=signed.did;
      const now=Math.floor(Date.now()/1000);
      state.binding=custody==="managed"?null:encodeBase64Url(await user.signAddressBinding({type:"hail.address-binding",version:1,
        address:address.toLowerCase(),did:signed.did,issued_at:now,expires_at:now+90*86400,key_id:`${signed.did}#hail-identity`}));
      await writeState(statePath,state);
    }
    if(user.vault.did===null) {await user.bindDid(state.did!,state.operation,custody==="managed");await writeState(vaultPath,user.vault);}
    else if(originallyUnbound)await writeState(vaultPath,user.vault);
    if(user.vault.did!==state.did)throw new Error("Signup state and vault DID differ");
    const result=await client.request(`/${prepared.accountId}`,{operation:state.operation,binding:state.binding ?? null},"/api/v1/onboarding");
    const credential=result.credential as Record<string,unknown>;
    if(result.did!==state.did||credential?.provider!==provider||credential.accountId!==prepared.accountId||credential.token!==state.token)throw new Error("Signup returned another account or credential");
    try {await savePrivateBytes(credentialPath,new TextEncoder().encode(JSON.stringify(credential)));}
    catch(error) {
      if(!(error instanceof Error&&"code" in error&&error.code==="EEXIST"))throw error;
      const saved=JSON.parse(new TextDecoder().decode(await privateFile(credentialPath,16384)));
      if(saved.token!==state.token||saved.accountId!==prepared.accountId||saved.provider!==provider)throw new Error("Credential output conflicts");
    }
    return {did:state.did,address,custody,credentialFile:credentialPath};
  } finally {secret.fill(0);}
}
