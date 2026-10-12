import { decodeBase64Url, encodeBase64Url } from "@hailproto/codec";
import { def } from "@did-plc/lib";
import { AccountApiClient } from "./account-api.js";
import { writeState } from "./account-creation.js";
import { privateFile } from "./grant-revocation.js";
import { unlockUserVault, type ManagedCustodyTransitionPreparation, type UserVaultFile } from "./vault.js";
import { readRecoverySecret } from "./cli/private-input.js";

interface State {type:"hailp.custody-transition-state";version:1;provider:string;accountId:string;did:string;transitionId:string;
  operation:string;operationCid:string;approval:string;signature:string;binding:string;bindingDigest:string;newIdentityKey:string;}
const uuid=(value:unknown):value is string=>typeof value==="string"&&/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(value);
const didKey=(value:unknown):value is string=>typeof value==="string"&&/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/.test(value);

function retained(value:unknown,provider:string,accountId:string,did:string):State {
  if(!value||typeof value!=="object"||Array.isArray(value))throw new Error("Invalid custody transition state");
  const state=value as State;
  if(state.type!=="hailp.custody-transition-state"||state.version!==1||state.provider!==provider||state.accountId!==accountId||
    state.did!==did||!uuid(state.transitionId)||typeof state.operation!=="string"||typeof state.operationCid!=="string"||
    typeof state.approval!=="string"||typeof state.signature!=="string"||typeof state.binding!=="string"||
    typeof state.bindingDigest!=="string"||!didKey(state.newIdentityKey)||decodeBase64Url(state.signature).length!==64)
    throw new Error("Retained custody transition state differs from the selected account");
  return state;
}

export async function transitionToManaged(client:AccountApiClient,vaultPath:string|undefined,statePath:string,
  recoveryInput=readRecoverySecret) {
  const account=await client.account();
  if(!account.scopes.includes("account:write"))throw new Error("Custody transition requires account:write authority");
  let state:State|undefined;
  try{state=retained(JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(await privateFile(statePath,131072))),
    account.provider,account.accountId,account.did);}catch(error){if(!(error instanceof Error&&"code" in error&&error.code==="ENOENT"))throw error;}
  if(!state) {
    if(account.custodyProfile!=="owner-controlled"||typeof account.identityPublicKey!=="string"||typeof account.ownerRecoveryPublicKey!=="string")
      throw new Error("A current owner-controlled account is required");
    if(!vaultPath)throw new Error("First custody preparation requires --vault; exact retries use the retained --state file");
    const raw=await client.request("/custody/managed",{});
    if(!uuid(raw.transitionId)||raw.accountId!==account.accountId||raw.did!==account.did||raw.direction!=="owner-to-managed"||
      raw.ownerRecoveryKey!==account.ownerRecoveryPublicKey||raw.oldIdentityKey!==account.identityPublicKey||!didKey(raw.newIdentityKey)||
      typeof raw.previousOperationCid!=="string"||typeof raw.historyCheckpointDigest!=="string"||typeof raw.bindingCose!=="string"||
      typeof raw.bindingDigest!=="string"||!Number.isSafeInteger(raw.generationFrom)||raw.generationTo!==(raw.generationFrom as number)+1||
      typeof raw.expiresAt!=="string"||!raw.unsignedOperation||typeof raw.unsignedOperation!=="object")throw new Error("Provider returned an invalid custody preparation");
    const preparation:ManagedCustodyTransitionPreparation={transitionId:raw.transitionId,accountId:account.accountId,did:account.did,
      direction:"owner-to-managed",ownerRecoveryKey:raw.ownerRecoveryKey,oldIdentityKey:raw.oldIdentityKey,newIdentityKey:raw.newIdentityKey,
      providerServiceBase:`${account.provider}/hail`,unsignedOperation:def.unsignedOperation.parse(raw.unsignedOperation),
      previousOperationCid:raw.previousOperationCid,historyCheckpointDigest:decodeBase64Url(raw.historyCheckpointDigest),
      bindingDigest:decodeBase64Url(raw.bindingDigest),generationFrom:raw.generationFrom as number,generationTo:raw.generationTo as number,
      expiresAt:raw.expiresAt};
    const secret=decodeBase64Url(await recoveryInput());
    try {const signer=await unlockUserVault(JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(await privateFile(vaultPath,16384))) as UserVaultFile,secret);
      const signed=await signer.signManagedCustodyTransition(preparation);
      state={type:"hailp.custody-transition-state",version:1,provider:account.provider,accountId:account.accountId,did:account.did,
        transitionId:preparation.transitionId,operation:encodeBase64Url(signed.operationBytes),operationCid:signed.operationCid,
        approval:encodeBase64Url(signed.approvalBytes),signature:encodeBase64Url(signed.approvalSignature),binding:raw.bindingCose,
        bindingDigest:raw.bindingDigest,newIdentityKey:preparation.newIdentityKey};await writeState(statePath,state);
    } finally {secret.fill(0);}
  }
  const result=await client.request("/custody/managed/commit",{transitionId:state.transitionId,operation:state.operation,
    approval:state.approval,signature:state.signature});
  if(result.transitionId!==state.transitionId||result.did!==state.did||result.state!=="complete"||!Number.isSafeInteger(result.generation))
    throw new Error("Provider completion does not match the retained custody transition");
  return {did:state.did,custodyProfile:"managed",identityPublicKey:state.newIdentityKey,generation:result.generation,
    stateFile:statePath,instruction:"Old credentials are terminal; use owner-recovery login for fresh access."};
}
