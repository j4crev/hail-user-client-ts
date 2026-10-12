import {createHash,randomUUID} from "node:crypto";
import {verifySignature as verifyDidSignature} from "@atproto/crypto";
import {decodeBase64Url,decodeDeterministic,encodeBase64Url,encodeDeterministic,type HailValue} from "@hailproto/codec";
import type {AccountApiClient} from "./account-api.js";
import {destinationOrigin} from "./account-transfer.js";
import {writeState} from "./account-creation.js";
import {readRecoverySecret} from "./cli/private-input.js";
import {privateFile} from "./grant-revocation.js";
import {verifySignature} from "./transfer-cutover.js";
import {unlockUserVault,type ManagedTransferAddressSelection,type ManagedTransferGrant,type UserVaultFile} from "./vault.js";

interface Wire {payload:string;signature:string}
interface State {
  type:"hailp.managed-account-transfer";version:1;provider:string;accountId:string;did:string;
  ownerRecoveryKey:string;sourceIdentityKey:string;destination:string;
  grant?:Wire;acknowledgement?:Wire;offer?:Wire;selection?:Wire;reservation?:Wire;
}

const sha=(bytes:Uint8Array)=>new Uint8Array(createHash("sha256").update(bytes).digest());
const equal=(a:Uint8Array,b:Uint8Array)=>Buffer.from(a).equals(Buffer.from(b));
const uuid=(value:unknown)=>typeof value==="string"&&/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(value);
const digest=(value:unknown)=>value instanceof Uint8Array&&value.length===32;

function wire(value:unknown):Wire {
  if(!value||typeof value!=="object"||Array.isArray(value)||Object.keys(value).length!==2||!("payload" in value)||!("signature" in value)||
    typeof value.payload!=="string"||typeof value.signature!=="string"||decodeBase64Url(value.payload).length>8192||decodeBase64Url(value.signature).length!==64)
    throw new Error("Invalid bounded managed transfer representation");
  return {payload:value.payload,signature:value.signature};
}

function decoded(signed:Wire,kind:string) {
  const bytes=decodeBase64Url(signed.payload),value=decodeDeterministic(bytes) as Record<string,any>;
  if(!value||typeof value!=="object"||value.type!==kind||value.version!==1||!equal(bytes,encodeDeterministic(value as HailValue))||
    typeof value.did!=="string"||!/^did:plc:[a-z2-7]{24}$/.test(value.did)||!uuid(value.nonce)||
    !Number.isSafeInteger(value.issued_at)||!Number.isSafeInteger(value.expires_at)||value.expires_at<=value.issued_at||
    value.expires_at-value.issued_at>3600)throw new Error("Invalid managed transfer handshake");
  return {bytes,value};
}

async function ownerRecord(signed:Wire,kind:string,key:string) {
  const {bytes,value}=decoded(signed,kind),tag=new TextEncoder().encode(`${kind}.v1\0`),input=new Uint8Array(tag.length+bytes.length);
  input.set(tag);input.set(bytes,tag.length);
  if(!await verifyDidSignature(key,input,decodeBase64Url(signed.signature),{jwtAlg:"ES256"}))
    throw new Error("Managed transfer owner signature differs from the reviewed recovery key");
  return value;
}

async function providerRecord(signed:Wire,kind:string,key:string) {
  const {bytes,value}=decoded(signed,kind);
  await verifySignature(`${kind}.v1`,bytes,decodeBase64Url(signed.signature),key);
  return value;
}

function validateStatus(status:Record<string,unknown>,account:Awaited<ReturnType<AccountApiClient["account"]>>) {
  if(status.type!=="hailp.managed-transfer-status"||status.version!==1||status.provider!==account.provider||
    status.accountId!==account.accountId||status.did!==account.did||
    !["none","acknowledgement-retained","offer-ready","expired","expired-unresolved"].includes(status.phase as string))
    throw new Error("Managed transfer status differs from its authenticated account");
  return status;
}

async function load(path:string) {
  return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(await privateFile(path,32768))) as State;
}

async function reviewGrant(state:State) {
  const grant=await ownerRecord(wire(state.grant),"hail.managed-transfer-grant",state.ownerRecoveryKey);
  if(grant.did!==state.did||grant.source_service_base!==`${state.provider}/hail`||
    grant.destination_service_base!==`${state.destination}/hail`||grant.destination_domain!==new URL(state.destination).hostname||
    grant.owner_recovery_key!==state.ownerRecoveryKey||grant.source_identity_key!==state.sourceIdentityKey)
    throw new Error("Retained managed transfer approval differs from the account or destination");
  return grant;
}

async function reviewAcknowledgement(state:State,grant:Record<string,any>,acknowledgementWire=wire(state.acknowledgement)) {
  const ackRaw=decoded(acknowledgementWire,"hail.managed-transfer-acknowledgement").value;
  const acknowledgement=await providerRecord(acknowledgementWire,"hail.managed-transfer-acknowledgement",ackRaw.source_messaging_key);
  if(acknowledgement.did!==state.did||acknowledgement.nonce!==grant.nonce||
    acknowledgement.source_service_base!==grant.source_service_base||acknowledgement.destination_service_base!==grant.destination_service_base||
    !digest(acknowledgement.grant_digest)||!equal(acknowledgement.grant_digest,sha(decodeBase64Url(state.grant!.payload))))
    throw new Error("Source acknowledgement differs from the reviewed managed transfer");
  return acknowledgement;
}

async function reviewOffer(state:State,grant:Record<string,any>) {
  const acknowledgement=await reviewAcknowledgement(state,grant);
  const offerWire=wire(state.offer),offerRaw=decoded(offerWire,"hail.managed-transfer-offer").value;
  const offer=await providerRecord(offerWire,"hail.managed-transfer-offer",offerRaw.destination_messaging_key);
  const keys=[offer.destination_rotation_key,offer.destination_identity_key,offer.destination_messaging_key];
  if(offer.did!==state.did||offer.nonce!==grant.nonce||!uuid(offer.transfer_id)||offer.source_service_base!==grant.source_service_base||
    offer.destination_service_base!==grant.destination_service_base||offer.expires_at<=Math.floor(Date.now()/1000)||offer.expires_at>grant.expires_at||
    !digest(offer.grant_digest)||!equal(offer.grant_digest,acknowledgement.grant_digest)||!digest(offer.acknowledgement_digest)||
    !equal(offer.acknowledgement_digest,sha(decodeBase64Url(state.acknowledgement!.payload)))||
    keys.some(key=>typeof key!=="string"||!key.startsWith("did:key:z"))||new Set(keys).size!==3)
    throw new Error("Destination Offer differs from the reviewed managed transfer");
  return offer;
}

export async function managedTransferStatus(client:AccountApiClient) {
  const account=await client.account();
  return validateStatus(await client.request("/transfers/managed"),account);
}

export async function managedTransferOffer(client:AccountApiClient,destination:string,vaultPath:string,path:string,
  recoveryInput=readRecoverySecret) {
  destination=destinationOrigin(destination);const account=await client.account();
  if(account.custodyProfile!=="managed"||account.migrationState||!account.scopes.includes("account:write")||
    typeof account.ownerRecoveryPublicKey!=="string"||typeof account.identityPublicKey!=="string"||destination===account.provider)
    throw new Error("Managed transfer preparation requires managed write authority, owner recovery, and a distinct destination");
  let state:State;
  try {state=await load(path);} catch(error) {
    if(!(error instanceof Error&&"code" in error&&error.code==="ENOENT"))throw error;
    state={type:"hailp.managed-account-transfer",version:1,provider:account.provider,accountId:account.accountId,did:account.did,
      ownerRecoveryKey:account.ownerRecoveryPublicKey,sourceIdentityKey:account.identityPublicKey,destination};
    await writeState(path,state);
  }
  if(state.type!=="hailp.managed-account-transfer"||state.version!==1||state.provider!==account.provider||state.accountId!==account.accountId||
    state.did!==account.did||state.ownerRecoveryKey!==account.ownerRecoveryPublicKey||state.sourceIdentityKey!==account.identityPublicKey||state.destination!==destination)
    throw new Error("Managed transfer state, account authority, or destination changed");
  if(!state.grant){const secret=decodeBase64Url(await recoveryInput());try {
    const owner=await unlockUserVault(JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(await privateFile(vaultPath,16384))) as UserVaultFile,secret);
    if(owner.vault.did!==state.did||owner.vault.recovery.publicDidKey!==state.ownerRecoveryKey)throw new Error("Vault does not match the managed account owner");
    const now=Math.floor(Date.now()/1000),grant:ManagedTransferGrant={type:"hail.managed-transfer-grant",version:1,did:state.did,nonce:randomUUID(),
      source_service_base:`${state.provider}/hail`,destination_service_base:`${destination}/hail`,destination_domain:new URL(destination).hostname,
      owner_recovery_key:state.ownerRecoveryKey,source_identity_key:state.sourceIdentityKey,issued_at:now,expires_at:now+3600};
    const signed=await owner.signManagedTransferOwnerIntent(grant);state.grant={payload:encodeBase64Url(signed.payloadBytes),signature:encodeBase64Url(signed.signature)};
    await writeState(path,state);
  } finally {secret.fill(0);}}
  const grant=await reviewGrant(state);
  if(grant.expires_at<=Math.floor(Date.now()/1000))throw new Error("Retained managed transfer approval is stale");
  const status=validateStatus(await client.request("/transfers/managed/offer",{...state.grant}),account);
  const acknowledgement=wire(status.acknowledgement);
  await reviewAcknowledgement(state,grant,acknowledgement);
  if(state.acknowledgement&&JSON.stringify(state.acknowledgement)!==JSON.stringify(acknowledgement))throw new Error("Source acknowledgement changed");
  state.acknowledgement=acknowledgement;await writeState(path,state);
  if(!status.offer){if(status.phase!=="acknowledgement-retained")throw new Error("Managed transfer is no longer awaiting an Offer");
    return {did:state.did,destination,pending:true,stateFile:path};}
  const offerWire=wire(status.offer);
  if(state.offer&&JSON.stringify(state.offer)!==JSON.stringify(offerWire))throw new Error("Destination Offer changed");
  state.offer=offerWire;const offer=await reviewOffer(state,grant);
  if(status.phase!=="offer-ready"||status.originConfirmed!==true||status.transferId!==offer.transfer_id||status.destinationServiceBase!==grant.destination_service_base)
    throw new Error("Source has not retained the exact destination-origin managed Offer");
  await writeState(path,state);
  return {did:state.did,destination,transferId:offer.transfer_id,expiresAt:offer.expires_at,
    destinationRotationPublicKey:offer.destination_rotation_key,destinationIdentityPublicKey:offer.destination_identity_key,
    destinationMessagingPublicKey:offer.destination_messaging_key,phase:"offer-ready",stateFile:path};
}

async function reserve(destination:string,selection:Wire,transport:typeof fetch) {
  const response=await transport(`${destination}/.well-known/hail/transfers/managed-reservations`,{method:"POST",redirect:"error",credentials:"omit",
    signal:AbortSignal.timeout(10000),headers:{"Content-Type":"application/hail-transfer+json","Accept-Encoding":"identity","Cache-Control":"no-store"},
    body:JSON.stringify(selection)});
  const length=response.headers.get("content-length");
  if(![200,202].includes(response.status)||response.headers.get("content-type")!=="application/hail-transfer+json"||response.headers.has("location")||
    response.headers.has("content-encoding")||length!==null&&(!/^\d+$/.test(length)||Number(length)>16384)){
    void response.body?.cancel();throw new Error(`Destination managed reservation response invalid (HTTP ${response.status}); retain and retry the exact state`);
  }
  const reader=response.body?.getReader();if(!reader)throw new Error("Destination managed reservation is missing");
  const chunks:Uint8Array[]=[];let size=0;
  try {while(true){const next=await reader.read();if(next.done)break;size+=next.value.length;
    if(size>16384)throw new Error("Destination managed reservation exceeds its limit");chunks.push(next.value);}}
  catch(error){await reader.cancel().catch(()=>{});throw error;}
  if(!size)throw new Error("Destination managed reservation is missing");
  const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
  return {status:response.status,record:wire(JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes)))};
}

export async function selectManagedTransferAddress(client:AccountApiClient,username:string,vaultPath:string,path:string,
  recoveryInput=readRecoverySecret,transport:typeof fetch=fetch) {
  if(username.length>63||!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(username)||username.includes("..")||
    username.split(".").some(label=>label.startsWith("-")||label.endsWith("-")))throw new Error("Username must be a canonical Hail local part");
  const account=await client.account(),state=await load(path);
  if(account.custodyProfile!=="managed"||!account.scopes.includes("account:write")||state.type!=="hailp.managed-account-transfer"||state.version!==1||
    state.provider!==account.provider||state.accountId!==account.accountId||state.did!==account.did||state.ownerRecoveryKey!==account.ownerRecoveryPublicKey||
    state.sourceIdentityKey!==account.identityPublicKey||account.migrationState&&!state.selection)
    throw new Error("Address selection requires the original managed source Offer");
  const grant=await reviewGrant(state),offer=await reviewOffer(state,grant),address=`${username}@${grant.destination_domain}`;
  const status=validateStatus(await client.request("/transfers/managed"),account);
  if(status.phase!=="offer-ready"||status.originConfirmed!==true||status.transferId!==offer.transfer_id||
    JSON.stringify(wire(status.acknowledgement))!==JSON.stringify(state.acknowledgement)||JSON.stringify(wire(status.offer))!==JSON.stringify(state.offer))
    throw new Error("Source no longer retains this exact managed Offer");
  if(!state.selection){const secret=decodeBase64Url(await recoveryInput());try {
    const owner=await unlockUserVault(JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(await privateFile(vaultPath,16384))) as UserVaultFile,secret);
    if(owner.vault.did!==state.did||owner.vault.recovery.publicDidKey!==state.ownerRecoveryKey)throw new Error("Wrong managed address-selection signer");
    const now=Math.floor(Date.now()/1000),selection:ManagedTransferAddressSelection={type:"hail.managed-transfer-address-selection",version:1,did:state.did,
      nonce:grant.nonce,transfer_id:offer.transfer_id,grant_digest:sha(decodeBase64Url(state.grant!.payload)),offer_digest:sha(decodeBase64Url(state.offer!.payload)),
      address,selection_nonce:randomUUID(),issued_at:now,expires_at:Math.min(now+1800,offer.expires_at,grant.expires_at)};
    const signed=await owner.signManagedTransferOwnerIntent(selection);state.selection={payload:encodeBase64Url(signed.payloadBytes),signature:encodeBase64Url(signed.signature)};
    await writeState(path,state);
  } finally {secret.fill(0);}}
  const selection=await ownerRecord(wire(state.selection),"hail.managed-transfer-address-selection",state.ownerRecoveryKey);
  if(selection.did!==state.did||selection.nonce!==grant.nonce||selection.transfer_id!==offer.transfer_id||selection.address!==address||
    selection.expires_at<=Math.floor(Date.now()/1000)||selection.expires_at>offer.expires_at||!digest(selection.grant_digest)||!digest(selection.offer_digest)||
    !equal(selection.grant_digest,sha(decodeBase64Url(state.grant!.payload)))||!equal(selection.offer_digest,sha(decodeBase64Url(state.offer!.payload))))
    throw new Error("Retained managed selection is stale or differs from the reviewed address/Offer");
  const result=await reserve(state.destination,state.selection,transport),reservation=await providerRecord(result.record,"hail.managed-transfer-reservation",offer.destination_messaging_key);
  const keys=[reservation.destination_rotation_key,reservation.destination_identity_key,reservation.destination_messaging_key];
  if(reservation.did!==state.did||reservation.nonce!==grant.nonce||reservation.transfer_id!==offer.transfer_id||reservation.address!==address||
    reservation.expires_at<=Math.floor(Date.now()/1000)||reservation.expires_at>selection.expires_at||!digest(reservation.offer_digest)||!digest(reservation.selection_digest)||
    !equal(reservation.offer_digest,selection.offer_digest)||!equal(reservation.selection_digest,sha(decodeBase64Url(state.selection.payload)))||
    keys.some((key,index)=>key!==[offer.destination_rotation_key,offer.destination_identity_key,offer.destination_messaging_key][index]))
    throw new Error("Destination managed reservation differs from the signed selection/Offer");
  if(state.reservation&&JSON.stringify(state.reservation)!==JSON.stringify(result.record))throw new Error("Destination managed reservation changed");
  state.reservation=result.record;await writeState(path,state);
  return {did:state.did,destination:state.destination,address,transferId:offer.transfer_id,requestAcknowledged:result.status===200,stateFile:path};
}
