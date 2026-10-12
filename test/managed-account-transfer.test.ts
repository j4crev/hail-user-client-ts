import {createHash,randomUUID} from "node:crypto";
import {mkdtemp,readFile,rm,stat,writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {decodeBase64Url,decodeDeterministic,encodeBase64Url,encodeDeterministic,type HailValue} from "@hailproto/codec";
import {base58btc} from "multiformats/bases/base58";
import {expect,it} from "vitest";
import type {AccountApiClient} from "../src/account-api.js";
import {managedTransferOffer,managedTransferStatus,selectManagedTransferAddress} from "../src/managed-account-transfer.js";
import {createUserVault} from "../src/vault.js";

it("orchestrates exact-retry managed owner authorization through destination reservation",async()=>{
  const generated=await createUserVault(),directory=await mkdtemp(join(tmpdir(),"hail-managed-transfer-"));
  const did=`did:plc:${"a".repeat(24)}`,vault={...generated.vault,did},vaultPath=join(directory,"vault.json"),statePath=join(directory,"state.json");
  await writeFile(vaultPath,JSON.stringify(vault),{mode:0o600});
  const key=async()=>{const pair=await crypto.subtle.generateKey("Ed25519",true,["sign","verify"]),raw=new Uint8Array(await crypto.subtle.exportKey("raw",pair.publicKey));
    return {pair,did:`did:key:${base58btc.encode(new Uint8Array([0xed,1,...raw]))}`};};
  const [sourceIdentity,sourceMessaging,destinationRotation,destinationIdentity,destinationMessaging]=await Promise.all([key(),key(),key(),key(),key()]);
  const sign=async(value:Record<string,HailValue>,pair:CryptoKeyPair)=>{const payload=encodeDeterministic(value),tag=new TextEncoder().encode(`${value.type}.v1\0`),input=new Uint8Array(tag.length+payload.length);
    input.set(tag);input.set(payload,tag.length);return {payload:encodeBase64Url(payload),signature:encodeBase64Url(new Uint8Array(await crypto.subtle.sign("Ed25519",pair.privateKey,input)))};};
  const hash=(bytes:Uint8Array)=>new Uint8Array(createHash("sha256").update(bytes).digest());
  const account={provider:"https://source.example.com",accountId:randomUUID(),did,custodyProfile:"managed",migrationState:null as string|null,
    scopes:["account:read","account:write"],ownerRecoveryPublicKey:vault.recovery.publicDidKey,identityPublicKey:sourceIdentity.did};
  let grant:Record<string,any>,acknowledgement:any,offer:any,lostOffer=true;
  const status=()=>({type:"hailp.managed-transfer-status",version:1,provider:account.provider,accountId:account.accountId,did,
    phase:"offer-ready",destinationServiceBase:"https://target.example.com/hail",expiresAt:new Date(Date.now()+3600000).toISOString(),
    originConfirmed:true,transferId:offer&&(decodeDeterministic(decodeBase64Url(offer.payload)) as Record<string,any>).transfer_id,
    acknowledgement,offer});
  const requests:unknown[]=[];
  const client={account:async()=>({...account}),request:async(path:string,body?:Record<string,unknown>)=>{
    if(path==="/transfers/managed")return status();
    requests.push(body);grant=decodeDeterministic(decodeBase64Url(body!.payload as string)) as Record<string,any>;
    acknowledgement??=await sign({type:"hail.managed-transfer-acknowledgement",version:1,did,nonce:grant.nonce,
      source_service_base:grant.source_service_base,destination_service_base:grant.destination_service_base,
      grant_digest:hash(decodeBase64Url(body!.payload as string)),source_messaging_key:sourceMessaging.did,issued_at:grant.issued_at,expires_at:grant.expires_at},sourceMessaging.pair);
    offer??=await sign({type:"hail.managed-transfer-offer",version:1,did,nonce:grant.nonce,transfer_id:randomUUID(),
      source_service_base:grant.source_service_base,destination_service_base:grant.destination_service_base,
      grant_digest:hash(decodeBase64Url(body!.payload as string)),acknowledgement_digest:hash(decodeBase64Url(acknowledgement.payload)),
      destination_rotation_key:destinationRotation.did,destination_identity_key:destinationIdentity.did,
      destination_messaging_key:destinationMessaging.did,issued_at:grant.issued_at,expires_at:grant.expires_at},destinationMessaging.pair);
    if(lostOffer){lostOffer=false;throw new Error("lost source response");}return status();
  }} as unknown as AccountApiClient;
  let prompts=0;const secret=async()=>{prompts++;return encodeBase64Url(generated.recoverySecret);};
  try {
    const prepare=()=>managedTransferOffer(client,"https://target.example.com",vaultPath,statePath,secret);
    await expect(prepare()).rejects.toThrow("lost source response");
    expect(await prepare()).toMatchObject({phase:"offer-ready",destinationIdentityPublicKey:destinationIdentity.did});
    expect(prompts).toBe(1);expect(requests[0]).toEqual(requests[1]);expect((await stat(statePath)).mode&0o777).toBe(0o600);
    expect((await managedTransferStatus(client)).phase).toBe("offer-ready");
    let lostReservation=true,reservation:any;const targetBodies:string[]=[];
    const transport=(async(url:string,init:RequestInit)=>{
      expect(url).toBe("https://target.example.com/.well-known/hail/transfers/managed-reservations");
      expect(new Headers(init.headers).has("Authorization")).toBe(false);targetBodies.push(init.body as string);
      const selectionWire=JSON.parse(init.body as string),selection=decodeDeterministic(decodeBase64Url(selectionWire.payload)) as Record<string,any>;
      reservation??=await sign({type:"hail.managed-transfer-reservation",version:1,did,nonce:selection.nonce,transfer_id:selection.transfer_id,
        offer_digest:selection.offer_digest,selection_digest:hash(decodeBase64Url(selectionWire.payload)),address:selection.address,
        destination_rotation_key:destinationRotation.did,destination_identity_key:destinationIdentity.did,destination_messaging_key:destinationMessaging.did,
        issued_at:selection.issued_at,expires_at:selection.expires_at},destinationMessaging.pair);
      if(lostReservation){lostReservation=false;throw new Error("lost destination response");}
      return new Response(JSON.stringify(reservation),{status:202,headers:{"Content-Type":"application/hail-transfer+json"}});
    }) as typeof fetch;
    const select=()=>selectManagedTransferAddress(client,"alice",vaultPath,statePath,secret,transport);
    await expect(select()).rejects.toThrow("lost destination response");
    expect(await select()).toMatchObject({address:"alice@target.example.com",requestAcknowledged:false});
    expect(prompts).toBe(2);expect(targetBodies[0]).toBe(targetBodies[1]);
    await expect(selectManagedTransferAddress(client,"bob",vaultPath,statePath,secret,transport)).rejects.toThrow("reviewed address/Offer");
    const saved=JSON.parse(await readFile(statePath,"utf8"));expect(saved.reservation).toEqual(reservation);
  } finally {generated.recoverySecret.fill(0);await rm(directory,{recursive:true,force:true});}
});
