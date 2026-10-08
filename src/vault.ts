import { randomBytes } from "node:crypto";
import { cidForCbor } from "@atproto/common";
import { P256Keypair } from "@atproto/crypto";
import { assureValidSig, didForCreateOp, signOperation, type Operation, type UnsignedOperation } from "@did-plc/lib";
import { createWebCryptoSigner, decodeBase64Url, encodeBase64Url, encodeDeterministic, signPayload,
  type HailAddressBinding, type HailGrant, type HailValue } from "@hailproto/codec";
import * as dagCbor from "@ipld/dag-cbor";
import { base58btc } from "multiformats/bases/base58";

type Role = "user-recovery" | "hail-identity";

export interface EncryptedUserKey {
  role: Role;
  publicDidKey: string;
  nonce: string;
  ciphertext: string;
}

export interface UserVaultFile {
  type: "hail.user-vault";
  version: 1;
  did: string | null;
  createdAt: string;
  recovery: EncryptedUserKey;
  identity: EncryptedUserKey;
}

export interface VaultCreation { vault: UserVaultFile; recoverySecret: Uint8Array; }

export interface UserMigrationConsent {
  type: "hail.portable-migration-consent";
  version: 1;
  did: string;
  transfer_id: string;
  snapshot_digest: Uint8Array;
  plc_operation_sha256: Uint8Array;
  source_service_base: string;
  destination_service_base: string;
  destination_address: string;
  destination_rotation_key: string;
  destination_messaging_key: string;
  user_recovery_key: string;
  user_identity_key: string;
  created_at: number;
  expires_at: number;
}

export interface UserTransferGrant {
  type: "hail.transfer-grant";
  version: 1;
  did: string;
  nonce: string;
  source_service_base: string;
  destination_service_base: string;
  destination_domain: string;
  issued_at: number;
  expires_at: number;
}

export interface UserTransferAddressSelection {
  type: "hail.transfer-address-selection"; version: 1; did: string; nonce: string;
  transfer_id: string; grant_digest: Uint8Array; offer_digest: Uint8Array;
  address: string; selection_nonce: string; issued_at: number; expires_at: number;
}

export interface UserTransferCancellation {
  type: "hail.transfer-cancellation"; version: 1; did: string; nonce: string;
  grant_digest: Uint8Array; issued_at: number; expires_at: number;
}

function bytes(value: Uint8Array): Uint8Array<ArrayBuffer> { return Uint8Array.from(value); }
function aad(role: Role, didKey: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`hail-user-vault-v1\0${role}\0${didKey}`);
}
async function cipher(secret: Uint8Array): Promise<CryptoKey> {
  if (secret.length !== 32) throw new Error("Vault recovery secret must be exactly 256 bits");
  return crypto.subtle.importKey("raw", bytes(secret), "AES-GCM", false, ["encrypt", "decrypt"]);
}
async function seal(key: CryptoKey, role: Role, publicDidKey: string, privateBytes: Uint8Array): Promise<EncryptedUserKey> {
  const nonce = randomBytes(12);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: bytes(nonce),
    additionalData: aad(role, publicDidKey), tagLength: 128 }, key, bytes(privateBytes)));
  return { role, publicDidKey, nonce: encodeBase64Url(nonce), ciphertext: encodeBase64Url(ciphertext) };
}
async function unseal(key: CryptoKey, value: EncryptedUserKey, role: Role): Promise<Uint8Array> {
  if (value.role !== role || typeof value.publicDidKey !== "string") throw new Error("Vault role mismatch");
  const nonce = decodeBase64Url(value.nonce);
  const ciphertext = decodeBase64Url(value.ciphertext);
  if (nonce.length !== 12 || ciphertext.length < 17) throw new Error("Vault ciphertext or nonce is invalid");
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes(nonce),
    additionalData: aad(role, value.publicDidKey), tagLength: 128 }, key, bytes(ciphertext)));
}

export async function createUserVault(): Promise<VaultCreation> {
  const recovery = await P256Keypair.create({ exportable: true });
  const identity = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const prefixed = new Uint8Array(34);
  prefixed.set([0xed, 0x01]);
  prefixed.set(new Uint8Array(await crypto.subtle.exportKey("raw", identity.publicKey)), 2);
  const identityDidKey = `did:key:${base58btc.encode(prefixed)}`;
  const recoverySecret = randomBytes(32);
  const key = await cipher(recoverySecret);
  const recoveryBytes = new Uint8Array(await recovery.export());
  const identityBytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", identity.privateKey));
  let sealedRecovery;
  let sealedIdentity;
  try {
    [sealedRecovery, sealedIdentity] = await Promise.all([
      seal(key, "user-recovery", recovery.did(), recoveryBytes),
      seal(key, "hail-identity", identityDidKey, identityBytes),
    ]);
  } finally { recoveryBytes.fill(0); identityBytes.fill(0); }
  return { vault: { type: "hail.user-vault", version: 1, did: null,
    createdAt: new Date().toISOString(), recovery: sealedRecovery, identity: sealedIdentity },
    recoverySecret: bytes(recoverySecret) };
}

export async function unlockUserVault(vault: UserVaultFile, recoverySecret: Uint8Array): Promise<UnlockedUserVault> {
  if (vault.type !== "hail.user-vault" || vault.version !== 1 ||
    (vault.did !== null && !/^did:plc:[a-z2-7]{24}$/.test(vault.did)) ||
    vault.recovery.publicDidKey === vault.identity.publicDidKey) throw new Error("Invalid user vault representation");
  const key = await cipher(recoverySecret);
  const [rotationBytes, identityBytes] = await Promise.all([
    unseal(key, vault.recovery, "user-recovery"), unseal(key, vault.identity, "hail-identity"),
  ]);
  try {
    // The official P-256 keypair may retain its input buffer. Pass a distinct
    // copy so clearing our temporary decrypted bytes does not zero the signer.
    const recovery = await P256Keypair.import(bytes(rotationBytes));
    const identity = await crypto.subtle.importKey("pkcs8", bytes(identityBytes), "Ed25519", false, ["sign"]);
    const publicBytes = base58btc.decode(vault.identity.publicDidKey.slice("did:key:".length));
    if (recovery.did() !== vault.recovery.publicDidKey || publicBytes.length !== 34 ||
      publicBytes[0] !== 0xed || publicBytes[1] !== 0x01) throw new Error("Vault public keys do not match private keys");
    const challenge = randomBytes(32);
    const signature = await crypto.subtle.sign("Ed25519", identity, bytes(challenge));
    const publicKey = await crypto.subtle.importKey("raw", bytes(publicBytes.slice(2)), "Ed25519", false, ["verify"]);
    if (!await crypto.subtle.verify("Ed25519", publicKey, signature, bytes(challenge))) {
      throw new Error("Vault identity private key does not match its public key");
    }
    return new UnlockedUserVault(vault, recovery, identity);
  } finally { rotationBytes.fill(0); identityBytes.fill(0); }
}

export class UnlockedUserVault {
  constructor(readonly vault: UserVaultFile, private readonly recovery: P256Keypair,
    private readonly identity: CryptoKey) {}

  async signPlcOperation(unsigned: UnsignedOperation): Promise<{ operation: Operation;
    dagCbor: Uint8Array; cid: string; did: string }> {
    if (unsigned.rotationKeys[0] !== this.vault.recovery.publicDidKey ||
      unsigned.verificationMethods["hail-identity"] !== this.vault.identity.publicDidKey ||
      !Array.isArray(unsigned.alsoKnownAs)) {
      throw new Error("PLC state must preserve the user's top key, identity role and aliases");
    }
    const operation = await signOperation(unsigned, this.recovery);
    const did = unsigned.prev === null ? await didForCreateOp(operation) : this.vault.did;
    if (!did || !/^did:plc:[a-z2-7]{24}$/.test(did)) throw new Error("PLC update requires a bound DID");
    const dagCborBytes = new Uint8Array(dagCbor.encode(operation));
    if (dagCborBytes.length > 7500) throw new Error("PLC operation exceeds the directory limit");
    return { operation, dagCbor: dagCborBytes, cid: (await cidForCbor(operation)).toString(), did };
  }

  async signManagedGenesis(unsigned: UnsignedOperation) {
    if (unsigned.prev !== null || unsigned.rotationKeys[0] !== this.vault.recovery.publicDidKey ||
      unsigned.verificationMethods["hail-identity"] === this.vault.identity.publicDidKey || unsigned.alsoKnownAs.length !== 0) {
      throw new Error("Managed genesis requires explicit provider identity and owner-controlled recovery");
    }
    const operation = await signOperation(unsigned,this.recovery);
    return {operation,did:await didForCreateOp(operation)};
  }

  async bindDid(did: string, signedGenesis: Operation, managed = false): Promise<UserVaultFile> {
    if (this.vault.did !== null || signedGenesis.prev !== null ||
      signedGenesis.rotationKeys[0] !== this.vault.recovery.publicDidKey ||
      (!managed && signedGenesis.verificationMethods["hail-identity"] !== this.vault.identity.publicDidKey) ||
      !/^did:plc:[a-z2-7]{24}$/.test(did)) throw new Error("Cannot bind vault to this DID");
    await assureValidSig([this.vault.recovery.publicDidKey], signedGenesis);
    if (await didForCreateOp(signedGenesis) !== did) throw new Error("Vault DID does not match exact signed genesis");
    this.vault.did = did;
    return this.vault;
  }

  async signGrant(payload: HailGrant): Promise<Uint8Array> {
    if (!this.vault.did || payload.grantor !== this.vault.did ||
      payload.key_id !== `${this.vault.did}#hail-identity`) throw new Error("Grant signer DID is not the user vault");
    return signPayload("hail.grant", payload,
      createWebCryptoSigner(payload.key_id, this.identity));
  }

  async signTransferGrant(grant: UserTransferGrant): Promise<{
    payloadBytes: Uint8Array; signature: Uint8Array }> {
    if (!this.vault.did || grant.did !== this.vault.did ||
      grant.type !== "hail.transfer-grant" || grant.version !== 1 ||
      !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(grant.nonce) ||
      !Number.isSafeInteger(grant.issued_at) || !Number.isSafeInteger(grant.expires_at) ||
      grant.expires_at <= grant.issued_at || grant.expires_at - grant.issued_at > 3600 ||
      grant.destination_service_base !== `https://${grant.destination_domain}/hail` ||
      grant.source_service_base === grant.destination_service_base) {
      throw new Error("Transfer grant must name this DID and one short-lived destination");
    }
    const payloadBytes = encodeDeterministic(grant as unknown as HailValue);
    const tag = new TextEncoder().encode("hail.transfer-grant.v1\0");
    const input = new Uint8Array(tag.length + payloadBytes.length);
    input.set(tag); input.set(payloadBytes, tag.length);
    return { payloadBytes, signature: new Uint8Array(await crypto.subtle.sign("Ed25519", this.identity, bytes(input))) };
  }

  async signTransferAddressSelection(selection: UserTransferAddressSelection): Promise<{
    payloadBytes: Uint8Array; signature: Uint8Array }> {
    if (!this.vault.did || selection.did !== this.vault.did ||
      selection.type !== "hail.transfer-address-selection" || selection.version !== 1 ||
      selection.grant_digest.length !== 32 || selection.offer_digest.length !== 32 ||
      !Number.isSafeInteger(selection.issued_at) || !Number.isSafeInteger(selection.expires_at) ||
      selection.expires_at <= selection.issued_at || selection.expires_at - selection.issued_at > 3600) {
      throw new Error("Address selection must bind the user's DID, exact offer and grant");
    }
    const payloadBytes = encodeDeterministic(selection as unknown as HailValue);
    const tag = new TextEncoder().encode("hail.transfer-address-selection.v1\0");
    const input = new Uint8Array(tag.length + payloadBytes.length);
    input.set(tag); input.set(payloadBytes, tag.length);
    return { payloadBytes, signature: new Uint8Array(await crypto.subtle.sign("Ed25519", this.identity, bytes(input))) };
  }

  async signTransferCancellation(cancellation: UserTransferCancellation): Promise<{
    payloadBytes: Uint8Array; signature: Uint8Array }> {
    if (!this.vault.did || cancellation.did !== this.vault.did ||
      cancellation.type !== "hail.transfer-cancellation" || cancellation.version !== 1 ||
      cancellation.grant_digest.length !== 32 ||
      !Number.isSafeInteger(cancellation.issued_at) || !Number.isSafeInteger(cancellation.expires_at) ||
      cancellation.expires_at <= cancellation.issued_at ||
      cancellation.expires_at - cancellation.issued_at > 3600) {
      throw new Error("Cancellation must bind the exact user-initiated transfer");
    }
    const payloadBytes = encodeDeterministic(cancellation as unknown as HailValue);
    const tag = new TextEncoder().encode("hail.transfer-cancellation.v1\0");
    const input = new Uint8Array(tag.length + payloadBytes.length);
    input.set(tag); input.set(payloadBytes, tag.length);
    return { payloadBytes, signature: new Uint8Array(await crypto.subtle.sign("Ed25519", this.identity, bytes(input))) };
  }

  async signAddressBinding(payload: HailAddressBinding): Promise<Uint8Array> {
    if (!this.vault.did || payload.did !== this.vault.did ||
      payload.key_id !== `${this.vault.did}#hail-identity`) throw new Error("Binding signer DID is not the user vault");
    return signPayload("hail.address-binding", payload,
      createWebCryptoSigner(payload.key_id, this.identity));
  }

  signMigrationConsent(consent: UserMigrationConsent): Promise<{
    payloadBytes: Uint8Array; signature: Uint8Array }> {
    if (!this.vault.did || consent.did !== this.vault.did ||
      consent.user_identity_key !== this.vault.identity.publicDidKey ||
      consent.user_recovery_key !== this.vault.recovery.publicDidKey) {
      throw new Error("Migration consent does not match the bound user identity");
    }
    return signMigrationConsentBytes(consent, this.identity);
  }
}

async function signMigrationConsentBytes(consent: UserMigrationConsent, key: CryptoKey) {
  const payloadBytes = encodeDeterministic(consent as unknown as HailValue);
  const tag = new TextEncoder().encode("hail.portable-migration-consent.v1\0");
  const message = new Uint8Array(tag.length + payloadBytes.length);
  message.set(tag);
  message.set(payloadBytes, tag.length);
  return { payloadBytes,
    signature: new Uint8Array(await crypto.subtle.sign("Ed25519", key, bytes(message))) };
}
