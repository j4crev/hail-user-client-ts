import { createHash } from "node:crypto";
import { open, readFile, stat, unlink } from "node:fs/promises";
import { decodeBase64Url, decodeDeterministic, encodeBase64Url,
  type HailAddressBinding } from "@hailproto/codec";
import { base58btc } from "multiformats/bases/base58";
import { unlockUserVault, type UserMigrationConsent, type UserVaultFile } from "../vault.js";
import { readRecoverySecret } from "./private-input.js";

async function privateFile(path: string, limit: number): Promise<Uint8Array> {
  const info = await stat(path);
  if (!info.isFile() || info.size < 1 || info.size > limit || (info.mode & 0o077) !== 0) {
    throw new Error("Cutover input must be a bounded private mode-0600 regular file");
  }
  return new Uint8Array(await readFile(path));
}
async function save(path: string, bytes: Uint8Array): Promise<void> {
  const file = await open(path, "wx", 0o600);
  let incomplete = false;
  try { await file.writeFile(bytes); }
  catch (error) { incomplete = true; throw error; }
  finally { await file.close(); if (incomplete) await unlink(path); }
}
function data(bytes: Uint8Array): Record<string, unknown> {
  const decoded: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) throw new Error("Invalid cutover file");
  return decoded as Record<string, unknown>;
}
async function verifySignature(kind: string, payload: Uint8Array,
  signature: Uint8Array, didKey: string): Promise<void> {
  const keyBytes = base58btc.decode(didKey.slice("did:key:".length));
  if (keyBytes.length !== 34 || keyBytes[0] !== 0xed || keyBytes[1] !== 0x01) {
    throw new Error("Cutover signer is not an Ed25519 DID key");
  }
  const publicKey = await crypto.subtle.importKey("raw", Uint8Array.from(keyBytes.slice(2)),
    "Ed25519", false, ["verify"]);
  const prefix = new TextEncoder().encode(`${kind}\0`);
  const input = new Uint8Array(prefix.length + payload.length);
  input.set(prefix); input.set(payload, prefix.length);
  if (!await crypto.subtle.verify("Ed25519", publicKey,
    Uint8Array.from(signature), Uint8Array.from(input))) {
    throw new Error("Cutover record is not signed by the expected provider key");
  }
}

const [vaultPath, snapshotPath, offerPath, reservationPath,
  consentPath, operationPath, bindingPath] = Bun.argv.slice(2);
if (!vaultPath || !snapshotPath || !offerPath || !reservationPath ||
  !consentPath || !operationPath || !bindingPath || Bun.argv.length !== 9) {
  throw new Error("Usage: bun run poc:sign-cutover -- <user-vault> <source-snapshot> <origin-verified-offer> <signed-reservation> <new-consent-json> <new-plc-operation-json> <new-binding.cose>");
}
const secret = decodeBase64Url(await readRecoverySecret());
try {
  const vault = JSON.parse(new TextDecoder().decode(await privateFile(vaultPath, 16_384))) as UserVaultFile;
  const user = await unlockUserVault(vault, secret);
  if (!vault.did) throw new Error("POC cutover needs a vault bound to the original private-PLC DID");
  const snapshot = data(await privateFile(snapshotPath, 100_000_000));
  if (snapshot.type !== "hail.portable-migration-transfer" || snapshot.version !== 2 ||
    typeof snapshot.manifest !== "string" || typeof snapshot.digest !== "string" ||
    typeof snapshot.signature !== "string" || typeof snapshot.sourceMessagingPublicKey !== "string") {
    throw new Error("Source did not supply a signed portable snapshot");
  }
  const manifestBytes = decodeBase64Url(snapshot.manifest);
  const digest = new Uint8Array(createHash("sha256").update(manifestBytes).digest());
  if (!Buffer.from(digest).equals(Buffer.from(decodeBase64Url(snapshot.digest)))) {
    throw new Error("Source snapshot digest mismatch");
  }
  await verifySignature("hail-migration-snapshot-v2", digest,
    decodeBase64Url(snapshot.signature), snapshot.sourceMessagingPublicKey);
  const manifest = data(manifestBytes) as {
    did: string; transferId: string; sourceServiceBase: string;
    destinationServiceBase: string; destinationRotationPublicKey: string;
    destinationMessagingPublicKey: string; tables: {
      account_keys: { role: string; public_key: string }[];
      portable_custody_evidence: { user_recovery_public_key: string;
        user_identity_public_key: string; monitor_verification_mode: string }[];
      plc_operation_evidence: { operation_cid: string; expected_state: unknown }[];
    } };
  const custody = manifest.tables.portable_custody_evidence[0];
  const oldKey = manifest.tables.account_keys.find((item) => item.role === "plc-rotation")?.public_key;
  const evidence = manifest.tables.plc_operation_evidence.at(-1);
  if (manifest.did !== vault.did || !custody || custody.monitor_verification_mode !== "poc-local" ||
    custody.user_identity_public_key !== vault.identity.publicDidKey ||
    custody.user_recovery_public_key !== vault.recovery.publicDidKey || !oldKey || !evidence) {
    throw new Error("POC snapshot is not for this user-held recovery and identity key");
  }
  const prior = (typeof evidence.expected_state === "string" ?
    JSON.parse(evidence.expected_state) : evidence.expected_state) as {
      rotationKeys: string[]; verificationMethods: Record<string, string>;
      alsoKnownAs: string[]; services: Record<string, { type: string; endpoint: string }> };
  if (!Array.isArray(prior.rotationKeys) || prior.rotationKeys[0] !== vault.recovery.publicDidKey ||
    prior.verificationMethods["hail-identity"] !== vault.identity.publicDidKey ||
    prior.verificationMethods["hail-messaging"] !== snapshot.sourceMessagingPublicKey ||
    prior.services.hail?.endpoint !== manifest.sourceServiceBase ||
    !prior.rotationKeys.includes(oldKey) || !Array.isArray(prior.alsoKnownAs)) {
    throw new Error("Original PLC state no longer agrees with the user vault and source snapshot");
  }
  const offerRow = data(await privateFile(offerPath, 16_384));
  const receiptRow = data(await privateFile(reservationPath, 16_384));
  if (typeof offerRow.payload !== "string" || typeof offerRow.signature !== "string" ||
    typeof receiptRow.payload !== "string" || typeof receiptRow.signature !== "string") {
    throw new Error("Offer or address reservation lacks a signed representation");
  }
  const offerBytes = decodeBase64Url(offerRow.payload);
  const offer = decodeDeterministic(offerBytes) as unknown as {
    did: string; transfer_id: string; source_service_base: string;
    destination_service_base: string; destination_rotation_key: string;
    destination_messaging_key: string };
  if (offer.did !== manifest.did || offer.transfer_id !== manifest.transferId ||
    offer.source_service_base !== manifest.sourceServiceBase ||
    offer.destination_service_base !== manifest.destinationServiceBase ||
    offer.destination_rotation_key !== manifest.destinationRotationPublicKey ||
    offer.destination_messaging_key !== manifest.destinationMessagingPublicKey) {
    throw new Error("Origin-verified Offer does not match the exact snapshot destination");
  }
  await verifySignature("hail.transfer-offer.v1", offerBytes,
    decodeBase64Url(offerRow.signature), offer.destination_messaging_key);
  const receiptBytes = decodeBase64Url(receiptRow.payload);
  const receipt = decodeDeterministic(receiptBytes) as unknown as {
    did: string; transfer_id: string; address: string; offer_digest: Uint8Array };
  if (receipt.did !== vault.did || receipt.transfer_id !== manifest.transferId ||
    !Buffer.from(receipt.offer_digest).equals(createHash("sha256").update(offerBytes).digest()) ||
    receipt.address.slice(receipt.address.indexOf("@") + 1) !==
      new URL(manifest.destinationServiceBase).hostname) {
    throw new Error("Destination reservation is not the user-approved Hail address");
  }
  await verifySignature("hail.transfer-reservation.v1", receiptBytes,
    decodeBase64Url(receiptRow.signature), offer.destination_messaging_key);
  const rotationKeys = [...prior.rotationKeys.filter((key) => key !== oldKey),
    manifest.destinationRotationPublicKey];
  const update = await user.signPlcOperation({ type: "plc_operation", prev: evidence.operation_cid,
    rotationKeys, verificationMethods: { ...prior.verificationMethods,
      "hail-messaging": manifest.destinationMessagingPublicKey },
    alsoKnownAs: prior.alsoKnownAs, services: { ...prior.services,
      hail: { type: "HailMessaging", endpoint: manifest.destinationServiceBase } },
  });
  if (update.did !== vault.did) throw new Error("Signed cutover changed the DID");
  const now = Math.floor(Date.now() / 1000);
  const consent: UserMigrationConsent = {
    type: "hail.portable-migration-consent", version: 1, did: vault.did,
    transfer_id: manifest.transferId, snapshot_digest: digest,
    plc_operation_sha256: new Uint8Array(createHash("sha256").update(update.dagCbor).digest()),
    source_service_base: manifest.sourceServiceBase,
    destination_service_base: manifest.destinationServiceBase,
    destination_address: receipt.address,
    destination_rotation_key: manifest.destinationRotationPublicKey,
    destination_messaging_key: manifest.destinationMessagingPublicKey,
    user_recovery_key: vault.recovery.publicDidKey,
    user_identity_key: vault.identity.publicDidKey, created_at: now, expires_at: now + 3600,
  };
  const signedConsent = await user.signMigrationConsent(consent);
  const signedBinding = await user.signAddressBinding({ type: "hail.address-binding", version: 1,
    address: receipt.address, did: vault.did, issued_at: now,
    expires_at: now + 90 * 86400, key_id: `${vault.did}#hail-identity` });
  await save(consentPath, new TextEncoder().encode(JSON.stringify({
    type: "hail.portable-migration-consent", version: 1,
    payload: encodeBase64Url(signedConsent.payloadBytes),
    signature: encodeBase64Url(signedConsent.signature),
  })));
  await save(operationPath, new TextEncoder().encode(JSON.stringify(update.operation)));
  await save(bindingPath, signedBinding);
  console.info(JSON.stringify({ did: vault.did, transferId: manifest.transferId,
    address: receipt.address, operationCid: update.cid, profile: "private-poc" }));
} finally { secret.fill(0); }
