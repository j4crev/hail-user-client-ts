import { createHash, randomBytes, randomUUID } from "node:crypto";
import { P256Keypair } from "@atproto/crypto";
import { assureValidSig, validateOperationLog } from "@did-plc/lib";
import { createWebCryptoVerifier, verifySignedPayload, type HailAddressBinding, type HailGrant } from "@hailproto/codec";
import { base58btc } from "multiformats/bases/base58";
import { describe, expect, it } from "vitest";
import { createUserVault, unlockUserVault, type UserMigrationConsent, type UserVaultFile } from "../src/vault.js";
import { verifyPortableMigrationConsent } from "../../hail-server-ts/src/migration/consent.js";

async function edDidKey() {
  const pair = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const bytes = new Uint8Array(34);
  bytes.set([0xed, 0x01]);
  bytes.set(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)), 2);
  return `did:key:${base58btc.encode(bytes)}`;
}

function verifier(publicDidKey: string) {
  return createWebCryptoVerifier(async () => {
    const bytes = base58btc.decode(publicDidKey.slice("did:key:".length));
    return crypto.subtle.importKey("raw", Uint8Array.from(bytes.slice(2)), "Ed25519", false, ["verify"]);
  });
}

describe("user-owned portable vault", () => {
  it("recovers two independent keys from an encrypted export and rejects an incorrect recovery secret", async () => {
    const generated = await createUserVault();
    const backup = JSON.parse(JSON.stringify(generated.vault)) as UserVaultFile;
    expect(generated.recoverySecret).toHaveLength(32);
    expect(backup.recovery.publicDidKey).not.toBe(backup.identity.publicDidKey);
    expect(backup.recovery.nonce).not.toBe(backup.identity.nonce);
    expect(Object.keys(backup)).toEqual(["type", "version", "did", "createdAt", "recovery", "identity"]);
    await expect(unlockUserVault(backup, randomBytes(32))).rejects.toThrow();
    const restored = await unlockUserVault(backup, generated.recoverySecret);
    expect(restored.vault.recovery.publicDidKey).toBe(generated.vault.recovery.publicDidKey);
    generated.recoverySecret.fill(0);
  });

  it("signs exact PLC state, Grants, bindings and migration consent without provider custody", async () => {
    const generated = await createUserVault();
    const client = await unlockUserVault(JSON.parse(JSON.stringify(generated.vault)) as UserVaultFile,
      generated.recoverySecret);
    const providerKey = await P256Keypair.create({ exportable: true });
    const messagingKey = await edDidKey();
    const genesis = await client.signPlcOperation({ type: "plc_operation", prev: null,
      rotationKeys: [generated.vault.recovery.publicDidKey, providerKey.did()],
      verificationMethods: { "hail-identity": generated.vault.identity.publicDidKey,
        "hail-messaging": messagingKey }, alsoKnownAs: [],
      services: { hail: { type: "HailMessaging", endpoint: "https://provider.example.com/hail" } },
    });
    expect((await assureValidSig([generated.vault.recovery.publicDidKey], genesis.operation)))
      .toBe(generated.vault.recovery.publicDidKey);
    expect((await validateOperationLog(genesis.did, [genesis.operation]))?.rotationKeys[0])
      .toBe(generated.vault.recovery.publicDidKey);
    await client.bindDid(genesis.did, genesis.operation);
    const now = Math.floor(Date.now() / 1000);
    const binding: HailAddressBinding = { type: "hail.address-binding", version: 1,
      address: "alice@user.example.com", did: genesis.did, issued_at: now,
      expires_at: now + 90 * 86400, key_id: `${genesis.did}#hail-identity` };
    const signedBinding = await client.signAddressBinding(binding);
    expect((await verifySignedPayload("hail.address-binding", signedBinding,
      verifier(generated.vault.identity.publicDidKey))).payload.address).toBe(binding.address);
    const hash = new Uint8Array(createHash("sha256").update(signedBinding).digest());
    const grant: HailGrant = { type: "hail.grant", version: 1,
      grant_id: "01954144-8097-7a9d-a7a8-ef29a823eaf1", revision: 1, previous: null,
      grantor: genesis.did, grantee: `did:plc:${"b".repeat(24)}`,
      scope: [{ type: "categories", values: ["updates"] }], status: "active",
      issued_at: now, updated_at: now, expires_at: null,
      consent_context: { grantee_address: "bob@example.com",
        address_binding_hash: { algorithm: "sha-256", value: hash },
        sender_profile_hash: { algorithm: "sha-256", value: hash } },
      key_id: `${genesis.did}#hail-identity` };
    expect((await verifySignedPayload("hail.grant", await client.signGrant(grant),
      verifier(generated.vault.identity.publicDidKey))).payload.grantor).toBe(genesis.did);
    const destination = await P256Keypair.create({ exportable: true });
    const consent: UserMigrationConsent = { type: "hail.portable-migration-consent", version: 1,
      did: genesis.did, transfer_id: randomUUID(), snapshot_digest: randomBytes(32),
      plc_operation_sha256: randomBytes(32), source_service_base: "https://provider.example.com/hail",
      destination_service_base: "https://next.example.com/hail", destination_address: binding.address,
      destination_rotation_key: destination.did(), destination_messaging_key: await edDidKey(),
      user_recovery_key: generated.vault.recovery.publicDidKey,
      user_identity_key: generated.vault.identity.publicDidKey, created_at: now, expires_at: now + 3600 };
    const signedConsent = await client.signMigrationConsent(consent);
    expect((await verifyPortableMigrationConsent(signedConsent,
      generated.vault.identity.publicDidKey, now)).transfer_id).toBe(consent.transfer_id);
    generated.recoverySecret.fill(0);
  });
});
