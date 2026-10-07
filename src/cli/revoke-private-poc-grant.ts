import { createHash } from "node:crypto";
import { open, readFile, stat, unlink } from "node:fs/promises";
import { isDeepStrictEqual } from "node:util";
import { createWebCryptoVerifier, decodeBase64Url, encodeBase64Url, inspectSignedPayload,
  verifySignedPayload, type HailGrant } from "@hailproto/codec";
import { base58btc } from "multiformats/bases/base58";
import { unlockUserVault, type UserVaultFile } from "../vault.js";
import { readRecoverySecret } from "./private-input.js";

async function privateFile(path: string, limit: number): Promise<Uint8Array> {
  const info = await stat(path);
  if (!info.isFile() || info.size < 1 || info.size > limit || (info.mode & 0o077) !== 0) {
    throw new Error("Grant revocation files must be bounded private mode-0600 regular files");
  }
  return new Uint8Array(await readFile(path));
}
const [vaultPath, grantPath, expectedGrantId, expectedSenderAddress, outputPath] = Bun.argv.slice(2);
if (!vaultPath || !grantPath || !expectedGrantId || !expectedSenderAddress || !outputPath || Bun.argv.length !== 7) {
  throw new Error("Usage: bun run poc:revoke-grant -- <private-vault> <current-signed-grant.cose> <reviewed-grant-id> <reviewed-sender-address> <new-signed-revocation.cose>");
}
const secret = decodeBase64Url(await readRecoverySecret());
try {
  const user = await unlockUserVault(JSON.parse(new TextDecoder().decode(
    await privateFile(vaultPath, 16_384))) as UserVaultFile, secret);
  if (!user.vault.did) throw new Error("Grant revocation needs a vault bound to the grantor DID");
  const publicBytes = base58btc.decode(user.vault.identity.publicDidKey.slice("did:key:".length));
  const key = await crypto.subtle.importKey("raw", Uint8Array.from(publicBytes.slice(2)), "Ed25519", false, ["verify"]);
  const verifier = createWebCryptoVerifier(async (kid) => {
    if (kid !== `${user.vault.did}#hail-identity`) throw new Error("Grant identity signer does not match this user");
    return key;
  });
  const currentBytes = await privateFile(grantPath, 262_144);
  const { payload: current } = await verifySignedPayload("hail.grant", currentBytes, verifier);
  if (current.grantor !== user.vault.did || current.status !== "active" ||
    current.grant_id !== expectedGrantId || current.consent_context.grantee_address !== expectedSenderAddress) {
    throw new Error("Current Grant does not match the user's reviewed relationship");
  }
  let existing: Uint8Array | null = null;
  try { existing = await privateFile(outputPath, 262_144); }
  catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
  }
  const now = Math.floor(Date.now() / 1000);
  const updatedAt = existing ? inspectSignedPayload("hail.grant", existing).payload.updated_at :
    Math.max(now, current.updated_at + 1);
  if (updatedAt <= current.updated_at || updatedAt > now + 300) throw new Error("Revocation timestamp is invalid");
  const payload: HailGrant = { ...current, revision: current.revision + 1,
    previous: new Uint8Array(createHash("sha256").update(currentBytes).digest()),
    status: "revoked", updated_at: updatedAt };
  const representation = existing ?? await user.signGrant(payload);
  const verified = await verifySignedPayload("hail.grant", representation, verifier);
  if (!isDeepStrictEqual(verified.payload, payload)) throw new Error("Existing signed revocation conflicts with this Grant");
  if (!existing) {
    const file = await open(outputPath, "wx", 0o600);
    let incomplete = false;
    try { await file.writeFile(representation); }
    catch (error) { incomplete = true; throw error; }
    finally { await file.close(); if (incomplete) await unlink(outputPath); }
  }
  console.info(JSON.stringify({ grantId: payload.grant_id, revision: payload.revision,
    state: "signed-revocation", reviewedSenderAddress: expectedSenderAddress,
    digest: encodeBase64Url(createHash("sha256").update(representation).digest()), signedFile: outputPath }));
} finally { secret.fill(0); }
