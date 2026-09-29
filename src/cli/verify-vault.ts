import { stat } from "node:fs/promises";
import { decodeBase64Url } from "@hailproto/codec";
import { unlockUserVault, type UserVaultFile } from "../vault.js";
import { readRecoverySecret } from "./private-input.js";

const filePath = Bun.argv[2];
if (!filePath || Bun.argv.length !== 3) throw new Error("Usage: bun run vault:verify -- <private-vault-file>");
const metadata = await stat(filePath);
if (!metadata.isFile() || metadata.size > 16384 || metadata.size < 1 || (metadata.mode & 0o077) !== 0) {
  throw new Error("Vault must be a bounded private file with mode 0600");
}
const source = await readRecoverySecret();
const secret = decodeBase64Url(source);
try {
  const vault = JSON.parse(await Bun.file(filePath).text()) as UserVaultFile;
  const unlocked = await unlockUserVault(vault, secret);
  console.info(JSON.stringify({ verified: true, did: unlocked.vault.did,
    recoveryPublicKey: unlocked.vault.recovery.publicDidKey,
    identityPublicKey: unlocked.vault.identity.publicDidKey }));
} finally { secret.fill(0); }
