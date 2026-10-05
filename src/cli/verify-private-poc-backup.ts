import { open, readFile, stat, unlink } from "node:fs/promises";
import { decodeBase64Url } from "@hailproto/codec";
import { unlockUserVault, type UserVaultFile } from "../vault.js";

const [vaultPath, recoveryPath, backupPath] = Bun.argv.slice(2);
if (!vaultPath || !recoveryPath || !backupPath ||
  new Set([vaultPath, recoveryPath, backupPath]).size !== 3 || Bun.argv.length !== 5) {
  throw new Error("Usage: bun run poc:verify-vault-copy -- <private-vault-file> <private-recovery-secret-file> <new-private-backup-vault-file>");
}
for (const path of [vaultPath, recoveryPath]) {
  const info = await stat(path);
  if (!info.isFile() || info.size < 1 || info.size > 16_384 || (info.mode & 0o077) !== 0) {
    throw new Error("Vault and recovery material must be bounded mode-0600 regular files");
  }
}
const secret = decodeBase64Url((await readFile(recoveryPath, "utf8")).trim());
try {
  const vault = JSON.parse(await readFile(vaultPath, "utf8")) as UserVaultFile;
  const original = await unlockUserVault(vault, secret);
  const file = await open(backupPath, "wx", 0o600);
  let success = false;
  try {
    await file.writeFile(JSON.stringify(vault));
    await file.close();
    const recovered = await unlockUserVault(
      JSON.parse(await readFile(backupPath, "utf8")) as UserVaultFile, secret);
    if (original.vault.identity.publicDidKey !== recovered.vault.identity.publicDidKey ||
      original.vault.recovery.publicDidKey !== recovered.vault.recovery.publicDidKey) {
      throw new Error("POC vault backup did not restore both exact user keys");
    }
    success = true;
  } finally {
    await file.close().catch(() => {});
    if (!success) await unlink(backupPath).catch(() => {});
  }
  console.info(JSON.stringify({ profile: "disposable-private-poc", backupVerified: true,
    vaultPath, backupPath, did: vault.did }));
} finally { secret.fill(0); }
