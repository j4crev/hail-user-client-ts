import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { decodeBase64Url, encodeBase64Url, inspectSignedPayload, type HailGrant } from "@hailproto/codec";
import { privateFile } from "./grant-revocation.js";

const GRANT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UUID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/;
const MAX_RESPONSE = 524_288;
type JsonObject = Record<string, unknown>;
function object(value: unknown): JsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Provider API returned an invalid object");
  return value as JsonObject;
}

export class AccountApiError extends Error {
  constructor(readonly status: number) { super(`Provider API returned HTTP ${status}`); }
}

export class AccountApiClient {
  private constructor(private readonly provider: string, private readonly token: string,
    private readonly accountId: string) {}

  static async fromCredentialFile(path: string): Promise<AccountApiClient> {
    const record = object(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await privateFile(path, 16_384))));
    if (record.type !== "hailp.api-credential" || record.version !== 1 ||
      typeof record.provider !== "string" || typeof record.token !== "string" ||
      !/^hailp_[A-Za-z0-9_-]{43}$/.test(record.token) || typeof record.accountId !== "string" || !UUID.test(record.accountId)) {
      throw new Error("Invalid hailp credential file");
    }
    const url = new URL(record.provider);
    if (url.protocol !== "https:" || url.origin !== record.provider || url.username || url.password ||
      url.search || url.hash || isIP(url.hostname) !== 0 || !/^[a-z0-9.-]+$/.test(url.hostname)) {
      throw new Error("Credential provider must be a canonical HTTPS DNS origin");
    }
    return new AccountApiClient(record.provider, record.token, record.accountId);
  }

  private async request(path: string, bytes?: Uint8Array): Promise<JsonObject> {
    const headers: Record<string, string> = { Authorization: `Bearer ${this.token}`,
      Accept: "application/json", "Accept-Encoding": "identity", "Cache-Control": "no-store" };
    if (bytes) headers["Content-Type"] = 'application/cose; cose-type="cose-sign1"';
    let response: Response;
    try {
      response = await fetch(`${this.provider}/api/v1/account${path}`, {
        method: bytes ? "PUT" : "GET", headers, redirect: "error", credentials: "omit",
        signal: AbortSignal.timeout(10_000), ...(bytes ? { body: Uint8Array.from(bytes) } : {}),
      });
    } catch { throw new Error("Provider API transport failed; check connectivity and HTTPS trust"); }
    if (!response.ok) { void response.body?.cancel(); throw new AccountApiError(response.status); }
    const length = response.headers.get("Content-Length");
    if (response.headers.get("Content-Type") !== "application/json" || response.headers.has("Content-Encoding") ||
      response.headers.has("Location") || length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_RESPONSE)) {
      void response.body?.cancel();
      throw new Error("Provider API returned an invalid response representation");
    }
    const reader = response.body?.getReader();
    if (!reader) throw new Error("Provider API returned an empty response");
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) {
        const next = await reader.read();
        if (next.done) break;
        size += next.value.length;
        if (size > MAX_RESPONSE) throw new Error("Provider API response exceeded its limit");
        chunks.push(next.value);
      }
    } catch (error) { await reader.cancel().catch(() => {}); throw error; }
    const all = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { all.set(chunk, offset); offset += chunk.length; }
    return object(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(all)));
  }

  async account() {
    const result = await this.request("");
    const publicKey = (value: unknown) => value === null || typeof value === "string" &&
      value.length <= 256 && /^did:key:z[1-9A-HJ-NP-Za-km-z]+$/.test(value);
    if (result.type !== "hailp.account" || result.version !== 1 || result.provider !== this.provider ||
      result.accountId !== this.accountId || typeof result.did !== "string" || !/^did:plc:[a-z2-7]{24}$/.test(result.did) ||
      typeof result.address !== "string" || result.address.length > 254 ||
      ![null, "fenced", "exported", "retired"].includes(result.migrationState as null | string) ||
      !["owner-controlled", "custodial-poc", "unknown"].includes(result.custodyProfile as string) ||
      !publicKey(result.identityPublicKey) || !publicKey(result.ownerRecoveryPublicKey) ||
      ![null, "independent", "poc-local"].includes(result.monitorVerificationMode as null | string) ||
      !Array.isArray(result.scopes) || !result.scopes.every(scope => ["account:read", "grants:read", "grants:write"].includes(scope))) {
      throw new Error("Provider account does not match the credential or API contract");
    }
    return { provider: this.provider, accountId: this.accountId, did: result.did, address: result.address,
      migrationState: result.migrationState, custodyProfile: result.custodyProfile, scopes: result.scopes,
      monitorVerificationMode: result.monitorVerificationMode, identityPublicKey: result.identityPublicKey,
      ownerRecoveryPublicKey: result.ownerRecoveryPublicKey };
  }

  async grant(id: string): Promise<{ representation: Uint8Array; payload: HailGrant; localRole: "grantor" | "grantee"; digest: string }> {
    if (!GRANT_ID.test(id)) throw new Error("Grant ID must be a canonical UUIDv7");
    const result = await this.request(`/grants/${id}`);
    if (result.type !== "hailp.grant" || result.version !== 1 ||
      typeof result.cose !== "string" || result.cose.length > 349_528 || typeof result.digest !== "string" ||
      !["grantor", "grantee"].includes(result.localRole as string)) throw new Error("Invalid provider Grant response");
    const representation = decodeBase64Url(result.cose);
    const payload = inspectSignedPayload("hail.grant", representation).payload;
    const digest = encodeBase64Url(new Uint8Array(createHash("sha256").update(representation).digest()));
    if (payload.grant_id !== id || digest !== result.digest) throw new Error("Provider Grant bytes or ID do not match");
    return { representation, payload, localRole: result.localRole as "grantor" | "grantee", digest };
  }

  async submit(representation: Uint8Array) {
    if (representation.length > 262_144) throw new Error("Signed Grant exceeds its limit");
    const payload = inspectSignedPayload("hail.grant", representation).payload;
    const result = await this.request(`/grants/${payload.grant_id}`, representation);
    const digest = encodeBase64Url(new Uint8Array(createHash("sha256").update(representation).digest()));
    if (result.grantId !== payload.grant_id || result.revision !== payload.revision || result.status !== payload.status ||
      result.digest !== digest || result.publication !== "durable") throw new Error("Provider did not acknowledge the exact signed Grant");
    return { grantId: payload.grant_id, revision: payload.revision, status: payload.status, digest, publication: "durable" };
  }
}
