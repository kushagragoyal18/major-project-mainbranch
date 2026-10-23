/**
 * The two data flows of the paper, run in the browser and reported step by step.
 *   upload   §6.2: DEK → AES-GCM → CP-ABE wrap → RSA wrap → sign → store
 *   download §6.3: ABAC gate → verify → outsourced transform → DEK → AES-GCM → checksum → (lazy re-wrap)
 */

import { api, ApiError, type FileItem, type User } from "./api";
import * as C from "./crypto";
import { bytes, ms } from "./format";

export type StepState = "pending" | "active" | "done" | "fail" | "skip";
export interface Step { id: string; title: string; detail?: string; state: StepState; ms?: number }
export type Report = (id: string, patch: Partial<Step>) => void;

let pkCache: { type?: string; key: string } | null = null;
export async function abePublicKey() {
  if (!pkCache) pkCache = (await api<{ pk: { type?: string; key: string } }>("/abe-params")).pk;
  return pkCache;
}
export const resetPkCache = () => { pkCache = null; };

/** Runs fn as one reported step, timing it and marking failure. */
async function step<T>(report: Report, id: string, fn: () => Promise<T>, detail?: (r: T) => string): Promise<T> {
  report(id, { state: "active" });
  const t0 = performance.now();
  try {
    const r = await fn();
    report(id, { state: "done", ms: performance.now() - t0, ...(detail ? { detail: detail(r) } : {}) });
    return r;
  } catch (e) {
    report(id, { state: "fail", ms: performance.now() - t0, detail: e instanceof Error ? e.message : String(e) });
    throw e;
  }
}

// ------------------------------------------------------------------ upload
export const uploadSteps = (): Step[] => [
  { id: "dek", title: "Generate a 256-bit data key", state: "pending" },
  { id: "aes", title: "Encrypt file · AES-256-GCM", state: "pending" },
  { id: "abe", title: "Wrap key under access policy · CP-ABE", state: "pending" },
  { id: "rsa", title: "Bind key to recipients' devices · RSA-OAEP", state: "pending" },
  { id: "sign", title: "Hash and sign ciphertext · SHA-256 + RSA-PSS", state: "pending" },
  { id: "store", title: "Upload ciphertext and wrapped keys", state: "pending" },
];

export interface UploadInput {
  file: File;
  policyDisplay: string;
  department: string;
  clearance: number;
  recipients: User[];
  device: C.DeviceKey | null;
}

export async function runUpload(input: UploadInput, report: Report) {
  const plaintext = new Uint8Array(await input.file.arrayBuffer());
  const pk = await abePublicKey();
  const { compiled } = await api<{ compiled: string }>("/abe/compile", { body: { policy: input.policyDisplay } });

  const dek = await step(report, "dek", async () => C.randomBytes(32), (k) => `${C.hex(k).slice(0, 8)}… · never leaves this browser`);
  const gcm = await step(report, "aes", () => C.aesEncrypt(dek, plaintext), (g) => `${bytes(plaintext.length)} → ${bytes(g.ciphertext.length)} ciphertext + 16-byte tag`);
  const wrapped = await step(report, "abe", () => C.abeEncrypt(pk, dek, compiled), () => compiled);

  let rsaMap: Record<string, string> = {};
  if (input.recipients.length) {
    rsaMap = await step(report, "rsa", async () => {
      const out: Record<string, string> = {};
      for (const r of input.recipients) if (r.pub_key_pem) out[r.username] = await C.rsaWrap(r.pub_key_pem, dek);
      return out;
    }, (m) => `Wrapped for ${Object.keys(m).join(", ")}`);
  } else report("rsa", { state: "skip", detail: "No recipients selected" });

  const checksum = await C.sha256Hex(plaintext);
  let signature: string | undefined;
  if (input.device) {
    signature = await step(report, "sign", async () => C.sign(input.device!, await C.sha256(gcm.ciphertext)),
      () => `Signed with device key ${input.device!.fingerprint}`);
  } else report("sign", { state: "skip", detail: "No device key on this browser" });

  const envelope = {
    ciphertext: C.b64e(gcm.ciphertext),
    nonce: C.b64e(gcm.nonce),
    tag: C.b64e(gcm.tag),
    wrapped_dek_abe: wrapped,
    wrapped_dek_rsa_map: rsaMap,
    policy: compiled,
    checksum,
    ...(signature ? { signature } : {}),
  };
  dek.fill(0); // best-effort: drop the key from memory
  return step(report, "store", () => api<{ file_id: string }>("/upload", {
    body: {
      filename: input.file.name,
      department: input.department,
      clearance_required: input.clearance,
      policy_display: input.policyDisplay,
      mime_type: input.file.type || "application/octet-stream",
      plain_size: plaintext.length,
      signer_pub_key_pem: input.device?.publicPem,
      envelope,
    },
  }), () => "The server stored ciphertext only");
}

// ------------------------------------------------------------------ download
export type UnwrapMode = "outsourced" | "local" | "device";

export function downloadSteps(file: FileItem, mode: UnwrapMode): Step[] {
  const unwrapTitle = {
    outsourced: "Server-side pairing transform · outsourced CP-ABE",
    local: "Full CP-ABE decryption on this device",
    device: "Unwrap with this device's RSA key · Tier 3",
  }[mode];
  return [
    { id: "abac", title: "Policy decision · ABAC (PEP → PDP)", state: "pending" },
    { id: "verify", title: "Verify author signature · RSA-PSS", state: "pending" },
    { id: "unwrap", title: unwrapTitle, state: "pending" },
    { id: "dek", title: "Recover data key locally", state: "pending" },
    { id: "aes", title: "Decrypt and authenticate · AES-256-GCM", state: "pending" },
    { id: "checksum", title: "Check integrity · SHA-256", state: "pending" },
    ...(file.stale ? [{ id: "rewrap", title: "Lazy re-wrap after revocation", state: "pending" as StepState }] : []),
  ];
}

interface DownloadPayload {
  envelope: {
    ciphertext: string; nonce: string; tag: string; checksum: string; policy: string; signature?: string;
    wrapped_dek_abe: C.AbeCiphertext; wrapped_dek_rsa_mine?: string;
  };
  metadata: FileItem & { signer_pub_key_pem?: string; current_policy: string };
}

export async function runDownload(file: FileItem, mode: UnwrapMode, sk: C.AbeKey, device: C.DeviceKey | null, report: Report) {
  const payload = await step(report, "abac", () => api<DownloadPayload>(`/download/${file.file_id}`),
    () => "Permit — subject, resource and environment attributes satisfy policy");
  const env = payload.envelope;
  const ciphertext = C.b64d(env.ciphertext);

  if (env.signature && payload.metadata.signer_pub_key_pem) {
    await step(report, "verify", async () => {
      const ok = await C.verify(payload.metadata.signer_pub_key_pem!, env.signature!, await C.sha256(ciphertext));
      // SECURITY: refuse before any key unwrapping if the author signature does not verify.
      if (!ok) throw new Error("Signature invalid — ciphertext was altered after upload");
      return ok;
    }, () => `Signed by ${payload.metadata.owner}`);
  } else report("verify", { state: "skip", detail: "File is unsigned" });

  let dek: Uint8Array;
  if (mode === "outsourced") {
    const { tk, dk } = C.makeTransformKey(sk);
    const res = await step(report, "unwrap", () => api<{ ct_prime: { ciphertext: string; nonce: string; tag: string } }>(
      `/transform/${file.file_id}`, { body: { tk } }), () => "Server did the heavy work but holds no z, so it cannot see the key");
    dek = await step(report, "dek", () => C.decryptTransformed(dk, res.ct_prime), () => "One lightweight operation with the secret z");
  } else if (mode === "local") {
    await step(report, "unwrap", async () => {
      if (!C.evaluatePolicy(env.wrapped_dek_abe.policy, sk.attributes)) throw new Error("Key attributes do not satisfy the policy");
      return true;
    }, () => "Attributes satisfy the ciphertext policy");
    dek = await step(report, "dek", () => C.abeDecrypt(sk, env.wrapped_dek_abe), () => "Recovered with your CP-ABE secret key");
  } else {
    if (!device || !env.wrapped_dek_rsa_mine) throw new Error("This file is not bound to this device");
    report("unwrap", { state: "done", detail: "Using the RSA-wrapped copy addressed to you" });
    dek = await step(report, "dek", () => C.rsaUnwrap(device, env.wrapped_dek_rsa_mine!), () => `Device key ${device.fingerprint}`);
  }

  const plaintext = await step(report, "aes", async () => {
    try {
      return await C.aesDecrypt(dek, { ciphertext, nonce: C.b64d(env.nonce), tag: C.b64d(env.tag) });
    } catch {
      throw new Error("Authentication tag rejected — ciphertext or key is wrong");
    }
  }, (p) => `${bytes(p.length)} recovered · GCM tag verified`);

  await step(report, "checksum", async () => {
    const h = await C.sha256Hex(plaintext);
    if (h !== env.checksum) throw new Error("Checksum mismatch");
    return h;
  }, (h) => `${h.slice(0, 16)}… matches`);

  if (file.stale) {
    // Lazy re-wrap (§6.4): re-encrypt only the 32-byte DEK under the current attribute versions.
    await step(report, "rewrap", async () => {
      const pk = await abePublicKey();
      const fresh = await C.abeEncrypt(pk, dek, payload.metadata.current_policy);
      await api(`/files/${file.file_id}/rewrap`, { body: { wrapped_dek_abe: fresh } });
      return payload.metadata.current_policy;
    }, (p) => `32-byte key re-wrapped under ${p}; ${bytes(ciphertext.length)} of ciphertext untouched`);
  }
  dek.fill(0);
  return { plaintext, metadata: payload.metadata };
}

/** Demo: fetch the stored envelope without ABAC and try CP-ABE alone. */
export async function runBreach(file: FileItem, sk: C.AbeKey) {
  const { envelope } = await api<DownloadPayload>(`/breach/${file.file_id}`);
  const t0 = performance.now();
  try {
    const dek = await C.abeDecrypt(sk, envelope.wrapped_dek_abe);
    const plaintext = await C.aesDecrypt(dek, { ciphertext: C.b64d(envelope.ciphertext), nonce: C.b64d(envelope.nonce), tag: C.b64d(envelope.tag) });
    return { opened: true as const, plaintext, ciphertext: envelope.ciphertext, ms: ms(performance.now() - t0) };
  } catch (e) {
    return { opened: false as const, reason: e instanceof Error ? e.message : String(e), ciphertext: envelope.ciphertext, policy: envelope.wrapped_dek_abe.policy };
  }
}

export const isDenied = (e: unknown) => e instanceof ApiError && e.status === 403;
