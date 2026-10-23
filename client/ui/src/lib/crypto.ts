/**
 * Browser-side cryptography (WebCrypto). Mirrors client/crypto/*.py byte-for-byte so
 * envelopes produced here and by the Python client are interchangeable.
 *
 *  Tier 1  AES-256-GCM file encryption           (aes_gcm.py)
 *  Tier 2  CP-ABE wrap of the 32-byte DEK          (cpabe_simulated.py interface)
 *  Tier 3  RSA-OAEP-SHA256 wrap to a device key    (rsa_wrap.py)
 *          RSA-PSS-SHA256 signature over SHA-256(ciphertext), salt = max length
 *
 * SECURITY: plaintext and the unwrapped DEK only ever exist inside this tab.
 */

const subtle = crypto.subtle;
const enc = new TextEncoder();

// ------------------------------------------------------------------ encoding
export function b64e(bytes: Uint8Array): string {
  let out = "";
  const CHUNK = 0x8000; // avoid call-stack limits on large files
  for (let i = 0; i < bytes.length; i += CHUNK) {
    out += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + CHUNK)));
  }
  return btoa(out);
}

export function b64d(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const randomBytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const buf = (b: Uint8Array) => b as unknown as BufferSource;

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest("SHA-256", buf(data)));
}
export const sha256Hex = async (data: Uint8Array) => hex(await sha256(data));

// ------------------------------------------------------------------ Tier 1: AES-256-GCM
const TAG_BYTES = 16;

export interface GcmParts { ciphertext: Uint8Array; nonce: Uint8Array; tag: Uint8Array }

export async function aesEncrypt(key: Uint8Array, plaintext: Uint8Array): Promise<GcmParts> {
  // SECURITY: fresh 96-bit nonce per encryption — GCM nonces must never repeat under one key.
  const nonce = randomBytes(12);
  const k = await subtle.importKey("raw", buf(key), "AES-GCM", false, ["encrypt"]);
  const out = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: buf(nonce) }, k, buf(plaintext)));
  // WebCrypto appends the tag; Python keeps it separate, so split it off.
  return { ciphertext: out.subarray(0, out.length - TAG_BYTES), nonce, tag: out.subarray(out.length - TAG_BYTES) };
}

export async function aesDecrypt(key: Uint8Array, p: GcmParts): Promise<Uint8Array> {
  const k = await subtle.importKey("raw", buf(key), "AES-GCM", false, ["decrypt"]);
  const joined = new Uint8Array(p.ciphertext.length + p.tag.length);
  joined.set(p.ciphertext);
  joined.set(p.tag, p.ciphertext.length);
  // SECURITY: throws if the tag does not verify (tampered ciphertext or wrong key).
  return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: buf(p.nonce) }, k, buf(joined)));
}

const gcmToJson = (p: GcmParts) => ({ ciphertext: b64e(p.ciphertext), nonce: b64e(p.nonce), tag: b64e(p.tag) });
const gcmFromJson = (o: { ciphertext: string; nonce: string; tag: string }): GcmParts =>
  ({ ciphertext: b64d(o.ciphertext), nonce: b64d(o.nonce), tag: b64d(o.tag) });

// ------------------------------------------------------------------ Tier 2: CP-ABE
export interface AbeKey { type: string; attributes: string[]; key: string }
export interface AbeCiphertext { type: string; policy: string; ciphertext: string; nonce: string; tag: string }

/** Boolean policy evaluation identical to cpabe_simulated.evaluate_policy (shunting-yard). */
export function evaluatePolicy(policy: string, attributes: string[]): boolean {
  const tokens = policy.toLowerCase().match(/[a-zA-Z0-9_\-:]+|\(|\)/g) ?? [];
  if (!tokens.length) return true;
  const have = new Set(attributes.map((a) => a.toLowerCase().trim()));
  const prec: Record<string, number> = { or: 1, and: 2 };
  const output: string[] = [];
  const ops: string[] = [];
  for (const t of tokens) {
    if (t === "(") ops.push(t);
    else if (t === ")") {
      while (ops.length && ops[ops.length - 1] !== "(") output.push(ops.pop()!);
      ops.pop();
    } else if (t in prec) {
      while (ops.length && ops[ops.length - 1] in prec && prec[ops[ops.length - 1]] >= prec[t]) output.push(ops.pop()!);
      ops.push(t);
    } else output.push(t);
  }
  while (ops.length) output.push(ops.pop()!);
  const stack: boolean[] = [];
  for (const t of output) {
    if (t === "and" || t === "or") {
      if (stack.length < 2) return false;
      const b = stack.pop()!, a = stack.pop()!;
      stack.push(t === "and" ? a && b : a || b);
    } else stack.push(have.has(t));
  }
  return stack.length === 1 && stack[0];
}

export function assertBrowserEngine(pk: { type?: string }) {
  if (pk.type !== "simulated_pk") {
    throw new Error("The server runs real Charm-Crypto pairings. Use the Python client for Tier 2 in this mode.");
  }
}

export async function abeEncrypt(pk: { type?: string; key: string }, dek: Uint8Array, policy: string): Promise<AbeCiphertext> {
  assertBrowserEngine(pk);
  const parts = await aesEncrypt(b64d(pk.key), dek);
  return { type: "simulated_ct", policy, ...gcmToJson(parts) };
}

/** Full local CP-ABE decryption — used by the breach demo to show the policy still holds. */
export async function abeDecrypt(sk: AbeKey, ct: AbeCiphertext): Promise<Uint8Array> {
  if (!evaluatePolicy(ct.policy, sk.attributes)) {
    const err = new Error(`Your key's attributes do not satisfy “${ct.policy}”.`);
    err.name = "PolicyError";
    throw err;
  }
  return aesDecrypt(b64d(sk.key), gcmFromJson(ct));
}

/**
 * Outsourced decryption (Green et al.). TK goes to the server, which does the heavy
 * work; DK (the secret z) never leaves the browser, so the server cannot learn the DEK.
 */
export function makeTransformKey(sk: AbeKey) {
  const z = b64e(randomBytes(32));
  return {
    tk: { type: "simulated_tk", attributes: sk.attributes, key: sk.key, z },
    dk: { type: "simulated_dk", z },
  };
}

export async function decryptTransformed(dk: { z: string }, ctPrime: { ciphertext: string; nonce: string; tag: string }) {
  return aesDecrypt(b64d(dk.z), gcmFromJson(ctPrime));
}

// ------------------------------------------------------------------ Tier 3: RSA device key
const OAEP = { name: "RSA-OAEP", hash: "SHA-256" } as const;
const PSS_SALT = 256 - 32 - 2; // PSS.MAX_LENGTH for RSA-2048 + SHA-256, as in rsa_wrap.py

export interface DeviceKey { oaepPriv: CryptoKey; pssPriv: CryptoKey; publicPem: string; fingerprint: string }

function toPem(spki: Uint8Array) {
  const body = b64e(spki).match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----\n`;
}
function fromPem(pem: string) {
  return b64d(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
}

/** Generates an RSA-2048 device key. The private halves are stored non-extractable. */
export async function generateDeviceKey(): Promise<DeviceKey> {
  const pair = await subtle.generateKey(
    { ...OAEP, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    ["encrypt", "decrypt"],
  );
  const pkcs8 = await subtle.exportKey("pkcs8", pair.privateKey);
  const spki = new Uint8Array(await subtle.exportKey("spki", pair.publicKey));
  // The same RSA key is used for OAEP unwrap and PSS signing, as in the Python client.
  // SECURITY: re-import both private halves as non-extractable, then drop the PKCS#8 bytes.
  const oaepPriv = await subtle.importKey("pkcs8", pkcs8, OAEP, false, ["decrypt"]);
  const pssPriv = await subtle.importKey("pkcs8", pkcs8, { name: "RSA-PSS", hash: "SHA-256" }, false, ["sign"]);
  const publicPem = toPem(spki);
  return { oaepPriv, pssPriv, publicPem, fingerprint: await pemFingerprint(publicPem) };
}

export const pemFingerprint = async (pem: string) => (await sha256Hex(enc.encode(pem))).slice(0, 16);

export async function rsaWrap(publicPem: string, dek: Uint8Array): Promise<string> {
  const pub = await subtle.importKey("spki", buf(fromPem(publicPem)), OAEP, false, ["encrypt"]);
  return b64e(new Uint8Array(await subtle.encrypt(OAEP, pub, buf(dek))));
}

export async function rsaUnwrap(device: DeviceKey, wrapped: string): Promise<Uint8Array> {
  return new Uint8Array(await subtle.decrypt(OAEP, device.oaepPriv, buf(b64d(wrapped))));
}

export async function sign(device: DeviceKey, data: Uint8Array): Promise<string> {
  const sig = await subtle.sign({ name: "RSA-PSS", saltLength: PSS_SALT }, device.pssPriv, buf(data));
  return b64e(new Uint8Array(sig));
}

export async function verify(publicPem: string, signature: string, data: Uint8Array): Promise<boolean> {
  const pub = await subtle.importKey("spki", buf(fromPem(publicPem)), { name: "RSA-PSS", hash: "SHA-256" }, false, ["verify"]);
  return subtle.verify({ name: "RSA-PSS", saltLength: PSS_SALT }, pub, buf(b64d(signature)), buf(data));
}

// ------------------------------------------------------------------ device key persistence (IndexedDB)
const DB = "tessera-device";
function idb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore("keys");
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function loadDeviceKey(username: string): Promise<DeviceKey | null> {
  try {
    const db = await idb();
    return await new Promise((resolve) => {
      const req = db.transaction("keys").objectStore("keys").get(username);
      req.onsuccess = () => resolve((req.result as DeviceKey) ?? null);
      req.onerror = () => resolve(null);
    });
  } catch {
    return null;
  }
}

export async function saveDeviceKey(username: string, key: DeviceKey) {
  const db = await idb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction("keys", "readwrite");
    tx.objectStore("keys").put(key, username);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
