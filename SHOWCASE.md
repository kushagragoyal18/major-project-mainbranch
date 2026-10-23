# test:202 — Evaluator Showcase Guide

**Privacy-Preserving Secure Cloud Storage with Hybrid Encryption and Attribute-Based Access Control**
Vansh Sharma · Kushagra Goyal · Geetanshi Singh · Himanshi Kumar — Department of Computer Science & Engineering

This guide is the script for demonstrating the project to an evaluator. Each part names the **claim from the paper**, what to **show on screen**, what to **say**, and where the **evidence** lives in the code and tests. The full walkthrough takes about 20 minutes; a 7-minute short version is at the end.

---

## 0. Before the evaluator arrives (5 minutes)

1. Start the system:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\start.ps1
   ```
   The browser opens at http://localhost:5000.
2. Restore a clean demo: sign in as **Dana Kapoor** → **Settings** → **Restore demo hospital** → sign out.
3. Run the test suite once so the result is fresh in the terminal:
   ```powershell
   .\.venv-win\Scripts\python.exe -m pytest tests -v
   ```
   Expected: **38 passed**.
4. Keep these files open in an editor tab for questions: `client/ui/src/lib/crypto.ts`, `server/abac/pdp.py`, `server/revocation/versioning.py`, `server/audit/audit_log.py`.
5. Use a private/incognito window for the demo, or sign out between personas. Each person's device key lives in that browser.

**Demo staff** (password for all: `tessera-demo`; one-click buttons on the sign-in screen)

| Person | Role | Department | Clearance | Used to show |
|---|---|---|---|---|
| Dr. Alice Mehra | Doctor | Cardiology | 3 | authorised reader, lazy re-wrap, device share |
| Bob Fernandes | Nurse | Cardiology | 2 | partial access, denial, breach simulation, revocation target |
| Dr. Carol Iyer | Doctor | Oncology | 3 | cross-department denial |
| Dana Kapoor | Admin | Security | 4 | policy administration, revocation console |

**Seeded records** (synthetic data, encrypted with the real client pipeline):

| File | CP-ABE policy | ABAC tags |
|---|---|---|
| ECG summary – patient 4471.txt | `cardiology and level2` | Cardiology, L2 |
| Catheterisation notes – bed 12.md | `cardiology and doctor and level3` | Cardiology, L3 |
| Ward lab results – week 42.csv | `cardiology and level1` | Cardiology, L1 |
| Tumour board minutes – October.txt | `oncology and level3` | Oncology, L3 |
| Incident response runbook.txt | `admin and level4` | Security, L4 |

---

## 1. Coverage map: paper → system

Use this table as the opening slide or hand-out. Every row is demonstrated live in the sections below.

| Paper item | What it means | Where it is shown | Evidence in code / tests |
|---|---|---|---|
| **O1 Confidentiality** | Files are AES-256-GCM encrypted on the client; the cloud sees only ciphertext | §3 Upload, §4 "What the cloud sees" | `client/ui/src/lib/crypto.ts` (`aesEncrypt`), `client/crypto/aes_gcm.py`, `tests/test_aes_gcm.py` |
| **O2 Cryptographic authorisation** | Each file's DEK is wrapped under a CP-ABE policy | §3 policy composer, §4 breach simulation | `client/crypto/cpabe.py`, `cpabe_simulated.py`, `tests/test_cpabe.py` |
| **O3 Context-aware ABAC** | PEP / PIP / PDP / PAP over subject, resource, action, environment | §5 Access Policies + simulator | `server/abac/*.py`, `tests/test_abac.py` |
| **O4 Efficient revocation** | Attribute versioning + lazy re-wrap of only the 32-byte DEK | §6 Revocation | `server/revocation/versioning.py`, `tests/test_revocation.py` |
| **O5 Integrity & authenticity** | GCM tag + SHA-256 checksum + RSA-PSS signature; tamper-evident audit | §2 Download pipeline, §7 Audit | `client/downloader.py`, `server/audit/audit_log.py`, `tests/test_end_to_end.py` |
| **O6 Evaluation** | Latency vs. file size and policy complexity | §8 Evaluation page | `evaluation/benchmarks.py`, `evaluation/results/*.png, *.csv` |
| **O7 Publishable contribution** | Three-tier key wrapping + revocation cost model | §6 and §8 | `evaluation/revocation_cost_model.py` |
| **Novelty 1 — Three-tier key wrapping** | AES → CP-ABE → RSA-OAEP | §3 Upload, §9 Device key | Upload pipeline steps 1–4 |
| **Novelty 2 — Efficient revocation** | Versioning + lazy re-encryption with a cost model | §6, §8 | Re-wrap step in download pipeline |
| **Novelty 3 — Layered trust model** | ABAC (instant) + CP-ABE (cannot be bypassed) | §4 Breach simulation | `/breach` demo endpoint + local CP-ABE check |
| **Novelty 4 — Outsourced decryption** | Server does the heavy CP-ABE work, client finishes with secret `z` | §2 Download pipeline | `server/cpabe_transform.py`, `makeTransformKey` in `crypto.ts` |
| **Novelty 5 — Post-quantum preparedness** | Assessment / future work | §10 Q&A | README "Scope", spec §5 |
| **Healthcare use case** | End-to-end records demo | Whole demo | `usecase/healthcare_demo.py` |
| **Zero-trust, client-centric model** (§6) | Plaintext and unwrapped keys never leave the client | §3, §4 | WebCrypto in browser; server stores only ciphertext + wrapped keys |
| **Pluggable storage** (§6.1) | MongoDB metadata + S3/Azure/local object store | §11 Settings → Server | `server/metadata/mongo.py`, `server/storage/*` |

---

## 2. The problem and the architecture (2 minutes) — sign-in screen

**Show:** the sign-in screen. Point at the left panel: the headline and the three tiers.

**Say:**
> "Cloud providers like S3 or Azure hold the encryption keys, so an insider, a subpoena or a compromised control plane can read the data. Access control lists are also coarse. They cannot express 'any cardiologist with clearance 3 or higher'. Our system fixes both. Files are encrypted in the browser before upload, and who can decrypt them depends on attributes, enforced twice: by a policy engine and by the cryptography itself."

**Point out:** the line at the bottom of the form shows the server is online, which CP-ABE engine is active and which metadata store is in use (MongoDB).

---

## 3. Upload: three-tier key wrapping (O1, O2, Novelty 1) — as Bob

1. Click **Bob Fernandes**. The **Overview** page opens.
   - **Show the "Your attribute key" card:** `Cardiology v1`, `Nurse v1`, `Level 1 v1`, `Level 2 v1`.
   - **Say:** "When Bob signed in, the attribute authority issued him a CP-ABE secret key carrying his attributes. Clearance works as a ladder. Clearance 2 gives Level 1 and Level 2, so a policy that needs 'level2' means 'clearance two or higher'. The `v1` is the attribute version, which is how revocation works later."
   - **Show the Device key line:** "Bob's browser also generated an RSA-2048 device key on first sign-in. The private half is stored non-extractable in the browser and never leaves it."
2. Go to **Vault** → **Upload**. Choose any small text file.
3. In **Who can open it**: Department **Cardiology**, Minimum clearance **L2**.
   - **Show:** the **CP-ABE policy** chips and the line *"compiles to cardiology_v1 and level2_v1"*.
   - **Show:** *"2 people can open this"* with Alice's and Bob's avatars. Change clearance to **L3** and watch Bob drop out; set it back to **L2**.
   - **Say:** "The same choice is applied twice. It becomes the CP-ABE policy on the key, and it also tags the file as Cardiology, L2 for the ABAC engine."
4. Under **Bind to a device**, select **Dr. Alice Mehra** if she is listed. People appear here only after they have signed in once and own a device key.
5. Click **Encrypt and upload**. Walk through the six steps as they turn green:

| Step on screen | Paper concept | What to say |
|---|---|---|
| Generate a 256-bit data key | Tier 1 DEK, CSPRNG | "A fresh random key for this file only. It never leaves this browser." |
| Encrypt file · AES-256-GCM | Tier 1 / O1 | "Authenticated encryption with a unique 96-bit nonce and a 16-byte tag." |
| Wrap key under access policy · CP-ABE | Tier 2 / O2 | "The DEK is locked to the attribute policy." |
| Bind key to recipients' devices · RSA-OAEP | Tier 3 | "Optionally, the same DEK is wrapped to a specific person's device key." |
| Hash and sign ciphertext · SHA-256 + RSA-PSS | O5 | "Non-repudiation: we can prove Bob authored this ciphertext." |
| Upload ciphertext and wrapped keys | Zero trust | "The server receives only ciphertext, wrapped keys and public metadata." |

**Evidence:** `runUpload` in `client/ui/src/lib/pipeline.ts`; the Python twin is `client/uploader.py`.

---

## 4. Download, outsourced decryption, and the layered trust model (O2, O3, O5, Novelties 3 & 4) — as Bob

### 4a. An authorised read

1. In the Vault, open **ECG summary – patient 4471.txt** (status *Can open*).
2. **Show the left column:** the cryptographic policy and the *Policy engine decision for you: **Permit*** with the matched rule (`department-clearance`).
3. Leave **Unwrap the key using → Outsourced** selected and click **Decrypt**. Walk the steps:

| Step | Paper concept | What to say |
|---|---|---|
| Policy decision · ABAC (PEP → PDP) | O3 | "The enforcement point intercepts the request, the information point gathers subject, resource and environment attributes, and the decision point evaluates the policies." |
| Verify author signature · RSA-PSS | O5 | "Checked *before* any key work, so tampered data never reaches the decryption code. This file was signed by the Python client and verified here in the browser. Both implementations are byte-compatible." |
| Server-side pairing transform · outsourced CP-ABE | Novelty 4 | "The browser sends a transformation key. The server does the heavy CP-ABE work but does not know the secret `z`, so it still cannot see the DEK." |
| Recover data key locally | Novelty 4 | "One lightweight operation with `z`. A thin client such as a phone stays fast." |
| Decrypt and authenticate · AES-256-GCM | O1, O5 | "The GCM tag verifies the ciphertext was not modified." |
| Check integrity · SHA-256 | O5 | "Final checksum against the original plaintext." |

4. The decrypted document appears. Optionally click **Save decrypted copy**.
5. Optional: switch to **On device** and decrypt again. This is full CP-ABE decryption without outsourcing, for comparison.

### 4b. A denied read, and why two layers matter

1. Close the sheet and open **Catheterisation notes – bed 12.md** (*Restricted*; needs Doctor and Level 3).
2. Click **Decrypt**. The first step fails: *Access Denied … do not satisfy policy*.
   - **Say:** "The ABAC layer denies by default. No permit rule matches a nurse at clearance 2."
3. Click **Bypass the policy engine** in the *"What if the server were compromised?"* card.
   - **Show:** the raw base64 ciphertext and the red message *"CP-ABE refused. Your key's attributes do not satisfy 'cardiology_v1 and doctor_v1 and level3_v1'."*
   - **Say:** "This simulates a malicious insider or a breached server handing over the stored data with the policy engine skipped. The cryptographic layer still refuses, because Bob's key mathematically lacks `doctor` and `level3`. ABAC gives speed and instant revocation; CP-ABE guarantees confidentiality even if ABAC is bypassed. That is our layered trust model."

**Evidence:** `runDownload` / `runBreach` in `pipeline.ts`; `server/abac/pep.py`; `server/cpabe_transform.py`; `tests/test_end_to_end.py` (policy violation, signature tampering, ciphertext tampering, checksum mismatch).

---

## 5. Context-aware ABAC (O3) — Access Policies page

1. Go to **Access Policies**. Walk through the cards:
   - **Suspended accounts** — deny overrides everything (deny-override).
   - **Owners read their own files.**
   - **Direct shares** — people a file was bound to (Tier 3) may read it.
   - **Department and clearance** — compares *subject* to *resource* attributes (`requester's department is file's department`, `clearance ≥ file's clearance required`).
   - **Business hours only** — an *environment* attribute rule, off by default.
2. Use **Try a request** on the right:
   - Requester **Bob**, file **Catheterisation notes** → **Deny** ("No rule matched — deny by default").
   - Requester **Alice**, same file → **Permit**; the matching card gets a blue outline.
   - Switch **Account → Suspended** → **Deny** via `suspended-accounts`. This is deny-override.
3. **Environment attributes (as Dana):** sign in as Dana, turn **Business hours only** on, then move the **Hour of day** slider to 22:00 → **Deny**. Move it to 10:00 → **Permit**. Turn the policy off again afterwards.
   - **Say:** "Policies reason over four attribute categories: subject, resource, action and environment. The rules are JSON, administered by the PAP, and changes apply on the very next request."

**Evidence:** `server/abac/pdp.py` (`evaluate`, `explain`, `$`-references, `in` operator), `pip.py`, `pep.py`, `pap.py`; `tests/test_abac.py`.

---

## 6. Efficient revocation (O4, O7, Novelty 2) — as Dana, then Alice

1. Sign in as **Dana** → **Revocation**.
2. On **Bob Fernandes**, click **Revoke attribute…** → **Department** → change to **Oncology** → **Revoke**.
3. **Show the result card:**
   - Green: **Policy engine · now.** "From the next request on, Bob is evaluated as Oncology."
   - Blue: **Cryptography · lazily.** *Cardiology v1 → v2. 3 file keys queued for re-wrap.*
4. **Show** the **Lazy re-wrap queue** (the three Cardiology files) and **Attribute versions** (`Cardiology v2`).
5. **Say:**
   > "Revocation normally means re-encrypting every file the user could read: gigabytes of work. We bump the attribute's version instead. Legitimate holders get keys with both v1 and v2; Bob never receives v2. The files are flagged, and nothing is re-encrypted yet."
6. Sign out and sign in as **Alice** → Vault → open **ECG summary** (status *Re-wrap pending*) → **Decrypt**.
   - **Show the last step:** **Lazy re-wrap after revocation** — *"32-byte key re-wrapped under cardiology_v2 and level2_v1; 303 B of ciphertext untouched."*
   - **Say:** "The first authorised reader re-wraps only the 32-byte DEK under the new version. The file ciphertext is never touched. The server accepts a re-wrap only under the current compiled policy, so this cannot be used to weaken access. From now on Bob's old v1 key is cryptographically useless against this file, even if the ABAC layer were bypassed."
7. Optional, instant suspension: as Dana, flip Carol's switch off on the Revocation page. Carol's next request is denied (`suspended-accounts`) and her sign-in is refused.

**Evidence:** `server/revocation/versioning.py` (`compile_policy`, `key_attributes`, `revoke_attribute`); `POST /files/<id>/rewrap` in `server/app.py`; `tests/test_revocation.py::test_lazy_rewrap_locks_out_old_key_without_touching_ciphertext` shows the old key opens the file before the re-wrap and fails after it, with identical ciphertext.

---

## 7. Tamper-evident audit (O5, §10) — Audit Trail page

1. Go to **Audit Trail**. Point out that every event is recorded, including the denial, the breach simulation, the revocation and the lazy re-wrap.
2. Click **Verify chain** → *"All N entries verified"* with the head hash.
3. **Say:** "Each entry's hash covers the previous hash plus the entry, so editing or deleting any past entry breaks every link after it. The log is append-only and tamper-evident, as required in section 10 of our specification."
4. **To prove detection:** in the terminal, run
   ```powershell
   .\.venv-win\Scripts\python.exe -m pytest tests/test_revocation.py::test_audit_chain_detects_tampering -v
   ```
   The test edits entry #3 and the verifier reports `broken_at = 3`.

**Evidence:** `server/audit/audit_log.py`.

---

## 8. Evaluation and the cost model (O6, O7) — Evaluation page

1. Open **Evaluation**. The benchmarks run live on this machine.
2. **Headline:** *"~47K× less data re-processed when revoking an attribute that guards 1,000 files of 10 MB"*: about 218 KB of key re-wraps against about 9.8 GB of full re-encryption. The exact figures vary slightly per run.
3. Walk the charts. Hover any point for exact values; **Table** gives the numbers.
   - **File encryption · AES-256-GCM:** latency vs. file size (16 KB → 16 MB), with server (Python) and **this browser (WebCrypto)** side by side.
   - **Key wrapping vs. policy size:** wrap, server transform and client decrypt vs. number of attributes. "With outsourcing, the client's share stays flat as policies grow."
   - **Revocation cost:** bytes re-processed vs. file size on a log scale. The lazy line is flat at 32 bytes per file; full re-encryption grows linearly.
   - **Per-file overheads:** RSA-OAEP wrap/unwrap, RSA-PSS signing, full upload envelope.
4. **Say:** "The cost model is: naive re-encryption costs N × file size; lazy re-wrap costs N × (32 bytes + header). The ratio grows linearly with file size, so the benefit is largest exactly where cloud storage is used most."
5. **Paper-ready outputs:** `evaluation/results/latency_vs_size.png`, `cpabe_vs_policy.png`, `revocation_cost.png` and the matching CSVs. Regenerate with:
   ```powershell
   .\.venv-win\Scripts\python.exe -m evaluation.benchmarks
   ```

---

## 9. Tier 3 device binding (Novelty 1, completed) — Bob → Alice

*Alice must have signed in once in this browser so her device key exists.*

1. As **Bob** → **Upload** a small file → Department **Oncology** → **Bind to a device: Dr. Alice Mehra** → upload.
2. As **Alice** → open that file. It shows *Can open* through the **Direct shares** rule, although Alice is in Cardiology.
3. Choose **Unwrap the key using → Device key** → **Decrypt**.
   - **Show:** *"Unwrap with this device's RSA key · Tier 3"* → *"Device key 8dab…"*.
   - **Say:** "Here the DEK was wrapped directly to Alice's RSA device key. Only this browser, which holds her non-extractable private key, can unwrap it. This is the third tier: binding a file to a person and a device."

---

## 10. Questions evaluators commonly ask

| Question | Answer |
|---|---|
| *Is the CP-ABE real?* | The system supports both. With Charm-Crypto (the BSW07 pairing scheme) it runs in Docker with `ABE_MODE=real` (`docker compose up --build`). Charm needs the PBC C library, which cannot be built on native Windows, so this laptop runs `cpabe_simulated.py`: a documented stand-in with the **same interface and policy semantics**. The UI states this openly under **Settings → Server**. The browser implements the simulated wire format; in real mode, Tier 2 runs through the Python client. |
| *Does the server ever see plaintext?* | No. Encryption and decryption run in the browser with WebCrypto. The server stores ciphertext, wrapped keys, a checksum and public metadata (`files` collection). The outsourced transform returns a value that still needs the browser-only secret `z`. |
| *Why have both ABAC and CP-ABE?* | ABAC is fast, context-aware (time, IP, account status) and revocable instantly, but it must be trusted. CP-ABE cannot be bypassed but is costly and slow to revoke. Together, ABAC handles the frequent path and CP-ABE guarantees confidentiality if ABAC is breached (shown in §4b). |
| *Can a revoked user still decrypt with an old key?* | Before the lazy re-wrap, the ABAC layer already blocks them. After the re-wrap, their key lacks the new attribute version, so the CP-ABE layer blocks them too. This is proved in `tests/test_revocation.py`. |
| *What stops a client from re-wrapping under a weaker policy?* | The server accepts `/rewrap` only if the new wrapped key's policy equals the current compiled policy of that file. |
| *How are passwords and tokens handled?* | Salted werkzeug password hashes; HS256 JWTs carrying subject attributes, with a one-hour expiry. The PIP re-reads attributes from the directory on each request, so changes apply without waiting for the token to expire. |
| *Post-quantum?* | Out of scope for this build (spec §4). RSA-OAEP sits behind one function (`rsaWrap`/`wrap_key`), so ML-KEM (Kyber) can replace Tier 3 without touching Tiers 1–2. This is listed as the next step in `DEVELOPMENT_LOG.md`. |
| *What if MongoDB is down?* | The metadata layer falls back to a local JSON store automatically (`METADATA_BACKEND=auto`). Object storage is pluggable: local, S3 or Azure. |
| *How was it tested?* | 38 pytest tests: AES-GCM, RSA, CP-ABE, ABAC/PDP, API end-to-end, tampering, revocation, lazy re-wrap, direct share, audit tamper detection. Every flow in this guide was also run in the browser. |

---

## 11. Supporting screens worth a glance

- **Settings → Server:** CP-ABE engine, metadata store (MongoDB), object store (local / S3).
- **Settings → This device:** device key fingerprint; **Rotate** generates a new key pair.
- **Appearance:** light and dark themes, phone layout (resize the window). Respects reduced-motion and high-contrast settings.

---

## 12. Short version (7 minutes)

1. **Sign-in screen** — the problem and the three tiers (30 s).
2. **Bob → ECG summary → Decrypt** — the full download pipeline and outsourced decryption (1.5 min).
3. **Bob → Catheterisation notes → Decrypt → Bypass the policy engine** — the layered trust model (1.5 min).
4. **Dana → Revocation → Bob → Oncology** — instant ABAC plus version bump (1 min).
5. **Alice → ECG summary → Decrypt** — lazy re-wrap of 32 bytes (1 min).
6. **Audit Trail → Verify chain**, then **Evaluation** headline number (1.5 min).

Finish with:
> "Confidentiality without trusting the cloud, fine-grained access with attributes, enforcement that survives a breached server, and revocation that costs 32 bytes per file instead of the whole file. All of it running end to end in this prototype."

---

## Reset between evaluators

Sign in as **Dana** → **Settings** → **Restore demo hospital**. This restores the staff, policies and five records and starts a new audit chain.
