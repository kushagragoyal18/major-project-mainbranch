# Tessera

**Privacy-preserving cloud storage with hybrid encryption and attribute-based access control.**

Files are encrypted in the browser before upload. Who can open a file is decided by attributes such as role, department and clearance, and that rule is enforced twice: by an ABAC policy engine (fast, revocable instantly) and by CP-ABE cryptography (holds even if the server is compromised).

*Vansh Sharma · Kushagra Goyal · Geetanshi Singh · Himanshi Kumar, Department of Computer Science & Engineering*

---

## Run it

**Windows**

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1
```

**macOS / Linux**

```bash
./start.sh
```

Then open <http://localhost:5000>. On first run the script creates a Python environment and builds the web client. You need Python 3.10+ and Node 18+; Node is only needed if `client/ui/dist` is missing.

MongoDB is used when it is running on `localhost:27017`. Otherwise Tessera falls back to a local JSON metadata store automatically, so a demo never fails because the database is down.

### Demo hospital

The server seeds four staff members, five synthetic clinical records and the default ABAC policies. Each record is encrypted with the real client pipeline. Every account's password is `tessera-demo`, and the sign-in screen offers one-click sign-in for each.

| Person | Role | Department | Clearance |
|---|---|---|---|
| Dr. Alice Mehra | Doctor | Cardiology | 3 |
| Bob Fernandes | Nurse | Cardiology | 2 |
| Dr. Carol Iyer | Doctor | Oncology | 3 |
| Dana Kapoor | Admin | Security | 4 |

To restore a clean demo, sign in as Dana and choose **Settings → Restore demo hospital**.

### A five-minute walkthrough

1. **Bob → Vault → ECG summary → Decrypt.** Watch the download pipeline: ABAC decision, signature check, outsourced pairing transform, local key recovery, AES-GCM, checksum.
2. **Bob → Catheterisation notes → Decrypt.** The policy engine denies it. Choose **Bypass the policy engine** to simulate a compromised server: CP-ABE still refuses, and the attacker sees only ciphertext.
3. **Bob → Upload.** Compose a policy and watch who can open it update live. Bind it to Alice's device (Tier 3).
4. **Dana → Revocation → Bob → Revoke attribute… → Department → Oncology.** The policy engine cuts Bob off immediately; `cardiology` goes v1 → v2 and affected file keys join the lazy re-wrap queue.
5. **Alice → open a queued file.** The pipeline ends with *Lazy re-wrap*: 32 bytes re-wrapped, ciphertext untouched.
6. **Audit Trail → Verify chain**, then **Evaluation** for live benchmarks.

---

## How it works

```
File ──AES-256-GCM──────────▶ ciphertext            Tier 1  (fresh 256-bit DEK per file)
DEK  ──CP-ABE(policy)───────▶ wrapped key            Tier 2  (attribute-based authorisation)
DEK  ──RSA-OAEP(recipient)──▶ wrapped key, optional  Tier 3  (device binding / direct share)
SHA-256(ciphertext) ──RSA-PSS──▶ author signature
```

* **Client-side encryption.** `client/ui/src/lib/crypto.ts` implements every tier with WebCrypto, byte-compatible with the Python client in `client/crypto/`. Plaintext and unwrapped DEKs never leave the browser. Device keys are RSA-2048, stored non-extractable in IndexedDB.
* **Dual enforcement.** Each read passes the ABAC PEP → PIP → PDP chain (`server/abac/`, deny-override, deny-by-default, subject/resource/environment attributes, cross-attribute references such as `$resource.department`), then the CP-ABE policy on the key itself.
* **Outsourced decryption.** The browser sends a transformation key; the server performs the heavy CP-ABE step and returns a ciphertext that only the browser's secret `z` can finish (`server/cpabe_transform.py`).
* **Revocation by attribute versioning with lazy re-wrap.** `server/revocation/versioning.py` compiles policies to versioned attributes (`cardiology_v2`). Revocation updates the directory (instant ABAC effect), bumps versions and flags affected files. The next authorised reader re-wraps only the 32-byte DEK. The server accepts a re-wrap only under the current compiled policy.
* **Tamper-evident audit.** `server/audit/audit_log.py` hash-chains every event; `/api/audit/verify` recomputes the chain.

### CP-ABE engine

Real BSW07 CP-ABE uses Charm-Crypto, which needs the PBC library. The Docker image builds it (`ABE_MODE=real`). Without it, for example on native Windows, the server uses `client/crypto/cpabe_simulated.py`, a documented stand-in with the same interface and policy semantics. The web client implements the simulated scheme's wire format; with `ABE_MODE=real`, use the Python client (`client/uploader.py`, `client/downloader.py`) for Tier 2. The UI shows which engine is active under **Settings → Server**.

---

## Repository

```
client/
  crypto/            AES-GCM, RSA-OAEP/PSS, CP-ABE (real + simulated), hashing
  uploader.py        upload flow (§6.2)
  downloader.py      download flow (§6.3)
  ui/                web client — React + TypeScript + Motion, built to ui/dist
server/
  app.py             Flask API (mounted at / and /api) + serves the web client
  abac/              PAP, PIP, PDP, PEP
  auth/              JWT
  revocation/        attribute versioning + lazy re-wrap
  audit/             hash-chained audit log
  metadata/          MongoDB with local JSON fallback
  storage/           local / S3 / Azure object stores
usecase/healthcare_demo.py   demo seed + console walkthrough
evaluation/                  benchmarks + revocation cost model, results/ (CSV + PNG)
tests/                       pytest suite
```

## Tests and evaluation

```bash
python -m pytest tests -q
```

```bash
python -m evaluation.benchmarks
```

The benchmark command writes CSVs and charts to `evaluation/results/`. The **Evaluation** page runs a smaller sweep live, on both the server and the browser.

```bash
python -m usecase.healthcare_demo
```

That last command is a console walkthrough of the full flow.

## Web client development

```bash
cd client/ui && npm install && npm run dev
```

This serves the client on :5173 and proxies `/api` to the Flask server on :5000. `npm run build` writes `client/ui/dist`, which Flask serves.

## Docker

```bash
docker compose up --build
```

This compiles PBC and Charm-Crypto, starts MongoDB, and serves Tessera on :5000. To use the web client's in-browser CP-ABE inside Docker, set `ABE_MODE=simulated` in `docker-compose.yml`.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `ABE_MODE` | `real` | `real` (Charm) or `simulated` |
| `METADATA_BACKEND` | `auto` | `auto`, `mongo` or `local` |
| `MONGO_URI` | `mongodb://localhost:27017/secure_storage` | MongoDB connection |
| `USE_LOCAL_STORAGE` | `true` | local directory instead of S3 |
| `JWT_SECRET` | dev value | **set in any shared deployment** |
| `DEMO_MODE` | `true` | enables the breach simulation endpoint |
| `HOST` / `PORT` | loopback / `5000` | bind address |

## Scope

This is a research prototype. Demo passwords, the demo-only `/breach` endpoint and the simulated CP-ABE fallback are for demonstration; set `DEMO_MODE=false`, a strong `JWT_SECRET` and `ABE_MODE=real` outside a demo. Multi-authority ABE and post-quantum (ML-KEM / lattice ABE) wrapping are future work (spec §4, §5).
