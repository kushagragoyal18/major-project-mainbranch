# 🔐 Privacy-Preserving Secure Cloud Storage
## Hybrid Encryption + Attribute-Based Access Control — Build Specification

> **This document is the single source of truth for Antigravity.** Read it fully before writing any code. Follow the phases in order. Keep `DEVELOPMENT_LOG.md` updated after every meaningful step (see Section 12). Comment every non-trivial function, class, and cryptographic step so a reviewer with no prior context can understand *what* is happening and *why*.

---

## 1. Project Summary

We are building a **client-centric, zero-trust cloud storage system** where files are encrypted **on the client before upload**, and the ability to decrypt depends on the **user's attributes** (role, department, clearance, time-of-day) — not on cloud-provider-managed keys.

The cloud provider only ever sees **opaque ciphertext**. Even a malicious insider or a compromised control plane cannot read plaintext.

**Core idea — Three-Tier Key Wrapping:**
```
File ──AES-256-GCM──> Ciphertext
DEK  ──CP-ABE────────> Wrapped under an attribute access policy
DEK  ──RSA-OAEP──────> Optionally wrapped per-user (device binding)
```
Access is enforced twice: **ABAC** (fast, real-time, at the app layer) AND **CP-ABE** (cryptographic, cannot be bypassed even by the server).

**Authors / Team:** Vansh Sharma, Kushagra Goyal, Geetanshi Singh, Himanshi Kumar — Dept. of Computer Science & Engineering.

---

## 2. The Problem We Solve

Storing confidential data (health, finance, government) on AWS S3 / Azure Blob has three structural weaknesses:

1. **Provider controls the keys.** SSE-S3 / SSE-KMS keys are provider-managed → vulnerable to insiders, subpoenas, control-plane compromise. Best case, the provider is "honest-but-curious."
2. **Coarse-grained access control.** IAM/ACL can say "User X can read object Y" but cannot naturally express *"any cardiologist of the Delhi branch with clearance ≥ 3 during business hours."* And if the enforcement layer is bypassed, plaintext leaks.
3. **Sharing breaks confidentiality.** Distributing files to many people forces either sharing the raw key (revocation becomes impossible) or re-encrypting every copy.

**Core problem:** achieve flexible access control + efficient key management + fast revocation + quantum-readiness + searchability **simultaneously**, without sacrificing security, efficiency, or usability.

---

## 3. Objectives (build to satisfy each of these)

| ID | Objective | What it means in code |
|----|-----------|------------------------|
| **O1** | Confidentiality | Encrypt every file with AES-256-GCM; cloud sees only ciphertext. |
| **O2** | Cryptographic authorisation | Wrap each file's DEK under a CP-ABE access policy. |
| **O3** | Context-aware enforcement | ABAC layer with PDP/PEP/PIP/PAP reasoning over subject, object, action, environment attributes. |
| **O4** | Efficient revocation | Attribute + key versioning with **lazy re-wrapping** — revoking a user never re-encrypts the underlying file, only the 32-byte DEK on next access. |
| **O5** | Integrity & authenticity | GCM tag + SHA-256 for tamper detection; RSA-PSS signatures for non-repudiation. |
| **O6** | Evaluation | Benchmark encryption, key-wrapping, end-to-end latency vs. file size and policy complexity. |
| **O7** | Publishable contribution | The three-tier key-wrapping model + its revocation cost model. |

---

## 4. Scope

### In Scope
- Hybrid **AES-256-GCM + RSA-OAEP** encryption for files and keys.
- **CP-ABE** (the **BSW07** construction) via **Charm-Crypto** for attribute-based key wrapping.
- An **ABAC policy engine** — PDP, PEP, PIP, PAP — built in **Flask**.
- **MongoDB** for metadata; **AWS S3** or **Azure Blob** as the object store.
- **Attribute-versioning-based revocation** with an audit log.
- A working **healthcare-records use case** + a **performance-evaluation suite**.

### Out of Scope (note as future work in code/docs)
- Full production multi-authority ABE.
- Full post-quantum lattice-based ABE (discuss; optionally prototype ML-KEM/Kyber in limited form).
- Encrypted keyword search at multi-terabyte scale.
- Production-grade polished UI (build a functional minimal client only).

---

## 5. Novelty (make sure the implementation reflects these)

1. **Three-tier key wrapping:** AES → CP-ABE → per-user RSA (attribute authorisation + device binding).
2. **Efficient revocation:** attribute versioning + lazy re-encryption, with a documented cost model.
3. **Layered trust model:** ABAC = instant revocation but must be trusted; CP-ABE = cryptographic, cannot be bypassed but costly. Merge both — ABAC handles the frequent path, CP-ABE guarantees confidentiality if the enforcement layer is breached.
4. **Outsourced decryption:** offload heavy pairing computation to the server via a transform key; keep the client lightweight.
5. **Post-quantum preparedness:** assess ML-KEM (Kyber) and lattice-based ABE alongside RSA.

---

## 6. System Architecture

**Model:** client-centric, zero-trust. Encryption/decryption happen **only on the client**. The cloud never sees plaintext or unwrapped keys.

### 6.1 Components
1. **Client (Uploader/Downloader)** — does all crypto. Minimal web UI.
2. **Flask API server** — auth (JWT), ABAC engine, outsourced CP-ABE transformation, metadata orchestration.
3. **ABAC Engine** — PDP (decision), PEP (enforcement), PIP (attribute info), PAP (policy admin).
4. **MongoDB** — metadata store (file records, policies, key versions, audit log).
5. **Object Store** — AWS S3 or Azure Blob for ciphertext blobs.

### 6.2 Data Flow — Upload (Owner)
1. Generate a random **DEK** (32 bytes).
2. Encrypt the document with **AES-256-GCM** using the DEK.
3. Encrypt the DEK under a **CP-ABE** access policy.
4. *(Optional)* Encrypt the DEK under recipient's **RSA public key** (device binding).
5. Compute **SHA-256** hash + **RSA-PSS** signature.
6. Store ciphertext → S3/Azure; metadata → MongoDB.

### 6.3 Data Flow — Download (User)
1. Login via **JWT**.
2. **ABAC PDP** evaluates subject/object/action/environment attributes.
3. If allowed, server runs the **outsourced CP-ABE transformation** using the user's transform key.
4. Client decrypts the lightweight transformed ciphertext to recover the **DEK**.
5. Client **AES-GCM-decrypts** the file; verifies the **GCM tag** and **signature**.

### 6.4 Revocation
- Increment the attribute/key version.
- **Lazily re-wrap** only the 32-byte DEK on the next access (never re-encrypt the file).
- At the ABAC layer, revoke the user **immediately**.

### 6.5 Three-Tier Key Hierarchy
```
Tier 1: AES-256-GCM DEK        → protects the file bytes
Tier 2: CP-ABE policy wrap     → attribute-based authorisation over the DEK
Tier 3: per-user RSA-OAEP wrap → device/user binding of the DEK
```

---

## 7. Technology Stack

| Layer | Choice | Notes |
|-------|--------|-------|
| Language | **Python 3.10+** | Charm-Crypto compatibility. |
| Web framework | **Flask** | REST API + ABAC engine. |
| Symmetric crypto | **AES-256-GCM** | via `cryptography` (PyCA). |
| Asymmetric crypto | **RSA-OAEP** (wrap), **RSA-PSS** (sign) | via `cryptography`. |
| ABE | **CP-ABE (BSW07)** | via **Charm-Crypto** (pairing-based). |
| Hash | **SHA-256** | integrity. |
| Auth | **JWT** | `PyJWT`. |
| Metadata DB | **MongoDB** | `pymongo`. |
| Object store | **AWS S3** (`boto3`) or **Azure Blob** (`azure-storage-blob`) | pluggable via an interface. |
| PQC (optional) | **ML-KEM / Kyber** | `liboqs-python` or `pqcrypto`, for the assessment only. |
| Frontend | **HTML/JS minimal client** (or a small React app) | functional, not polished. |
| Containerisation | **Docker** | front-load Charm-Crypto build to Week 1. |
| Testing | **pytest** | crypto correctness + API. |
| Benchmarking | **pytest-benchmark / custom timers + matplotlib** | for O6. |

> **Critical build risk:** Charm-Crypto is hard to install. **Build it in Docker in Week 1.** If it fails, use the **simulated-CP-ABE fallback** (a well-documented mock module that mimics the CP-ABE interface so the rest of the system can proceed). Keep the interface identical so the real implementation can drop in later.

---

## 8. Repository Structure (create this)

```
secure-cloud-storage/
├── README.md
├── PROJECT_SPEC.md              # this file
├── DEVELOPMENT_LOG.md           # you maintain this continuously (see §12)
├── docker-compose.yml
├── Dockerfile                   # includes Charm-Crypto build
├── requirements.txt
├── .env.example
├── client/                      # client-side crypto + minimal UI
│   ├── crypto/
│   │   ├── aes_gcm.py           # Tier 1: AES-256-GCM encrypt/decrypt
│   │   ├── rsa_wrap.py          # Tier 3: RSA-OAEP wrap + RSA-PSS sign
│   │   ├── cpabe.py             # Tier 2: CP-ABE wrapper (real or simulated)
│   │   ├── cpabe_simulated.py   # fallback mock (same interface)
│   │   └── hashing.py           # SHA-256 helpers
│   ├── uploader.py              # full upload data flow (§6.2)
│   ├── downloader.py            # full download data flow (§6.3)
│   └── ui/                      # minimal web client
├── server/
│   ├── app.py                   # Flask entrypoint
│   ├── auth/                    # JWT issue/verify
│   ├── abac/
│   │   ├── pdp.py               # Policy Decision Point
│   │   ├── pep.py               # Policy Enforcement Point
│   │   ├── pip.py               # Policy Information Point
│   │   └── pap.py               # Policy Administration Point
│   ├── cpabe_transform.py       # outsourced CP-ABE transformation
│   ├── storage/
│   │   ├── base.py              # ObjectStore interface
│   │   ├── s3_store.py
│   │   └── azure_store.py
│   ├── metadata/
│   │   └── mongo.py             # file records, policies, key versions
│   ├── revocation/
│   │   └── versioning.py        # attribute/key versioning + lazy re-wrap
│   └── audit/
│       └── audit_log.py         # tamper-evident audit trail
├── evaluation/
│   ├── benchmarks.py            # O6: latency vs file size / policy complexity
│   ├── revocation_cost_model.py # O7: cost model
│   └── results/                 # generated charts + CSVs
├── usecase/
│   └── healthcare_demo.py       # end-to-end healthcare-records demo
└── tests/
    ├── test_aes_gcm.py
    ├── test_rsa_wrap.py
    ├── test_cpabe.py
    ├── test_abac.py
    ├── test_revocation.py
    └── test_end_to_end.py
```

---

## 9. Build Phases (follow in order; matches the 15-week plan)

### Phase 1 (P1) — Cryptographic Core  ⏳ *front-load Charm-Crypto*
- Set up Docker + Charm-Crypto (fallback: `cpabe_simulated.py`).
- Implement & unit-test: `aes_gcm.py`, `rsa_wrap.py`, `hashing.py`, `cpabe.py`.
- **Exit criteria:** encrypt/decrypt round-trips pass; CP-ABE wrap/unwrap works.

### Phase 2 (P2) — CP-ABE Envelope + Three-Tier Wrapping
- Implement `uploader.py` and `downloader.py` full data flows.
- Wire the three tiers together (AES → CP-ABE → RSA).
- Add RSA-PSS signing + verification.
- **Exit criteria:** a file can be uploaded, wrapped through all three tiers, and recovered end-to-end (locally).

### Phase 3 (P3) — API + ABAC Engine
- Flask app, JWT auth.
- PDP/PEP/PIP/PAP implementation with subject/object/action/environment attributes.
- MongoDB metadata + S3/Azure storage integration.
- Outsourced CP-ABE transformation endpoint.
- **Exit criteria:** full upload/download over HTTP with ABAC gating.

### Phase 4 (P4) — Revocation
- Attribute/key versioning + lazy re-wrap.
- Immediate ABAC-layer revocation.
- Tamper-evident audit log.
- **Exit criteria:** revoking a user blocks access immediately (ABAC) and cryptographically on next access (CP-ABE) without re-encrypting files.

### Phase 5 (P5) — Evaluation, UI, Docs + Buffer
- Benchmark suite (O6) + revocation cost model (O7) with charts.
- Minimal web UI.
- Healthcare demo.
- Finalise docs. Reserve the tail as risk buffer.

**Critical path:** P1 → P2 → P3 → P5. P4 branches from P3 and converges on P5.

**Work streams:** crypto core + CP-ABE (Kushagra, Vansh); backend API + ABAC (Vansh, Geetanshi); metadata + storage (Geetanshi, Himanshi); evaluation + UI + docs (Himanshi, Kushagra).

---

## 10. Security Requirements
- Plaintext and unwrapped DEKs **never** leave the client.
- All DEKs are 32 random bytes from a CSPRNG.
- AES-256-GCM nonces are unique per encryption (never reused with the same key).
- Verify GCM tag AND RSA-PSS signature before trusting any decrypted output.
- Store only ciphertext + wrapped keys + metadata server-side.
- Audit log entries must be append-only and tamper-evident (e.g., hash-chained).

---

## 11. Evaluation Deliverables (O6/O7)
- Latency of: AES encryption, CP-ABE wrap, RSA wrap, end-to-end upload/download.
- Vary: file size (KB → hundreds of MB) and policy complexity (# attributes).
- Revocation cost model: prove lazy re-wrap costs ~32 bytes vs. full file re-encryption.
- Output CSVs + matplotlib charts into `evaluation/results/`.

---

## 12. 📓 MANDATORY: Documentation & Commenting Rules

> **These rules are not optional. The team is learning from this — clarity matters more than cleverness.**

### 12.1 Maintain `DEVELOPMENT_LOG.md` continuously
After **every meaningful step** (a module finished, a decision made, a bug fixed, a phase completed), append an entry to `DEVELOPMENT_LOG.md` using this template:

```markdown
## [YYYY-MM-DD HH:MM] <Short title>

**Phase:** P1 / P2 / ...
**What I did:** <plain-English description of the work>
**Why:** <reason / which objective (O1–O7) or spec section it serves>
**How it works:** <brief technical explanation a beginner can follow>
**Files changed:** <list>
**Decisions & trade-offs:** <any choice made and the alternatives rejected>
**Problems hit & fixes:** <errors, how they were solved>
**How to test / verify:** <commands or steps>
**Next step:** <what comes next>
```

### 12.2 Comment the code thoroughly
- Every **module** starts with a docstring: what it does, which spec section (§) and objective (O#) it implements.
- Every **function/class** has a docstring: purpose, parameters, returns, and any security-critical notes.
- Every **cryptographic step** gets an inline comment explaining *what* and *why* (e.g., `# Generate a fresh 96-bit nonce — GCM nonces must never repeat under the same key`).
- Prefer clear names + comments over cleverness. Assume the reader is a teammate learning cryptography.
- Flag every security-sensitive line with a `# SECURITY:` comment.
- Mark fallback/mock code clearly with `# FALLBACK:` and `# TODO: replace with real CP-ABE`.

### 12.3 Keep `README.md` current
- Setup instructions (Docker, env vars, MongoDB, cloud creds).
- How to run the server, client, tests, and benchmarks.
- Architecture diagram description (§6).

---

## 13. Definition of Done
- [ ] All objectives O1–O7 implemented and demonstrable.
- [ ] End-to-end healthcare demo works (upload → ABAC gate → outsourced transform → client decrypt).
- [ ] Revocation demonstrated (immediate ABAC + lazy CP-ABE re-wrap).
- [ ] Benchmark charts + revocation cost model generated.
- [ ] All tests pass (`pytest`).
- [ ] `DEVELOPMENT_LOG.md` complete and continuous.
- [ ] Code fully commented per §12.
- [ ] `README.md` lets a fresh clone run the system.

---

## 14. References (from the report)
1. Doshi et al., "Flexible revocation in CP-ABE with verifiable ciphertext delegation," MTA, 2022.
2. "Puncturable CP-ABE for efficient user revocation," Sci China Info Sci, 2023.
3. "Cloud-based enhanced CP-ABE for user/attribute revocation," IJCA, 2023.
4. "MA-RABE: revocable multi-authority ABE for EHR in blockchain," P2P Net & Apps, 2022.
5. "Blockchain-Based Multi-Authority ABE for EHR," Applied Sciences (MDPI), 2022.
6. "Lattice-based ABE for post-quantum security (review)," Springer, 2024–26.
7. "BL-ABSE: Blockchain-Enabled Lattice-Based ABSE with Instant Revocation," Electronics (MDPI), 2025.
8. "CRYSTALS-Kyber (ML-KEM) vs RSA/ECC performance," arXiv, 2025.

Foundational: Sahai & Waters (2005, Fuzzy IBE); Goyal et al. (2006, KP-ABE); Bethencourt, Sahai & Waters (2007, CP-ABE); Waters (2011, LSSS); Lewko & Waters (2011, multi-authority); NIST SP 800-162 (ABAC); Green et al. (2011, outsourced decryption); Akinyele et al. (2013, Charm).
