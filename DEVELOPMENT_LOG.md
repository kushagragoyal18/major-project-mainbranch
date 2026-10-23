# Development Log

This file tracks the development progress of the Privacy-Preserving Secure Cloud Storage project, documenting design decisions, cryptographic choices, trade-offs, issues, and next steps for each phase of construction.

---

## [2026-08-29 20:30] Scaffolding and Docker Configuration

**Phase:** P1
**What I did:** Created the basic project structure and files, including requirements.txt, Dockerfile, docker-compose.yml, .env.example, README.md, and implementation plan.
**Why:** To establish the infrastructure, dependency management, and configuration pathways for Phase 1 (Cryptographic Core). Serves as the foundation for objectives O1 to O7 and satisfies repo organization (§8).
**How it works:** 
* `Dockerfile` compiles PBC (Pairing-Based Cryptography) and Charm-Crypto from source, providing the required Linux environment.
* `docker-compose.yml` configures the Flask application and MongoDB to run together on an isolated network.
* `requirements.txt` specifies key-wrapping and web dependencies (`cryptography`, `pyjwt`, `pymongo`).
* Fallback options are defined in `.env.example` to allow local development with simulated CP-ABE when native dependencies are unavailable.
**Files changed:**
* `requirements.txt` [NEW]
* `Dockerfile` [NEW]
* `docker-compose.yml` [NEW]
* `.env.example` [NEW]
* `README.md` [NEW]
* `DEVELOPMENT_LOG.md` [NEW]
**Decisions & trade-offs:**
* Compiling PBC and Charm-Crypto inside the Docker container is preferred over host compilation because host compilation is highly error-prone on Windows and macOS.
* Created a pluggable local storage directory option in docker-compose (`USE_LOCAL_STORAGE=true`) to enable developers to run and test the core system without requiring an active AWS S3 / Azure Blob connection.
**Problems hit & fixes:**
* The Charm-Crypto compilation is slow and complex, so I established a simulated fallback mode (`cpabe_simulated.py`) to run tests locally without Docker dependencies, avoiding blocks on building other layers of the project.
**How to test / verify:**
* Build docker container: `docker compose build`
**Next step:** Implement client-side cryptographic core: `aes_gcm.py`, `rsa_wrap.py`, `hashing.py`, `cpabe_simulated.py`, and `cpabe.py`.

---

## [2026-08-29 20:55] Client-Side Cryptographic Core Implementation & Local Verification

**Phase:** P1
**What I did:** Implemented the client-side cryptographic core modules (`aes_gcm.py`, `rsa_wrap.py`, `hashing.py`, `cpabe_simulated.py`, and `cpabe.py`) along with their respective unit tests (`test_aes_gcm.py`, `test_rsa_wrap.py`, and `test_cpabe.py`). Ran and verified all tests successfully.
**Why:** To build the core security framework ensuring confidentiality (O1), cryptographic authorization (O2), integrity (O5), and outsourced decryption transforms (§6.2, §6.3, §10).
**How it works:**
* `aes_gcm.py` performs authenticated encryption using AES-256-GCM, returning a ciphertext, unique nonce, and authentication tag.
* `rsa_wrap.py` performs RSA-OAEP wrapping/unwrapping of the 32-byte DEK (Tier 3) and PSS digital signatures to verify file origin/authenticity.
* `hashing.py` provides SHA-256 message digests for tamper-detection.
* `cpabe_simulated.py` parses boolean logic strings using the Shunting-yard algorithm, and uses symmetric AES-GCM primitives to simulate CP-ABE policies and outsourced decryption transforms.
* `cpabe.py` acts as a dynamic entry point, importing Charm-Crypto BSW07 and scaling key components by $1/z$ for outsourced pairings, automatically falling back to simulated mode if Charm-Crypto is unavailable on the host.
**Files changed:**
* `client/crypto/aes_gcm.py` [NEW]
* `client/crypto/rsa_wrap.py` [NEW]
* `client/crypto/hashing.py` [NEW]
* `client/crypto/cpabe_simulated.py` [NEW]
* `client/crypto/cpabe.py` [NEW]
* `tests/test_aes_gcm.py` [NEW]
* `tests/test_rsa_wrap.py` [NEW]
* `tests/test_cpabe.py` [NEW]
**Decisions & trade-offs:**
* Implemented a robust pure-Python boolean policy parser inside `cpabe_simulated.py` using Shunting-yard instead of hardcoding simple checks, making the fallback model behave exactly like real CP-ABE for complex nesting.
* Standardized base64-encoded strings for serializing ABE keys and ciphertexts so they can be easily transmitted over HTTP in Phase 3.
**Problems hit & fixes:**
* Docker com.docker.service was stopped on the host and failed to start due to Windows user permission boundaries.
* Pip installation on mounted drvfs (`/mnt/c/...`) in WSL suffered from heavy I/O blocking.
* **Fix:** Canceled the virtual environment package compilation, and installed the packages natively inside WSL's ext4 partition (`python3-cryptography`, `python3-pytest`, etc.) using `apt-get` as root. This completed in seconds and allowed us to run the tests locally with the simulated fallback.
**How to test / verify:**
* Set up `PYTHONPATH=.` and run `pytest tests/ -v` inside WSL. All 20 tests pass.
**Next step:** Move to Phase 2, implementing client-side envelope wrapping and uploader/downloader data flows.

---

## [2026-08-29 21:00] Three-Tier Envelope Integration (Uploader & Downloader)

**Phase:** P2
**What I did:** Implemented `client/uploader.py` and `client/downloader.py` to orchestrate symmetric AES-GCM encryption, asymmetric RSA key wrapping, CP-ABE policy authorization, and digital signatures. Created `tests/test_end_to_end.py` to verify the envelope operations, and ran the full 27-test suite.
**Why:** Integrates the three-tier key wrapping architecture (AES → ABE → RSA) to achieve objectives O1, O2, and O5 as defined in §6.5 of the spec, and guarantees client-side confidentiality and origin authenticity.
**How it works:**
* `uploader.py` generates a fresh 256-bit DEK, encrypts raw files with AES-256-GCM, wraps the DEK with CP-ABE under a boolean policy, optionally wraps the DEK under a recipient's RSA public key (device binding), hashes the ciphertext, signs the hash with RSA-PSS using the sender's private key, and aggregates everything into a serializable JSON envelope.
* `downloader.py` verifies the digital signature over the ciphertext first. If valid, it unwraps the DEK using either standard CP-ABE, outsourced pairings transform, or recipient's RSA private key. It then decrypts the file bytes and performs a final SHA-256 integrity checksum check.
* `test_end_to_end.py` tests standard CP-ABE decryption, RSA key-wrap bypass, outsourced transform decryption, policy violation blocks, signature and ciphertext tampering detection, and checksum mismatch detection.
**Files changed:**
* `client/uploader.py` [NEW]
* `client/downloader.py` [MODIFY]
* `tests/test_end_to_end.py` [NEW]
* `DEVELOPMENT_LOG.md` [MODIFY]
**Decisions & trade-offs:**
* Signature verification is executed at the very start of download processing. This early-gating prevents the execution of ABE bilinear pairings or RSA decryptions on malicious or tampered data, protecting against decryption oracle attacks and CPU exhaustion.
* Standardized error types raised by `decrypt_envelope`: mapped lower-level cryptographic `InvalidTag` exceptions to a standard `ValueError` with a clear message, ensuring a clean error contract for callers.
**Problems hit & fixes:**
* The GCM integrity test failed initially because `aes_gcm.decrypt` raises `cryptography.exceptions.InvalidTag`, which bypassed the test case's `ValueError` capture.
* **Fix:** Imported `InvalidTag` in `downloader.py` and wrapped `aes_gcm.decrypt` in a try-except block, mapping `InvalidTag` to a standard `ValueError` with an explicit message.
**How to test / verify:**
* Execute tests in WSL: `PYTHONPATH=. pytest tests/ -v`. All 27 tests passed.
**Next step:** Proceed to Phase 3, implementing the Flask API server, ABAC PDP/PEP policy engine, JWT authentication, and MongoDB metadata storage.

---

## [2026-08-29 22:30] Flask API + ABAC Policy Engine (PAP, PIP, PDP, PEP) & ObjectStore Decoupling

**Phase:** P3
**What I did:** Developed the Flask REST API server, JWT authentication helper, in-memory MongoDB mock collection test fixture, pluggable ObjectStore engine (Local, S3, Azure), and the full ABAC policy execution pipeline (PAP, PIP, PDP, PEP). Expanded the test suite with `tests/test_abac.py` to achieve 31 successful test runs.
**Why:** Establishes the centralized server logic, integrating context-aware authorization (ABAC) with cryptographic envelope storage. It separates the storage layer (for large file ciphertexts) from the metadata catalog (for lightweight key records, checksums, and access policies) to achieve scalability and defense-in-depth.
**How it works:**
* `jwt_helper.py` generates and validates HS256 JWTs embedding subject profile claims (role, department, clearance).
* `pap.py` provides DB hooks for administrative access control policies.
* `pip.py` aggregates subject attributes (from JWT), resource attributes (from MongoDB), environment attributes (UTC hour, IP address), and action variables into a resolved context.
* `pdp.py` recursively checks context against administrative policies using a deny-override and deny-by-default logic, supporting comparisons and boolean tree nesting.
* `pep.py` intercepts route execution, returning `403 Forbidden` if denied.
* `app.py` exposes `/register`, `/login`, `/policies`, `/upload` (decouples storage and catalog), `/download/<file_id>` (PEP gated), `/transform/<file_id>` (PEP gated outsourced CP-ABE pairing transform), and `/abe-params` (authority PK getter).
**Files changed:**
* `server/metadata/mongo.py` [NEW]
* `server/storage/base.py` [NEW]
* `server/storage/local_store.py` [NEW]
* `server/storage/s3_store.py` [NEW]
* `server/storage/azure_store.py` [NEW]
* `server/auth/jwt_helper.py` [NEW]
* `server/abac/pap.py` [NEW]
* `server/abac/pip.py` [NEW]
* `server/abac/pdp.py` [NEW]
* `server/abac/pep.py` [NEW]
* `server/cpabe_transform.py` [NEW]
* `server/app.py` [NEW]
* `tests/test_abac.py` [NEW]
* `DEVELOPMENT_LOG.md` [MODIFY]
**Decisions & trade-offs:**
* Decoupled storage architecture: stored ciphertext binary payloads in the ObjectStore (S3/Local) and lightweight cryptographic keys, signatures, and policies in MongoDB. This minimizes database bloat and takes advantage of cloud-native blob storage scalability.
* Lazy Initialization of Authority Keys: wrapped the authority parameters initialization in `app.py` inside a lazy property `get_abe_keys()`. This prevents module-level connection side-effects when importing the Flask application during test collection.
* In-Memory DB Testing: created a custom `MockCollection` to monkeypatch PyMongo's collections. This allows tests to run instantly with zero dependencies on a running local MongoDB daemon.
**Problems hit & fixes:**
* A pytest collection error occurred because `app.py` was trying to contact a live MongoDB server during module import to initialize CP-ABE authority parameters.
  * **Fix:** Transitioned to lazy initialization inside routes and mocked `abe_params_col` in the mock fixture.
* Keygen clearance attributes failed to satisfy uploader policy checks due to key format mismatches (`clearance_3` vs `level3`).
  * **Fix:** Standardized the ABE attribute generation in `app.py` to use `level{N}`.
* `NameError: os is not defined` inside `test_abac.py`.
  * **Fix:** Imported `os` and `cpabe` at the top of the test file.
**How to test / verify:**
* Execute tests in WSL: `PYTHONPATH=. pytest tests/ -v`. All 31 tests passed successfully.
**Next step:** Proceed to Phase 4, implementing attribute/key versioning, lazy re-wrapping, and administrative audit logging.




---

## [2026-10-23 21:30] Phase 4 — Revocation, Lazy Re-Wrap and Tamper-Evident Audit

**Phase:** P4
**What I did:** Implemented attribute versioning with lazy DEK re-wrap (`server/revocation/versioning.py`), a hash-chained audit log (`server/audit/audit_log.py`), instant ABAC suspension, and the revocation/audit API routes. Added `tests/test_revocation.py`.
**Why:** O4 (efficient revocation), O5 (tamper evidence), §6.4 and §10 of the spec.
**How it works:**
* Human policies ("cardiology and level2") are compiled to versioned attributes ("cardiology_v1 and level2_v1") before the DEK is wrapped.
* Revoking an attribute (1) updates the user directory, so the PIP/PDP deny the next request, and (2) bumps the attribute's version and flags every file whose policy uses it. Non-revoked holders get keys with v1 *and* v2; the revoked user never receives the retired version again.
* The next authorised reader re-wraps only the 32-byte DEK under the new compiled policy (`POST /files/<id>/rewrap`). The server only accepts a re-wrap under exactly the current compiled policy, so the endpoint cannot be used to weaken access.
* Audit entries store `hash = SHA-256(prev_hash || canonical_json(entry))`; `verify_chain()` reports the first broken link.
* Clearance is now a ladder in the CP-ABE key (clearance 3 → level1, level2, level3), so "level2" in a policy means "clearance ≥ 2".
**Files changed:** `server/revocation/versioning.py` [NEW], `server/audit/audit_log.py` [NEW], `server/abac/pdp.py`, `server/abac/pip.py`, `server/abac/pep.py`, `server/app.py`, `tests/test_revocation.py` [NEW], `tests/conftest.py` [NEW]
**Decisions & trade-offs:**
* Versioned tokens instead of re-keying the authority: revocation cost stays O(32 bytes) per affected file.
* PDP gained `$path` attribute references (subject.department = resource.department), an `in` operator for direct shares, an `enabled` flag on policies, and `explain()` so the UI can show which rule decided.
* Passwords now use salted werkzeug hashes; legacy SHA-256 hashes are still accepted.
**Problems hit & fixes:** PyMongo returns cursors, not lists. The audit verifier now materialises them.
**How to test / verify:** `python -m pytest tests -q` (38 tests pass).
**Next step:** Evaluation suite and the web client.

---

## [2026-10-23 22:15] Phase 5 — Evaluation Suite, Healthcare Demo and the Tessera Web Client

**Phase:** P5
**What I did:** Built the evaluation suite (`evaluation/benchmarks.py`, `evaluation/revocation_cost_model.py`, charts and CSVs in `evaluation/results/`), the healthcare demo seed (`usecase/healthcare_demo.py`), and the web client **Tessera** (`client/ui/`, React + TypeScript + Motion). Added a JSON-file metadata fallback for when MongoDB is down, a Waitress production server, and one-command start scripts.
**Why:** O6, O7 and the §13 Definition of Done: an end-to-end demonstrable system for the conference showcase.
**How it works:**
* All three tiers run in the browser with WebCrypto (`client/ui/src/lib/crypto.ts`), byte-compatible with the Python client: AES-GCM tag layout, RSA-OAEP-SHA256, and RSA-PSS with salt length 222 (= PSS.MAX_LENGTH for RSA-2048/SHA-256). Files signed by Python verify in the browser and vice versa.
* Each person gets an RSA-2048 device key at first sign-in; private halves are stored non-extractable in IndexedDB and the public half is bound to the account.
* Upload and download are run as reported step pipelines, so the audience sees each cryptographic step and its timing.
* "Bypass the policy engine" (demo mode only) fetches a ciphertext without the ABAC gate and tries CP-ABE alone, which shows the second layer holding.
* The UI follows Apple's interaction guidelines: springs instead of fixed curves, interruptible sheets that can be flicked away, blur and scale animated together, feedback on pointer-down, translucent materials, tracking that tightens with size, and support for reduced motion, reduced transparency and increased contrast.
**Files changed:** `client/ui/**` [NEW], `evaluation/**` [NEW], `usecase/healthcare_demo.py` [NEW], `server/metadata/mongo.py`, `server/app.py`, `requirements.txt`, `Dockerfile`, `docker-compose.yml`, `README.md`, `start.ps1` [NEW], `start.sh` [NEW], `.gitignore` [NEW]
**Decisions & trade-offs:**
* The browser implements the simulated CP-ABE wire format. Real pairings (Charm) are not available in browsers; with `ABE_MODE=real`, Tier 2 runs through the Python client.
* Seeded staff have no device key until they first sign in. A seed key whose private half is discarded would make "bind to Alice" silently unusable.
* Binding a file to someone's device counts as an explicit share: the new `direct-share` ABAC policy permits recipients, who then unwrap with their device key.
**Problems hit & fixes:**
* Every request to `localhost` cost ~300 ms because browsers try `::1` first and Flask listened on IPv4 only. Fixed by serving with Waitress on both `127.0.0.1` and `[::1]` (~6 ms per request).
* Log-scale chart ticks fell on awkward binary sizes. Switched to decimal units and capped gridlines at about five.
**How to test / verify:** `.\start.ps1`, open http://localhost:5000 and follow the walkthrough in README.md; `python -m pytest tests -q`; `python -m evaluation.benchmarks`.
**Next step:** Optional ML-KEM (Kyber) assessment for post-quantum preparedness (§5.5).
