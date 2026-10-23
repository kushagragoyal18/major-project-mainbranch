# test:202 — System Design

**Privacy-Preserving Secure Cloud Storage with Hybrid Encryption and Attribute-Based Access Control**
Vansh Sharma · Kushagra Goyal · Geetanshi Singh · Himanshi Kumar — Department of Computer Science & Engineering

This document describes the system as it exists in this repository. File paths are given so each statement can be checked against the code.

---

## 1. Overview

test:202 is a client-centric, zero-trust file store. Files are encrypted in the browser before upload, and decryption depends on the user's **attributes** (role, department, clearance) rather than on keys the storage provider holds.

Each file is protected by a three-tier key hierarchy:

| Tier | Mechanism | Purpose | Code |
|---|---|---|---|
| 1 | AES-256-GCM with a fresh 32-byte DEK per file | Confidentiality and integrity of file bytes | `client/ui/src/lib/crypto.ts`, `client/crypto/aes_gcm.py` |
| 2 | CP-ABE wrap of the DEK under an attribute policy | Cryptographic authorisation | `client/crypto/cpabe.py`, `cpabe_simulated.py` |
| 3 | RSA-OAEP-SHA256 wrap of the DEK to a recipient's device key (optional) | Device binding / direct share | `crypto.ts` (`rsaWrap`), `client/crypto/rsa_wrap.py` |

Ciphertext is additionally signed (RSA-PSS over SHA-256 of the ciphertext). Every read is checked twice: by an ABAC policy engine on the server, and by the CP-ABE policy on the wrapped key.

---

## 2. High-level architecture

```mermaid
flowchart LR
    subgraph Client["User's browser"]
        UI["test:202 web client<br/>React 19 + TypeScript + Motion<br/>(client/ui)"]
        WC["WebCrypto<br/>AES-GCM · RSA-OAEP · RSA-PSS · SHA-256"]
        IDB[("IndexedDB<br/>non-extractable RSA device keys")]
        SS[("sessionStorage<br/>JWT + profile")]
        UI --> WC
        UI --> IDB
        UI --> SS
    end

    PyClient["Python client library<br/>client/uploader.py · downloader.py<br/>(used by tests, seed, benchmarks)"]

    subgraph Server["Application server (Waitress WSGI, port 5000)"]
        API["Flask app · server/app.py<br/>REST API at / and /api<br/>+ serves built UI from client/ui/dist"]
    end

    subgraph Data["Persistence"]
        Mongo[("MongoDB<br/>database: secure_storage")]
        LocalMeta[("Local JSON metadata<br/>local_storage/_metadata.json<br/>(fallback)")]
        LocalBlob[("Local directory<br/>local_storage/")]
        S3[("AWS S3 bucket<br/>(boto3, optional)")]
    end

    UI -- "HTTPS/HTTP JSON + Bearer JWT" --> API
    PyClient -. "in-process / HTTP" .-> API
    API -- "pymongo" --> Mongo
    API -. "if MongoDB unreachable" .-> LocalMeta
    API -- "USE_LOCAL_STORAGE=true" --> LocalBlob
    API -. "USE_LOCAL_STORAGE=false" .-> S3
```

**Deployment options that exist in the repository:**

```mermaid
flowchart TB
    subgraph Local["Local run · start.ps1 / start.sh"]
        V[".venv-win / .venv<br/>python -m server.app"] --> W["Waitress on 127.0.0.1:5000 and [::1]:5000"]
        W --> M1[("MongoDB on localhost:27017<br/>or local JSON fallback")]
    end
    subgraph Docker["docker compose up --build"]
        S["service: server<br/>python:3.10-slim + PBC + Charm-Crypto<br/>HOST=0.0.0.0, port 5000, ABE_MODE=real"] --> D[("service: db<br/>mongo:6.0, volume mongo_data")]
    end
```

The web client is a static build (`npm run build` → `client/ui/dist`) served by the same Flask process; there is no separate frontend server in production. In development, Vite serves the UI on :5173 and proxies `/api` to :5000 (`client/ui/vite.config.ts`).

---

## 3. Component diagram

```mermaid
flowchart TB
    subgraph Browser["client/ui/src"]
        Pages["pages/<br/>SignIn · Overview · Vault · Access ·<br/>Revocation · Audit · Evaluation · Settings"]
        Comps["components/<br/>UploadSheet · FileSheet · LineChart ·<br/>PolicyChips · ui (Sheet, Pipeline, Toasts)"]
        Session["lib/session.tsx<br/>sign-in, key refresh, device key"]
        Pipeline["lib/pipeline.ts<br/>runUpload · runDownload · runBreach"]
        Crypto["lib/crypto.ts<br/>AES-GCM · simulated CP-ABE · RSA · IndexedDB"]
        Policy["lib/policy.ts<br/>policy composer + eligibility preview"]
        ApiTs["lib/api.ts<br/>fetch wrapper, Bearer token"]
        Pages --> Comps
        Pages --> Session
        Comps --> Pipeline
        Comps --> Policy
        Pipeline --> Crypto
        Pipeline --> ApiTs
        Session --> Crypto
        Session --> ApiTs
        Policy --> Crypto
    end

    subgraph Flask["server/"]
        App["app.py<br/>Blueprint 'api' (mounted twice)<br/>require_auth · require_admin"]
        JWT["auth/jwt_helper.py<br/>HS256 issue / verify"]
        PEP["abac/pep.py<br/>@enforce_abac decorator"]
        PIP["abac/pip.py<br/>resolve subject/resource/action/env"]
        PDP["abac/pdp.py<br/>evaluate · explain"]
        PAP["abac/pap.py<br/>policy CRUD"]
        Rev["revocation/versioning.py<br/>compile_policy · key_attributes ·<br/>revoke_attribute · mark_stale_files"]
        Audit["audit/audit_log.py<br/>append · list · verify_chain"]
        Xform["cpabe_transform.py<br/>outsourced transform"]
        Meta["metadata/mongo.py<br/>MongoDB or LocalDatabase"]
        Store["storage/<br/>base · local_store · s3_store · azure_store*"]
    end

    subgraph Shared["client/ (Python)"]
        CPABE["crypto/cpabe.py → cpabe_simulated.py<br/>(Charm BSW07 when available)"]
        PyCrypto["crypto/aes_gcm · rsa_wrap · hashing"]
        UpDown["uploader.py · downloader.py"]
    end

    Seed["usecase/healthcare_demo.py<br/>seed + console walkthrough"]
    Bench["evaluation/benchmarks.py<br/>revocation_cost_model.py"]

    ApiTs -- "JSON over HTTP" --> App
    App --> JWT
    App --> PEP
    PEP --> JWT
    PEP --> PIP
    PEP --> PDP
    PEP --> Audit
    PDP --> PAP
    App --> PAP
    App --> PDP
    App --> Rev
    App --> Audit
    App --> Xform
    App --> CPABE
    App --> Store
    Xform --> CPABE
    PIP --> Meta
    PAP --> Meta
    Rev --> Meta
    Audit --> Meta
    App --> Meta
    App -- "/admin/reset-demo, bootstrap" --> Seed
    App -- "/bench" --> Bench
    Seed --> UpDown
    Bench --> UpDown
    UpDown --> CPABE
    UpDown --> PyCrypto
```

\* `server/storage/azure_store.py` implements the `ObjectStore` interface but is **not selected anywhere** in `app.py`; only `LocalStore` and `S3Store` are wired in.

**Note on code placement:** the server imports `client/crypto/cpabe.py` directly. The authority uses it for `setup` and `keygen`, and `cpabe_transform.py` uses it for `transform`. The Python CP-ABE module is therefore shared between client-side tooling and the server.

---

## 4. Database schema

MongoDB is schemaless; the structure below is what the code reads and writes. There are no foreign-key constraints and no indexes are created by the code. Relationships are logical, by key value. The same documents are used by the local JSON fallback (`LocalDatabase` in `server/metadata/mongo.py`).

```mermaid
erDiagram
    USERS {
        string username PK "lower-case, unique by check in /register"
        string display_name
        string password "werkzeug salted hash (legacy SHA-256 hex accepted)"
        object attributes "role, department, clearance 1-5"
        bool active "false = suspended"
        string pub_key_pem "RSA-2048 device public key, nullable"
    }
    FILES {
        string file_id PK "16 hex chars; also the object-store key"
        string filename
        string owner FK "users.username"
        string department "ABAC resource attribute"
        int clearance_required "ABAC resource attribute"
        string policy "compiled CP-ABE policy, e.g. cardiology_v2 and level2_v1"
        string policy_display "human policy, e.g. cardiology and level2"
        object wrapped_dek_abe "CP-ABE ciphertext of the DEK"
        object wrapped_dek_rsa_map "username -> RSA-OAEP wrapped DEK"
        string wrapped_dek_rsa "legacy single RSA wrap, nullable"
        string nonce "AES-GCM nonce, base64"
        string tag "AES-GCM tag, base64"
        string checksum "SHA-256 hex of plaintext"
        string signature "RSA-PSS over SHA-256(ciphertext), nullable"
        string signer_pub_key_pem
        int size_bytes "ciphertext size"
        int plain_size
        string mime_type
        string uploaded_at "ISO-8601 UTC"
        bool stale "needs lazy re-wrap"
        int rewrap_count
    }
    POLICIES {
        string policy_id PK
        string title
        string description
        bool enabled
        object target "action, resource match"
        array rules "rule_id, effect permit|deny, condition tree"
    }
    ATTRIBUTE_VERSIONS {
        string attribute PK "slug, e.g. cardiology"
        int version "absent = 1"
        array revocations "username, retired_version"
    }
    AUDIT_LOGS {
        int seq PK "1, 2, 3 ..."
        string ts "ISO-8601 UTC"
        string actor "username or system"
        string action
        string resource "file_id, policy_id or username"
        string decision "permit | deny | info"
        string detail
        string prev_hash "hash of seq-1, or 64 zeros"
        string hash "SHA-256(prev_hash + canonical JSON)"
    }
    ABE_PARAMS {
        string type "authority_keys"
        object public_key "stored as field pk: CP-ABE public key"
        object master_key "stored as field msk: CP-ABE master secret key"
    }
    CIPHERTEXT_BLOB {
        string key PK "= files.file_id"
        bytes data "AES-GCM ciphertext (local dir or S3)"
    }

    USERS ||--o{ FILES : "owns (owner)"
    USERS }o--o{ FILES : "device-bound recipient (wrapped_dek_rsa_map keys)"
    FILES ||--|| CIPHERTEXT_BLOB : "file_id = key"
    ATTRIBUTE_VERSIONS ||--o{ FILES : "version tokens in compiled policy"
    USERS ||--o{ ATTRIBUTE_VERSIONS : "listed in revocations"
    USERS ||--o{ AUDIT_LOGS : "actor"
    AUDIT_LOGS ||--o| AUDIT_LOGS : "prev_hash -> hash"
```

**Client-side storage (browser):**

| Store | Key | Contents | Code |
|---|---|---|---|
| IndexedDB `tessera-device` / `keys` | username | `{ oaepPriv, pssPriv (non-extractable CryptoKey), publicPem, fingerprint }` | `lib/crypto.ts` |
| sessionStorage `tessera.session` | — | JWT and public profile | `lib/session.tsx` |
| localStorage `tessera.theme` | — | appearance preference only | `main.tsx`, `pages/Settings.tsx` |

The CP-ABE secret key is held in React state only (re-fetched via `/me`), not persisted.

---

## 5. Key user flows

### 5.1 Registration, login and device-key binding

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant B as Browser (session.tsx, crypto.ts)
    participant A as Flask API (app.py)
    participant D as Metadata store
    participant L as Audit log

    opt New account
        U->>B: name, username, password, role, department, clearance
        B->>A: POST /api/register
        A->>A: reject Admin role, clamp clearance 1-5, werkzeug hash
        A->>D: users.insert_one
        A->>L: append(register)
        A-->>B: 201
    end
    U->>B: username + password
    B->>A: POST /api/login
    A->>D: users.find_one(username)
    alt bad password or suspended
        A->>L: append(login, deny)
        A-->>B: 401 / 403
    else ok
        A->>A: JWT (HS256, 1 h, sub + attributes)
        A->>D: attribute_versions.find (versioning.key_attributes)
        A->>A: cpabe.keygen(pk, msk, versioned attribute tokens)
        A->>L: append(login, permit)
        A-->>B: token, abe_sk, user
    end
    B->>B: sessionStorage.set(token)
    B->>B: loadDeviceKey(username) from IndexedDB
    alt no device key in this browser
        B->>B: generate RSA-2048, re-import private halves non-extractable, save to IndexedDB
    end
    opt server key differs from local key
        B->>A: PUT /api/me/device-key {pub_key_pem}
        A->>D: users.update_one(pub_key_pem)
        A->>L: append(bind_device_key)
    end
```

### 5.2 Upload (three-tier wrap) — `runUpload` in `lib/pipeline.ts`

```mermaid
sequenceDiagram
    autonumber
    actor U as Uploader
    participant B as Browser (pipeline.ts / crypto.ts)
    participant A as Flask API
    participant D as Metadata store
    participant O as Object store
    participant L as Audit log

    U->>B: file + policy (department, min clearance, roles) + optional recipients
    B->>A: GET /api/abe-params
    A-->>B: CP-ABE public key
    B->>A: POST /api/abe/compile {policy}
    A->>D: attribute_versions.find
    A-->>B: compiled policy (e.g. cardiology_v1 and level2_v1)
    B->>B: DEK = 32 random bytes
    B->>B: AES-256-GCM(DEK, file) -> ciphertext, nonce, tag
    B->>B: CP-ABE wrap(pk, DEK, compiled policy)
    opt recipients selected
        B->>A: GET /api/users (recipient public keys)
        B->>B: RSA-OAEP wrap(DEK) per recipient
    end
    B->>B: SHA-256(plaintext) checksum, RSA-PSS sign SHA-256(ciphertext)
    B->>A: POST /api/upload {envelope, metadata, signer key}
    A->>A: require_auth (JWT), reject suspended uploader
    A->>O: put(file_id, ciphertext bytes)
    A->>D: files.replace_one(record without ciphertext)
    A->>L: append(upload)
    A-->>B: 201 {file_id}
```

### 5.3 Download: ABAC gate, outsourced decryption, lazy re-wrap — `runDownload`

Preceded, when relevant, by an administrator revoking an attribute (`POST /api/admin/revoke`). That updates the user's directory attributes, bumps the attribute version and sets `stale=true` on every file whose policy uses it.

```mermaid
sequenceDiagram
    autonumber
    actor U as Reader
    participant B as Browser
    participant P as PEP / PIP / PDP
    participant A as Flask route
    participant D as Metadata store
    participant O as Object store
    participant L as Audit log

    B->>A: GET /api/me (fresh CP-ABE key with current versions)
    A-->>B: abe_sk
    B->>P: GET /api/download/{file_id}
    P->>P: verify JWT
    P->>D: user attributes + status, file attributes (PIP)
    P->>D: policies (PDP via PAP)
    alt Deny
        P->>L: append(read, deny)
        P-->>B: 403
    else Permit
        P->>A: continue to route
        A->>O: get(file_id)
        A->>L: append(download, permit)
        A-->>B: envelope + metadata + signer key + current compiled policy
    end
    B->>B: verify RSA-PSS signature before any key work
    alt Outsourced mode (default)
        B->>B: TK, DK(z) = makeTransformKey(abe_sk)
        B->>A: POST /api/transform/{id} {tk}  (same PEP gate)
        A->>A: cpabe.transform(pk, tk, wrapped_dek_abe)
        A->>L: append(transform)
        A-->>B: ct_prime
        B->>B: DEK = decryptTransformed(z, ct_prime)
    else On-device mode
        B->>B: DEK = CP-ABE decrypt(abe_sk, wrapped_dek_abe)
    else Device-key mode (Tier 3)
        B->>B: DEK = RSA-OAEP unwrap with non-extractable device key
    end
    B->>B: AES-GCM decrypt (tag verified), compare SHA-256 checksum
    opt file.stale (after a revocation)
        B->>B: new wrap = CP-ABE wrap(pk, DEK, current compiled policy)
        B->>A: POST /api/files/{id}/rewrap  (same PEP gate)
        A->>A: accept only if new policy == compile_policy(policy_display)
        A->>D: files.update_one(wrapped_dek_abe, policy, stale=false, rewrap_count+1)
        A->>L: append(lazy_rewrap)
    end
    B-->>U: rendered document / Save
```

---

## 6. Data flow

```mermaid
flowchart LR
    subgraph Input["User input"]
        F["File bytes"]
        Pol["Access choices<br/>department · clearance · roles"]
        R["Recipients (optional)"]
    end

    subgraph BrowserOnly["Stays in the browser"]
        DEK["DEK (32 bytes)"]
        PT["Plaintext"]
        Z["Secret z (outsourced decryption)"]
        PRIV["RSA private key"]
    end

    subgraph Sent["Sent to server"]
        CT["Ciphertext"]
        NT["nonce + tag"]
        WABE["CP-ABE wrapped DEK"]
        WRSA["RSA-wrapped DEKs"]
        SIG["signature + signer public key"]
        MD["filename · department · clearance ·<br/>policy text · checksum · sizes · mime"]
    end

    F --> PT
    PT -->|AES-256-GCM| CT
    PT -->|SHA-256| MD
    DEK -->|key for| CT
    DEK -->|CP-ABE wrap| WABE
    DEK -->|RSA-OAEP| WRSA
    Pol -->|compose + /abe/compile| WABE
    Pol --> MD
    R --> WRSA
    PRIV -->|RSA-PSS| SIG

    CT -->|POST /upload| OBJ[("Object store<br/>key = file_id")]
    NT --> META[("files collection")]
    WABE --> META
    WRSA --> META
    SIG --> META
    MD --> META

    META -->|GET /download after PEP Permit| ENV["Envelope back to browser"]
    OBJ --> ENV
    ENV -->|"TK -> /transform -> ct_prime, finished with z"| DEK2["DEK recovered in browser"]
    DEK2 -->|AES-GCM decrypt + checksum| OUT["Plaintext shown / saved"]
    DEK2 -.->|"if stale: re-wrap 32 bytes -> /rewrap"| META
```

Every state-changing or access-decision step also appends to `audit_logs` (see §8).

---

## 7. Technology stack and rationale

| Layer | Technology (as used) | Why |
|---|---|---|
| Web client | React 19, TypeScript, Vite 8 (`client/ui/package.json`) | Component model for the multi-page app; type safety for crypto envelope shapes; fast static build served by Flask |
| Motion / UI | `motion` (springs, layout animations), `lucide-react` icons, self-hosted Inter via `@fontsource-variable/inter` | Interruptible spring animations; no runtime CDN dependency |
| Client crypto | Browser **WebCrypto** (`crypto.subtle`) | Native AES-GCM, RSA-OAEP, RSA-PSS, SHA-256; private keys can be non-extractable |
| API server | Python 3, **Flask** 3, **Waitress** WSGI | Same language as the crypto core and Charm-Crypto; Waitress is a production server that listens on IPv4 and IPv6 loopback |
| Server / Python crypto | PyCA `cryptography` (AES-GCM, RSA-OAEP, RSA-PSS) | Audited, standard primitives |
| Attribute-based crypto | Charm-Crypto BSW07 CP-ABE (`ABE_MODE=real`, Docker); simulated module otherwise | BSW07 is the scheme named in the specification; the fallback keeps the same interface where PBC cannot be built |
| Auth | PyJWT (HS256), werkzeug password hashing | Stateless bearer tokens carrying ABAC subject claims |
| Metadata | MongoDB via `pymongo`; JSON-file fallback | Flexible documents for nested envelopes and policy trees |
| Object storage | Local directory or AWS S3 (`boto3`) behind `ObjectStore` | Keeps large ciphertext out of the database; pluggable backend |
| Evaluation | `matplotlib`, custom timers | CSV + PNG output in `evaluation/results/` |
| Testing | `pytest` (38 tests) | Crypto round-trips, ABAC, API end-to-end, revocation, audit tamper detection |
| Packaging | Docker (python:3.10-slim + PBC 0.5.14 + Charm), docker-compose with `mongo:6.0` | Reproducible build of the native pairing library |

---

## 8. API endpoints

All routes are registered on one blueprint mounted at both `/` (legacy, used by the Python tests) and `/api` (used by the web client). "PEP" means the route is wrapped in `@pep.enforce_abac("read")`.

| Method | Path | Auth | Purpose | Audit event |
|---|---|---|---|---|
| GET | `/health` | none | version, CP-ABE mode, metadata and storage backends, demo flag | — |
| GET | `/abe-params` | none | CP-ABE public key | — |
| GET | `/abe/versions` | none | current attribute versions | — |
| POST | `/abe/compile` | none | compile human policy → versioned policy; list unknown attributes | — |
| POST | `/register` | none | create account (Admin role refused, clearance clamped 1–5) | `register` |
| POST | `/login` | none | verify password; return JWT + CP-ABE key | `login` permit/deny |
| GET | `/me` | JWT | profile + freshly issued CP-ABE key | — |
| PUT | `/me/device-key` | JWT | bind RSA public key | `bind_device_key` |
| GET | `/users` | JWT | public profiles (incl. public keys) | — |
| GET | `/policies` | none | list ABAC policies | — |
| POST | `/policies` | Admin | create / replace policy | `policy_upsert` |
| PATCH | `/policies/<policy_id>` | Admin | enable / disable | `policy_toggle` |
| DELETE | `/policies/<policy_id>` | Admin | delete | `policy_delete` |
| POST | `/abac/simulate` | JWT | PDP `explain()` on hypothetical attributes (not logged) | — |
| POST | `/upload` | JWT | store ciphertext + envelope metadata | `upload` |
| GET | `/files` | JWT | catalogue with a live PDP decision per file for the caller | — |
| GET | `/download/<file_id>` | JWT + PEP | envelope + ciphertext | `download` (deny logged by PEP) |
| POST | `/transform/<file_id>` | JWT + PEP | outsourced CP-ABE transform | `transform` |
| POST | `/files/<file_id>/rewrap` | JWT + PEP | lazy re-wrap; only under the current compiled policy | `lazy_rewrap` |
| DELETE | `/files/<file_id>` | owner or Admin | delete blob + record | `delete` |
| GET | `/breach/<file_id>` | JWT, `DEMO_MODE=true` | ciphertext **without** ABAC (demonstration) | `breach_simulation` |
| POST | `/admin/revoke` | Admin | revoke role / department / clearance | `revoke_attribute` |
| POST | `/admin/users/<username>/active` | Admin | suspend / reinstate | `suspend_user` / `reinstate_user` |
| POST | `/admin/reset-demo` | Admin | re-seed demo data | `demo_reset` |
| GET | `/audit` | JWT | latest entries (`?limit=`, default 300) | — |
| GET | `/audit/verify` | JWT | recompute the hash chain | — |
| GET | `/bench` | JWT | quick benchmark sweep | — |
| GET | `/`, `/assets/*`, `/<name>.<svg,png,ico,txt,webmanifest>` | none | built web client | — |

---

## 9. Authentication and security approach

**Authentication**
- Passwords are stored with `werkzeug.security.generate_password_hash` (salted, scrypt by default). Old unsalted SHA-256 hex hashes are still verified, with a constant-time comparison (`_check_password`).
- Login issues an HS256 JWT (`server/auth/jwt_helper.py`) with `sub`, `iat`, `exp` (1 hour) and the subject's attributes. The client sends it as `Authorization: Bearer …`.
- `require_auth` verifies the token and loads the directory record; `require_admin` additionally requires the role `admin`.

**Authorisation — ABAC (NIST SP 800-162 roles)**
- **PEP** (`abac/pep.py`) intercepts gated routes. **PIP** (`abac/pip.py`) re-reads subject attributes and account status from the directory on every request, rather than trusting the JWT claims, plus resource attributes (owner, department, clearance, recipients) and environment attributes (UTC hour, local hour, day, IP). **PDP** (`abac/pdp.py`) evaluates JSON condition trees (`and`/`or`/`not`, `eq`/`neq`/`gt`/`gte`/`lt`/`lte`, `in`, and `$`-references between attributes) with deny-override and deny-by-default. **PAP** (`abac/pap.py`) stores policies.
- Seeded policies: suspended-accounts (deny), owner-access, direct-share, department-clearance, business-hours (disabled by default).

**Authorisation — cryptographic**
- The DEK is wrapped under a CP-ABE policy compiled to versioned attributes. A user's key carries their attribute tokens; clearance is a ladder (clearance 3 → `level1..level3`).
- **Outsourced decryption:** the server transforms with a TK; the final step needs `z`, which stays in the browser.

**Confidentiality and integrity**
- AES-256-GCM with a fresh DEK and 96-bit random nonce per file; GCM tag, SHA-256 plaintext checksum and an RSA-PSS (SHA-256, salt length 222) signature over SHA-256(ciphertext). The browser verifies the signature before unwrapping any key.
- Device private keys are re-imported into WebCrypto as **non-extractable** before being stored in IndexedDB.

**Revocation**
- Instant at the ABAC layer: a directory update or suspension takes effect on the next request, because the PIP reads the directory each time.
- Cryptographic, lazy: the attribute version is bumped and files are flagged `stale`; the next authorised reader re-wraps the DEK. `/rewrap` rejects any policy other than the current compiled one. Revoked users never re-receive retired versions (`_revoked_pairs`).

**Audit**
- Append-only, hash-chained entries; `verify_chain()` locates the first broken link. Appends are serialised with a process-local lock.

---

## 10. Scalability considerations

What helps:
- **Stateless API.** Authentication is a self-contained JWT, so Flask workers need no shared session store.
- **Ciphertext is decoupled from metadata.** Large blobs go to the object store (local or S3); MongoDB holds only small records.
- **Revocation cost is O(32 bytes) per affected file**, and it is deferred to the next access (`evaluation/revocation_cost_model.py`).
- **Outsourced decryption** moves the expensive CP-ABE step off the client.

Constraints in the current code:
- **Whole files in memory.** Uploads and downloads are single base64 JSON bodies (limit `MAX_CONTENT_LENGTH` = 80 MB, UI limit 50 MB). There is no streaming or chunking on either side.
- **`GET /files` runs the PDP once per file** for the caller, and `mark_stale_files` scans every file record: both are O(number of files).
- **No database indexes** are created (e.g. on `files.file_id`, `users.username`, `audit_logs.seq`).
- **The audit chain uses a process-local `threading.Lock`.** With multiple server processes, concurrent appends could compute the same `seq`/`prev_hash`. It is safe only with the single Waitress process (8 threads) used here.
- **CP-ABE parameters are cached in a module-global** per process (`abe_pk`, `abe_msk`).
- **The local JSON metadata fallback** rewrites the whole file on every write and is single-process only. It is intended as a demo safety net.

---

## 11. Known limitations

1. **Simulated CP-ABE outside Docker.** Charm-Crypto (BSW07) needs PBC, which is built only in the Docker image. Elsewhere, `cpabe_simulated.py` is used. In that module the "public key", user secret key and transformation key all embed the same symmetric master key, and policy checks are enforced in code. It reproduces the interface and policy semantics but **provides no cryptographic access control**: anyone holding a simulated key or TK, including the server receiving a TK, could unwrap any DEK. The security claims of Tier 2 hold only with `ABE_MODE=real`.
2. **The browser implements only the simulated wire format.** With `ABE_MODE=real`, the web client refuses Tier 2 operations (`assertBrowserEngine`), and the Python client must be used.
3. **Self-asserted attributes.** `/register` lets users choose their role, department and clearance (only Admin is blocked, and clearance is clamped to 1–5). There is no attribute-authority verification step.
4. **Demo affordances.** A default `JWT_SECRET`, seeded demo passwords, and the `/breach` endpoint (enabled while `DEMO_MODE=true`, the default) are for demonstration.
5. **Token handling.** JWTs live in `sessionStorage` (readable by any script on the page if XSS existed). There is no refresh token, denylist or rate limiting. Suspension is still enforced on every gated request via the PIP.
6. **Open read endpoints.** `GET /policies`, `/abe-params`, `/abe/versions` and `POST /abe/compile` require no authentication.
7. **Lazy re-wrap depends on access.** Files never opened again after a revocation stay wrapped under the old version; until then only the ABAC layer stops a revoked user who already holds an old key.
8. **Audit chain is not externally anchored or signed.** It detects edits to individual entries, but someone with write access to the whole collection could rebuild a consistent chain.
9. **Device keys are per browser.** Clearing site data or using another browser creates a new key; files bound to the old key can no longer be unwrapped with Tier 3.
10. **Azure Blob storage** is implemented (`azure_store.py`) but not wired into `app.py`, and `azure-storage-blob` is not in `requirements.txt`.
11. **Post-quantum wrapping** (ML-KEM / lattice ABE) and **multi-authority ABE** are not implemented. They are future work in the specification.
12. **No indexes, no streaming, single-process audit lock** — see §10.
