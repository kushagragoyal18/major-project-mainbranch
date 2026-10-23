"""
Flask API Server Entry Point
Implements Specification Section: §6.1 (Components), §6.2 (Upload), §6.3 (Download), §6.4 (Revocation), §7, §8
Implements Objectives: O1 (Confidentiality), O2 (Cryptographic authorisation), O3 (ABAC),
                       O4 (Efficient revocation), O5 (Integrity), O6 (Evaluation)

This module implements the main Flask application. All routes live on one blueprint that is
mounted twice: at "/" (the original API used by the Python client and tests) and at "/api"
(used by the web client in client/ui). The built web client is served from "/".

Core routes
    /register, /login, /me                 - accounts, JWT issue, CP-ABE key issue
    /abe-params, /abe/versions, /abe/compile - CP-ABE public key and attribute versions
    /policies                              - ABAC Policy Administration Point (PAP)
    /upload, /files, /download/<id>        - ciphertext catalogue (PEP-gated reads)
    /transform/<id>                        - outsourced CP-ABE decryption (PEP-gated)
    /files/<id>/rewrap                     - lazy re-wrap of a 32-byte DEK after revocation
    /admin/revoke, /admin/users/<u>/active - revocation console
    /audit, /audit/verify                  - hash-chained audit log
    /bench                                 - live micro-benchmarks (O6)
    /breach/<id>                           - demo only: ciphertext without the ABAC gate
"""

import os
import base64
import hashlib
import logging
import secrets
from functools import wraps
from flask import Flask, Blueprint, request, jsonify, g, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from server.metadata import mongo
from server.metadata.mongo import db, users_col, files_col
from server.auth import jwt_helper
from server.abac import pap, pep, pip, pdp
from server.audit import audit_log
from server.revocation import versioning
from server import cpabe_transform
from server.storage.local_store import LocalStore
from server.storage.s3_store import S3Store
from client.crypto import cpabe

# Setup server logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

APP_VERSION = "1.0.0"
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
UI_DIST = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "client", "ui", "dist"))

app = Flask(__name__, static_folder=None)
# Base64 inflates payloads by ~4/3, so 80 MB of JSON is roughly a 60 MB file.
app.config["MAX_CONTENT_LENGTH"] = 80 * 1024 * 1024
api = Blueprint("api", __name__)

# -----------------------------------------------------------------------------
# Persist CP-ABE Authority Parameters
# -----------------------------------------------------------------------------
# Persist the CP-ABE Setup PK and MSK so they are consistent across server lifetimes.
abe_params_col = db["abe_params"]
abe_pk = None
abe_msk = None


def get_abe_keys():
    """Lazily initializes and returns the CP-ABE authority parameters (PK, MSK)."""
    global abe_pk, abe_msk
    if abe_pk is None or abe_msk is None:
        # Load from DB collection
        record = abe_params_col.find_one({"type": "authority_keys"})
        if record:
            abe_pk = record["pk"]
            abe_msk = record["msk"]
            logger.info("Loaded persisted CP-ABE authority keys from the metadata store.")
        else:
            # Generate new keys
            pk, msk = cpabe.setup()
            abe_params_col.insert_one({
                "type": "authority_keys",
                "pk": pk,
                "msk": msk
            })
            abe_pk = pk
            abe_msk = msk
            logger.info("Generated and persisted new CP-ABE authority keys.")
    return abe_pk, abe_msk

# -----------------------------------------------------------------------------
# Initialize Object Storage Backend
# -----------------------------------------------------------------------------
USE_LOCAL_STORAGE = os.getenv("USE_LOCAL_STORAGE", "true").lower() == "true"
if USE_LOCAL_STORAGE:
    storage = LocalStore()
    logger.info(f"Local storage backend enabled at: {storage.base_dir}")
else:
    storage = S3Store()
    logger.info(f"AWS S3 storage backend enabled on bucket: {storage.bucket_name}")


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def _hash_password(password: str) -> str:
    # SECURITY: salted, iterated hash (scrypt/pbkdf2 via werkzeug), not bare SHA-256.
    return generate_password_hash(password)


def _check_password(stored: str, password: str) -> bool:
    # Accounts created before the upgrade stored an unsalted SHA-256 hex digest.
    if len(stored) == 64 and ":" not in stored:
        return secrets.compare_digest(stored, hashlib.sha256(password.encode("utf-8")).hexdigest())
    return check_password_hash(stored, password)


def _issue_abe_key(username: str, attributes: dict) -> dict:
    """Issues a CP-ABE secret key carrying the user's current (and historic) attribute versions."""
    pk, msk = get_abe_keys()
    attrs = versioning.key_attributes(username, attributes)
    # Keep the original "levelN" tag so policies written before versioning still work.
    attrs.append(f"level{int(attributes.get('clearance', 1))}")
    return cpabe.keygen(pk, msk, sorted(set(attrs)))


def _public_user(u: dict) -> dict:
    return {
        "username": u["username"],
        "display_name": u.get("display_name") or u["username"],
        "attributes": u.get("attributes", {}),
        "active": u.get("active", True),
        "pub_key_pem": u.get("pub_key_pem"),
    }


def require_auth(f):
    """Verifies the bearer JWT and loads the caller's directory record into g."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing authorization header"}), 401
        try:
            claims = jwt_helper.decode_token(auth_header.split(" ", 1)[1])
        except Exception:
            return jsonify({"error": "Unauthorized"}), 401
        g.user_id = claims["sub"]
        g.user = users_col.find_one({"username": g.user_id}, {"_id": 0})
        g.claims = claims
        return f(*args, **kwargs)
    return wrapper


def _is_admin() -> bool:
    attrs = (g.user or {}).get("attributes") or g.claims.get("attributes", {})
    return versioning.slug(attrs.get("role", "")) == "admin"


def require_admin(f):
    @wraps(f)
    @require_auth
    def wrapper(*args, **kwargs):
        if not _is_admin():
            audit_log.append(g.user_id, request.endpoint.split(".")[-1], None, "deny", "Admin role required")
            return jsonify({"error": "Administrator role required"}), 403
        return f(*args, **kwargs)
    return wrapper


def _file_summary(f: dict, decision: dict = None) -> dict:
    return {
        "file_id": f["file_id"],
        "filename": f["filename"],
        "owner": f["owner"],
        "department": f.get("department"),
        "clearance_required": f.get("clearance_required", 1),
        "policy": f.get("policy"),
        "policy_display": f.get("policy_display") or f.get("policy"),
        "size_bytes": f.get("size_bytes", 0),
        "plain_size": f.get("plain_size"),
        "mime_type": f.get("mime_type"),
        "uploaded_at": f.get("uploaded_at"),
        "stale": bool(f.get("stale")),
        "rewrap_count": f.get("rewrap_count", 0),
        "signed": bool(f.get("signature")),
        "recipients": sorted((f.get("wrapped_dek_rsa_map") or {}).keys()),
        "decision": decision,
    }


# -----------------------------------------------------------------------------
# System & CP-ABE parameters
# -----------------------------------------------------------------------------
@api.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "version": APP_VERSION,
        "abe_mode": "simulated" if cpabe.is_simulated() else "charm-bsw07",
        "metadata_backend": mongo.BACKEND,
        "storage_backend": "local" if USE_LOCAL_STORAGE else "s3",
        "demo_mode": DEMO_MODE,
    })


@api.route("/abe-params", methods=["GET"])
def get_abe_params():
    """Returns the serialized CP-ABE Public Key so uploader can encrypt the DEK."""
    pk, _ = get_abe_keys()
    return jsonify({"pk": pk, "simulated": cpabe.is_simulated()})


@api.route("/abe/versions", methods=["GET"])
def abe_versions():
    return jsonify(versioning.get_versions())


@api.route("/abe/compile", methods=["POST"])
def abe_compile():
    """Compiles a human policy into its versioned form and lists the attributes it uses."""
    policy = (request.get_json() or {}).get("policy", "").strip()
    if not policy:
        return jsonify({"error": "Empty policy"}), 400
    known = set()
    for u in users_col.find({}, {"_id": 0}):
        known.update(versioning.subject_tokens(u.get("attributes", {})))
    attrs = sorted(versioning.policy_attributes(policy))
    return jsonify({
        "compiled": versioning.compile_policy(policy),
        "attributes": attrs,
        "unknown": [a for a in attrs if a not in known],
    })


# -----------------------------------------------------------------------------
# Accounts
# -----------------------------------------------------------------------------
@api.route("/register", methods=["POST"])
def register():
    """Registers a new user, hashes password, and saves their attributes and RSA public key."""
    data = request.get_json() or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password")
    role = data.get("role", "User")
    department = data.get("department", "Default")
    clearance = data.get("clearance", 1)
    pub_key_pem = data.get("pub_key_pem")  # Optional recipient RSA public key

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    # Check if user already exists
    if users_col.find_one({"username": username}):
        return jsonify({"error": "User already exists"}), 409

    # SECURITY: self-registration can never grant the Admin role.
    if versioning.slug(role) == "admin":
        role = "User"

    user_record = {
        "username": username,
        "display_name": data.get("display_name") or username,
        "password": _hash_password(password),
        "attributes": {
            "role": role,
            "department": department,
            "clearance": max(1, min(5, int(clearance)))
        },
        "active": True,
        "pub_key_pem": pub_key_pem
    }
    users_col.insert_one(user_record)
    audit_log.append(username, "register", username, "info", f"{role} · {department} · L{clearance}")
    return jsonify({"message": "User registered successfully"}), 201


@api.route("/login", methods=["POST"])
def login():
    """Authenticates credentials and issues a JWT token plus a CP-ABE secret key."""
    data = request.get_json() or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    user_record = users_col.find_one({"username": username})
    if not user_record or not _check_password(user_record["password"], password):
        audit_log.append(username, "login", username, "deny", "Bad credentials")
        return jsonify({"error": "Invalid username or password"}), 401
    if not user_record.get("active", True):
        audit_log.append(username, "login", username, "deny", "Account suspended")
        return jsonify({"error": "This account has been suspended"}), 403

    token = jwt_helper.generate_token(username, user_record["attributes"])
    sk = _issue_abe_key(username, user_record["attributes"])
    audit_log.append(username, "login", username, "permit", "JWT + CP-ABE key issued")

    return jsonify({
        "token": token,
        "attributes": user_record["attributes"],
        "abe_sk": sk,
        "pub_key_pem": user_record.get("pub_key_pem"),
        "user": _public_user(user_record),
    }), 200


@api.route("/me", methods=["GET"])
@require_auth
def me():
    """Returns the caller's profile and a freshly issued CP-ABE key (picks up version bumps)."""
    if not g.user:
        return jsonify({"error": "Unknown user"}), 404
    if not g.user.get("active", True):
        return jsonify({"error": "This account has been suspended"}), 403
    return jsonify({"user": _public_user(g.user), "abe_sk": _issue_abe_key(g.user_id, g.user["attributes"])})


@api.route("/me/device-key", methods=["PUT"])
@require_auth
def bind_device_key():
    """Binds this device's RSA public key (Tier 3 / signatures) to the account."""
    pem = (request.get_json() or {}).get("pub_key_pem", "")
    if "BEGIN PUBLIC KEY" not in pem:
        return jsonify({"error": "Expected a PEM public key"}), 400
    users_col.update_one({"username": g.user_id}, {"$set": {"pub_key_pem": pem}})
    fp = hashlib.sha256(pem.encode()).hexdigest()[:16]
    audit_log.append(g.user_id, "bind_device_key", g.user_id, "info", f"RSA-2048 key {fp}")
    return jsonify({"message": "Device key bound", "fingerprint": fp})


@api.route("/users", methods=["GET"])
@require_auth
def list_users():
    return jsonify([_public_user(u) for u in users_col.find({}, {"_id": 0})])


# -----------------------------------------------------------------------------
# ABAC policy administration (PAP)
# -----------------------------------------------------------------------------
@api.route("/policies", methods=["POST"])
@require_admin
def add_policy():
    """Saves a JSON ABAC policy (PAP)."""
    policy = request.get_json() or {}
    try:
        pap.add_policy(policy)
        audit_log.append(g.user_id, "policy_upsert", policy.get("policy_id"), "info", policy.get("description", ""))
        return jsonify({"message": f"Policy '{policy.get('policy_id')}' added successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@api.route("/policies", methods=["GET"])
def get_all_policies():
    """Returns all ABAC policies."""
    return jsonify(pap.get_all_policies()), 200


@api.route("/policies/<policy_id>", methods=["PATCH"])
@require_admin
def toggle_policy(policy_id):
    policy = pap.get_policy(policy_id)
    if not policy:
        return jsonify({"error": "Policy not found"}), 404
    policy["enabled"] = bool((request.get_json() or {}).get("enabled", True))
    pap.add_policy(policy)
    audit_log.append(g.user_id, "policy_toggle", policy_id, "info", "enabled" if policy["enabled"] else "disabled")
    return jsonify(policy)


@api.route("/policies/<policy_id>", methods=["DELETE"])
@require_admin
def delete_policy(policy_id):
    if not pap.delete_policy(policy_id):
        return jsonify({"error": "Policy not found"}), 404
    audit_log.append(g.user_id, "policy_delete", policy_id, "info", "")
    return jsonify({"message": "Deleted"})


@api.route("/abac/simulate", methods=["POST"])
@require_auth
def abac_simulate():
    """Runs the PDP against a hypothetical subject/resource so the policy studio can preview decisions."""
    data = request.get_json() or {}
    subject = dict(data.get("subject", {}))
    subject.setdefault("status", "active")
    subject.setdefault("id", "preview")
    resource = data.get("resource", {})
    env = pip.resolve_attributes("__preview__", None, "read")["environment"]
    env.update(data.get("environment", {}))
    attrs = {"subject": subject, "resource": resource, "action": {"name": data.get("action", "read")}, "environment": env}
    return jsonify(pdp.explain(attrs))


# -----------------------------------------------------------------------------
# Files
# -----------------------------------------------------------------------------
@api.route("/upload", methods=["POST"])
@require_auth
def upload():
    """
    Accepts the uploader cryptographic envelope.
    Decouples storage:
    1. Extracts ciphertext and stores it in the Object Store.
    2. Saves the rest of the metadata details in the metadata store.
    """
    owner = g.user_id
    if g.user and not g.user.get("active", True):
        return jsonify({"error": "This account has been suspended"}), 403

    data = request.get_json() or {}
    file_id = data.get("file_id") or secrets.token_hex(8)
    filename = data.get("filename")
    department = data.get("department", "Default")
    clearance_required = data.get("clearance_required", 1)
    envelope = data.get("envelope")

    if not file_id or not filename or not envelope:
        return jsonify({"error": "Missing file_id, filename, or envelope"}), 400

    # Ensure uploader envelope is structurally valid
    if "ciphertext" not in envelope or "nonce" not in envelope or "tag" not in envelope:
        return jsonify({"error": "Invalid uploader envelope: missing AES GCM fields"}), 400

    # Decouple: Extract ciphertext bytes and upload to S3/Local Object Store
    try:
        ciphertext_bytes = base64.b64decode(envelope["ciphertext"].encode('utf-8'))
    except Exception:
        return jsonify({"error": "Malformed base64 ciphertext"}), 400

    # Store blob in ObjectStore
    if not storage.put(file_id, ciphertext_bytes):
        return jsonify({"error": "Failed to store file bytes in object store"}), 500

    import datetime
    # SECURITY: only ciphertext, wrapped keys and public metadata are stored server-side.
    file_record = {
        "file_id": file_id,
        "filename": filename,
        "owner": owner,
        "department": department,
        "clearance_required": int(clearance_required),
        "policy": envelope["policy"],
        "policy_display": data.get("policy_display") or envelope["policy"],
        "checksum": envelope["checksum"],
        "nonce": envelope["nonce"],
        "tag": envelope["tag"],
        "wrapped_dek_abe": envelope["wrapped_dek_abe"],
        "wrapped_dek_rsa": envelope.get("wrapped_dek_rsa"),
        "wrapped_dek_rsa_map": envelope.get("wrapped_dek_rsa_map") or {},
        "signature": envelope.get("signature"),
        "signer_pub_key_pem": data.get("signer_pub_key_pem") or (g.user or {}).get("pub_key_pem"),
        "size_bytes": len(ciphertext_bytes),
        "plain_size": data.get("plain_size"),
        "mime_type": data.get("mime_type"),
        "uploaded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "stale": False,
        "rewrap_count": 0,
    }

    files_col.replace_one({"file_id": file_id}, file_record, upsert=True)
    audit_log.append(owner, "upload", file_id, "info", f"{filename} · policy: {file_record['policy_display']}")
    return jsonify({"message": f"File '{filename}' uploaded and cataloged successfully", "file_id": file_id}), 201


@api.route("/files", methods=["GET"])
@require_auth
def list_files():
    """Lists the catalogue with a live ABAC decision for the caller on every file."""
    out = []
    for f in files_col.find({}, {"_id": 0}):
        attrs = pip.resolve_attributes(g.user_id, f["file_id"], "read", request.remote_addr or "127.0.0.1",
                                       g.claims.get("attributes"))
        out.append(_file_summary(f, pdp.explain(attrs)))
    out.sort(key=lambda x: x.get("uploaded_at") or "", reverse=True)
    return jsonify(out)


@api.route("/download/<file_id>", methods=["GET"])
@pep.enforce_abac("read")
def download(file_id):
    """
    Retrieves the file metadata and ciphertext.
    Interpreted and gated by ABAC PEP decorator.
    """
    file_record = files_col.find_one({"file_id": file_id}, {"_id": 0})
    if not file_record:
        return jsonify({"error": "File not found"}), 404

    # Fetch file ciphertext bytes from ObjectStore
    try:
        ciphertext_bytes = storage.get(file_id)
    except FileNotFoundError:
        return jsonify({"error": "Ciphertext blob missing from object store"}), 404
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve ciphertext from storage: {e}"}), 500

    # Pack envelope back for client decryption
    envelope = {
        "ciphertext": base64.b64encode(ciphertext_bytes).decode('utf-8'),
        "nonce": file_record["nonce"],
        "tag": file_record["tag"],
        "wrapped_dek_abe": file_record["wrapped_dek_abe"],
        "wrapped_dek_rsa": file_record.get("wrapped_dek_rsa"),
        "signature": file_record.get("signature"),
        "checksum": file_record["checksum"],
        "policy": file_record["policy"]
    }
    mine = (file_record.get("wrapped_dek_rsa_map") or {}).get(g.user_id)
    if mine:
        envelope["wrapped_dek_rsa_mine"] = mine

    audit_log.append(g.user_id, "download", file_id, "permit", file_record["filename"])
    return jsonify({"envelope": envelope, "metadata": {
        **_file_summary(file_record),
        "signer_pub_key_pem": file_record.get("signer_pub_key_pem"),
        "current_policy": versioning.compile_policy(file_record.get("policy_display") or file_record["policy"]),
    }}), 200


@api.route("/transform/<file_id>", methods=["POST"])
@pep.enforce_abac("read")
def transform(file_id):
    """
    API endpoint for outsourced pairings calculations.
    Accepts user's Transformation Key (TK).
    Interpreted and gated by ABAC PEP decorator.
    Returns transformed ciphertext ct_prime.
    """
    file_record = files_col.find_one({"file_id": file_id})
    if not file_record:
        return jsonify({"error": "File not found"}), 404

    data = request.get_json() or {}
    tk = data.get("tk")
    if not tk:
        return jsonify({"error": "Missing transformation key 'tk'"}), 400

    # Run outsourced CP-ABE transform
    try:
        pk, _ = get_abe_keys()
        ct_prime = cpabe_transform.perform_transformation(pk, tk, file_record)
        audit_log.append(g.user_id, "transform", file_id, "permit", "Outsourced pairing transform")
        return jsonify({"ct_prime": ct_prime}), 200
    except PermissionError as e:
        audit_log.append(g.user_id, "transform", file_id, "deny", "CP-ABE policy not satisfied")
        return jsonify({"error": f"Access Denied during transform: {e}"}), 403
    except Exception as e:
        return jsonify({"error": f"Transformation execution error: {e}"}), 500


@api.route("/files/<file_id>/rewrap", methods=["POST"])
@pep.enforce_abac("read")
def rewrap(file_id):
    """
    Lazy re-wrap (§6.4): after revocation, the first authorised reader re-wraps the
    32-byte DEK under the current attribute versions. The file ciphertext is untouched.
    """
    f = files_col.find_one({"file_id": file_id}, {"_id": 0})
    if not f:
        return jsonify({"error": "File not found"}), 404
    data = request.get_json() or {}
    new_wrap = data.get("wrapped_dek_abe")
    expected = versioning.compile_policy(f.get("policy_display") or f["policy"])
    # SECURITY: the server only accepts a re-wrap under exactly the current compiled policy,
    # so a client cannot use this endpoint to weaken the file's access policy.
    if not new_wrap or new_wrap.get("policy") != expected:
        return jsonify({"error": "Re-wrap must target the current compiled policy", "expected": expected}), 400
    files_col.update_one({"file_id": file_id}, {"$set": {
        "wrapped_dek_abe": new_wrap, "policy": expected, "stale": False,
        "rewrap_count": int(f.get("rewrap_count", 0)) + 1,
    }})
    audit_log.append(g.user_id, "lazy_rewrap", file_id, "info",
                     f"DEK re-wrapped under {expected} (32 bytes; {f.get('size_bytes', 0)} ciphertext bytes untouched)")
    return jsonify({"message": "Re-wrapped", "policy": expected})


@api.route("/files/<file_id>", methods=["DELETE"])
@require_auth
def delete_file(file_id):
    f = files_col.find_one({"file_id": file_id}, {"_id": 0})
    if not f:
        return jsonify({"error": "File not found"}), 404
    if f["owner"] != g.user_id and not _is_admin():
        audit_log.append(g.user_id, "delete", file_id, "deny", "Only the owner or an admin can delete")
        return jsonify({"error": "Only the owner or an administrator can delete this file"}), 403
    storage.delete(file_id)
    files_col.delete_one({"file_id": file_id})
    audit_log.append(g.user_id, "delete", file_id, "info", f["filename"])
    return jsonify({"message": "Deleted"})


@api.route("/breach/<file_id>", methods=["GET"])
@require_auth
def breach(file_id):
    """
    DEMO ONLY: returns the stored envelope *without* the ABAC gate, simulating a
    compromised server or a malicious insider. It shows that CP-ABE alone still
    prevents decryption by anyone whose key does not satisfy the policy.
    """
    if not DEMO_MODE:
        return jsonify({"error": "Disabled outside demo mode"}), 404
    f = files_col.find_one({"file_id": file_id}, {"_id": 0})
    if not f:
        return jsonify({"error": "File not found"}), 404
    try:
        ciphertext_bytes = storage.get(file_id)
    except FileNotFoundError:
        return jsonify({"error": "Ciphertext blob missing"}), 404
    audit_log.append(g.user_id, "breach_simulation", file_id, "info", "ABAC layer bypassed for demonstration")
    return jsonify({"envelope": {
        "ciphertext": base64.b64encode(ciphertext_bytes).decode(),
        "nonce": f["nonce"], "tag": f["tag"], "wrapped_dek_abe": f["wrapped_dek_abe"],
        "checksum": f["checksum"], "policy": f["policy"],
    }, "metadata": _file_summary(f)})


# -----------------------------------------------------------------------------
# Revocation console
# -----------------------------------------------------------------------------
@api.route("/admin/revoke", methods=["POST"])
@require_admin
def revoke():
    data = request.get_json() or {}
    field = data.get("field")
    if field not in ("role", "department", "clearance"):
        return jsonify({"error": "field must be role, department or clearance"}), 400
    try:
        result = versioning.revoke_attribute(data.get("username", ""), field, data.get("value"))
    except KeyError as e:
        return jsonify({"error": str(e)}), 404
    audit_log.append(g.user_id, "revoke_attribute", result["username"], "info",
                     f"{field} → {data.get('value')}; "
                     + (", ".join(f"{t} v{v - 1}→v{v}" for t, v in result["bumped"].items()) or "no version change")
                     + f"; {len(result['stale_files'])} file key(s) queued for lazy re-wrap")
    return jsonify(result)


@api.route("/admin/users/<username>/active", methods=["POST"])
@require_admin
def set_active(username):
    if not users_col.find_one({"username": username}):
        return jsonify({"error": "Unknown user"}), 404
    active = bool((request.get_json() or {}).get("active", True))
    versioning.disable_user(username, active)
    audit_log.append(g.user_id, "reinstate_user" if active else "suspend_user", username, "info",
                     "ABAC layer updated instantly")
    return jsonify({"username": username, "active": active})


@api.route("/admin/reset-demo", methods=["POST"])
@require_admin
def reset_demo():
    from usecase import healthcare_demo
    healthcare_demo.seed(reset=True)
    global abe_pk, abe_msk
    abe_pk = abe_msk = None
    return jsonify({"message": "Demo data restored"})


# -----------------------------------------------------------------------------
# Audit & evaluation
# -----------------------------------------------------------------------------
@api.route("/audit", methods=["GET"])
@require_auth
def audit():
    return jsonify(audit_log.list_entries(int(request.args.get("limit", 300))))


@api.route("/audit/verify", methods=["GET"])
@require_auth
def audit_verify():
    return jsonify(audit_log.verify_chain())


@api.route("/bench", methods=["GET"])
@require_auth
def bench():
    from evaluation import benchmarks
    return jsonify(benchmarks.run_quick())


# -----------------------------------------------------------------------------
# Web client
# -----------------------------------------------------------------------------
app.register_blueprint(api, url_prefix="/api", name="api")
app.register_blueprint(api, name="legacy")


@app.route("/", methods=["GET"])
def index():
    if not os.path.exists(os.path.join(UI_DIST, "index.html")):
        return "Web client not built. Run `npm run build` in client/ui.", 503
    return send_from_directory(UI_DIST, "index.html")


@app.route("/assets/<path:path>", methods=["GET"])
def assets(path):
    return send_from_directory(os.path.join(UI_DIST, "assets"), path, max_age=31536000)


@app.route("/<path:name>.<ext>", methods=["GET"])
def root_static(name, ext):
    if ext not in ("svg", "png", "ico", "txt", "webmanifest"):
        return jsonify({"error": "Not found"}), 404
    return send_from_directory(UI_DIST, f"{name}.{ext}")


def bootstrap():
    """Ensures authority keys, default ABAC policies and demo data exist."""
    get_abe_keys()
    from usecase import healthcare_demo
    healthcare_demo.seed(reset=False)


if __name__ == "__main__":
    # Check metadata store connection
    from server.metadata.mongo import check_connection
    if check_connection():
        logger.info(f"Metadata store ready ({mongo.BACKEND}).")
    else:
        logger.error("Could not connect to MongoDB.")
    bootstrap()
    port = int(os.getenv("PORT", "5000"))
    host = os.getenv("HOST")
    try:
        from waitress import serve
        # Listen on IPv4 *and* IPv6 loopback: browsers resolve "localhost" to ::1 first,
        # and an IPv4-only server costs ~300 ms of fallback on every request.
        listen = f"{host}:{port}" if host else f"127.0.0.1:{port} [::1]:{port}"
        logger.info(f"test:202 is running at http://localhost:{port}")
        serve(app, listen=listen, threads=8)
    except ImportError:
        logger.info(f"test:202 is running at http://localhost:{port} (Flask development server)")
        app.run(host=host or "127.0.0.1", port=port, threaded=True)
