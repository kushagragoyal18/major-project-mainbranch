"""
Healthcare Records Use Case (Seed Data + End-to-End Demo)
Implements Specification Section: §4 (healthcare use case), §9 (Phase 5), §13 (Definition of Done)
Implements Objectives: O1–O5 (demonstrated end-to-end)

Seeds a small hospital: four staff members, the default ABAC policies and five
clinical documents. Every document is encrypted with the real client code path
(client/uploader.py): AES-256-GCM file encryption, CP-ABE wrap of the DEK under a
versioned policy, and an RSA-PSS signature by its author.

All patient data below is synthetic.

Run directly for a console walkthrough:
    python -m usecase.healthcare_demo
"""

import os
import datetime
from client import uploader, downloader
from client.crypto import cpabe, rsa_wrap

# Demo credentials for the local showcase build only.
DEMO_PASSWORD = "tessera-demo"

STAFF = [
    {"username": "alice", "display_name": "Dr. Alice Mehra", "role": "Doctor", "department": "Cardiology", "clearance": 3},
    {"username": "bob", "display_name": "Bob Fernandes", "role": "Nurse", "department": "Cardiology", "clearance": 2},
    {"username": "carol", "display_name": "Dr. Carol Iyer", "role": "Doctor", "department": "Oncology", "clearance": 3},
    {"username": "dana", "display_name": "Dana Kapoor", "role": "Admin", "department": "Security", "clearance": 4},
]

DEFAULT_POLICIES = [
    {
        "policy_id": "suspended-accounts",
        "title": "Suspended accounts",
        "description": "Deny every request from an account that has been suspended. Overrides all permits.",
        "enabled": True,
        "target": {},
        "rules": [{"rule_id": "deny-suspended", "effect": "deny",
                   "condition": {"eq": ["subject.status", "suspended"]}}],
    },
    {
        "policy_id": "owner-access",
        "title": "Owners read their own files",
        "description": "The person who uploaded a file can always read it back.",
        "enabled": True,
        "target": {"action": "read"},
        "rules": [{"rule_id": "permit-owner", "effect": "permit",
                   "condition": {"eq": ["subject.id", "$resource.owner"]}}],
    },
    {
        "policy_id": "direct-share",
        "title": "Direct shares",
        "description": "People a file was bound to with their device key (Tier 3) can read it, whatever their department.",
        "enabled": True,
        "target": {"action": "read"},
        "rules": [{"rule_id": "permit-recipient", "effect": "permit",
                   "condition": {"in": ["subject.id", "$resource.recipients"]}}],
    },
    {
        "policy_id": "department-clearance",
        "title": "Department and clearance",
        "description": "Staff can read records of their own department when their clearance meets the record's level.",
        "enabled": True,
        "target": {"action": "read"},
        "rules": [{"rule_id": "permit-dept-clearance", "effect": "permit",
                   "condition": {"and": [
                       {"eq": ["subject.department", "$resource.department"]},
                       {"gte": ["subject.clearance", "$resource.clearance_required"]},
                   ]}}],
    },
    {
        "policy_id": "business-hours",
        "title": "Business hours only",
        "description": "Deny reads outside 08:00–20:00 server time. Turn on to demonstrate environment attributes.",
        "enabled": False,
        "target": {"action": "read"},
        "rules": [{"rule_id": "deny-after-hours", "effect": "deny",
                   "condition": {"or": [
                       {"lt": ["environment.local_hour", 8]},
                       {"gte": ["environment.local_hour", 20]},
                   ]}}],
    },
]

DOCUMENTS = [
    {
        "owner": "alice", "filename": "ECG summary - patient 4471.txt", "department": "Cardiology",
        "clearance_required": 2, "policy": "cardiology and level2", "mime_type": "text/plain",
        "body": (
            "12-LEAD ECG SUMMARY\nPatient ID: 4471 (synthetic)\nRecorded: 14 Oct, 09:12\n\n"
            "Rhythm: sinus rhythm, 78 bpm\nPR 168 ms · QRS 92 ms · QTc 431 ms\n"
            "Axis: normal\nST segments: 1 mm depression in V4–V6\n\n"
            "Impression: possible lateral ischaemia. Recommend troponin series and stress echo.\n"
            "Reviewed by: Dr. A. Mehra\n"
        ),
    },
    {
        "owner": "alice", "filename": "Catheterisation notes - bed 12.md", "department": "Cardiology",
        "clearance_required": 3, "policy": "cardiology and doctor and level3", "mime_type": "text/markdown",
        "body": (
            "# Cardiac catheterisation — bed 12 (synthetic)\n\n"
            "**Access:** right radial, 6F sheath\n\n"
            "**Findings**\n- LAD: 80% proximal stenosis\n- LCx: minor irregularities\n- RCA: dominant, no significant disease\n\n"
            "**Intervention:** drug-eluting stent to proximal LAD, TIMI 3 flow restored.\n\n"
            "**Plan:** dual antiplatelet therapy for 12 months; review in clinic in 6 weeks.\n"
        ),
    },
    {
        "owner": "alice", "filename": "Ward lab results - week 42.csv", "department": "Cardiology",
        "clearance_required": 1, "policy": "cardiology and level1", "mime_type": "text/csv",
        "body": (
            "patient,troponin_ng_l,bnp_pg_ml,potassium_mmol_l,creatinine_umol_l\n"
            "4471,38,410,4.1,92\n4472,6,85,3.9,77\n4475,112,1290,5.2,141\n4480,4,40,4.4,68\n"
        ),
    },
    {
        "owner": "carol", "filename": "Tumour board minutes - October.txt", "department": "Oncology",
        "clearance_required": 3, "policy": "oncology and level3", "mime_type": "text/plain",
        "body": (
            "MULTIDISCIPLINARY TUMOUR BOARD — OCTOBER (synthetic)\n\n"
            "Case 1: 58F, stage IIB breast carcinoma, HER2+. Plan: neoadjuvant chemotherapy, then surgery.\n"
            "Case 2: 66M, NSCLC stage IIIA. Plan: concurrent chemoradiation; re-image at 12 weeks.\n"
            "Case 3: 49M, colorectal liver metastases. Plan: refer for hepatobiliary surgical opinion.\n\n"
            "Chair: Dr. C. Iyer\n"
        ),
    },
    {
        "owner": "dana", "filename": "Incident response runbook.txt", "department": "Security",
        "clearance_required": 4, "policy": "admin and level4", "mime_type": "text/plain",
        "body": (
            "INCIDENT RESPONSE RUNBOOK\n\n"
            "1. Suspend the affected account in the revocation console (takes effect on the next request).\n"
            "2. Revoke the compromised attribute; versions bump and affected files queue for lazy re-wrap.\n"
            "3. Verify the audit chain and export it for the incident record.\n"
            "4. Rotate the device key of any user whose laptop was lost.\n"
        ),
    },
]


def seed(reset: bool = False) -> None:
    """
    Creates the demo hospital. With reset=False it only fills in what is missing,
    so it is safe to call on every server start.
    """
    from server.metadata import mongo
    from server import app as server_app
    from server.abac import pap
    from server.audit import audit_log
    from server.revocation import versioning
    from werkzeug.security import generate_password_hash

    if reset:
        for f in mongo.files_col.find({}, {"_id": 0}):
            server_app.storage.delete(f["file_id"])
        for col in (mongo.files_col, mongo.users_col, mongo.policies_col, mongo.versions_col, mongo.audit_col):
            col.delete_many({})
        audit_log.append("system", "demo_reset", None, "info", "Demo hospital restored")

    for policy in DEFAULT_POLICIES:
        if reset or not pap.get_policy(policy["policy_id"]):
            pap.add_policy(dict(policy))

    signing_keys = {}
    for person in STAFF:
        if mongo.users_col.find_one({"username": person["username"]}):
            continue
        # The seed key only signs the sample records. It is not bound as the person's
        # device key (its private half is discarded), so nobody can bind files to it;
        # each person's real device key is created in their browser at first sign-in.
        priv, _pub = rsa_wrap.generate_key_pair()
        signing_keys[person["username"]] = priv
        mongo.users_col.insert_one({
            "username": person["username"],
            "display_name": person["display_name"],
            "password": generate_password_hash(DEMO_PASSWORD),
            "attributes": {k: person[k] for k in ("role", "department", "clearance")},
            "active": True,
            "pub_key_pem": None,
        })

    if mongo.files_col.count_documents({}) > 0 and not reset:
        return

    pk, _ = server_app.get_abe_keys()
    now = datetime.datetime.now(datetime.timezone.utc)
    for i, doc in enumerate(DOCUMENTS):
        priv = signing_keys.get(doc["owner"]) or rsa_wrap.generate_key_pair()[0]
        body = doc["body"].encode("utf-8")
        compiled = versioning.compile_policy(doc["policy"])
        envelope = uploader.prepare_envelope(body, compiled, pk, sender_priv_key=priv)
        file_id = os.urandom(8).hex()
        import base64
        server_app.storage.put(file_id, base64.b64decode(envelope["ciphertext"]))
        mongo.files_col.insert_one({
            "file_id": file_id,
            "filename": doc["filename"],
            "owner": doc["owner"],
            "department": doc["department"],
            "clearance_required": doc["clearance_required"],
            "policy": compiled,
            "policy_display": doc["policy"],
            "checksum": envelope["checksum"],
            "nonce": envelope["nonce"],
            "tag": envelope["tag"],
            "wrapped_dek_abe": envelope["wrapped_dek_abe"],
            "wrapped_dek_rsa": None,
            "wrapped_dek_rsa_map": {},
            "signature": envelope["signature"],
            "signer_pub_key_pem": rsa_wrap.serialize_public_key(priv.public_key()).decode(),
            "size_bytes": len(base64.b64decode(envelope["ciphertext"])),
            "plain_size": len(body),
            "mime_type": doc["mime_type"],
            "uploaded_at": (now - datetime.timedelta(hours=26 - i * 5)).isoformat(timespec="seconds"),
            "stale": False,
            "rewrap_count": 0,
        })
        audit_log.append(doc["owner"], "upload", file_id, "info", f"{doc['filename']} · policy: {doc['policy']}")


def walkthrough() -> None:
    """Console demo: encrypt a record, read it as an authorised and an unauthorised user."""
    pk, msk = cpabe.setup()
    record = b"Patient 4471: troponin 38 ng/L, ECG shows lateral ST depression."
    priv, pub = rsa_wrap.generate_key_pair()
    env = uploader.prepare_envelope(record, "cardiology_v1 and level2_v1", pk, sender_priv_key=priv)
    print("Ciphertext (first 48 bytes):", env["ciphertext"][:64], "...")

    alice = cpabe.keygen(pk, msk, ["doctor_v1", "cardiology_v1", "level1_v1", "level2_v1", "level3_v1"])
    tk, dk = cpabe.generate_transform_key(pk, alice)
    ct_prime = cpabe.transform(pk, tk, env["wrapped_dek_abe"])
    plain = downloader.decrypt_envelope(env, pk, sender_pub_key=pub, ct_prime=ct_prime, dk=dk)
    print("Alice (Cardiology, L3) reads:", plain.decode())

    carol = cpabe.keygen(pk, msk, ["doctor_v1", "oncology_v1", "level1_v1", "level2_v1", "level3_v1"])
    try:
        downloader.decrypt_envelope(env, pk, abe_sk=carol)
    except PermissionError:
        print("Carol (Oncology, L3) is refused by CP-ABE — even with the raw ciphertext in hand.")


if __name__ == "__main__":
    walkthrough()
