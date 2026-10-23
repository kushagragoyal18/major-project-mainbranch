"""
Revocation, lazy re-wrap and audit-chain tests.
Implements Specification Section: §6.4, §9 (Phase 4), §10
Implements Objectives: O4 (Efficient revocation), O5 (Tamper-evident audit)

Runs against the local JSON metadata backend configured in conftest.py.
"""

import pytest
from client import uploader, downloader
from client.crypto import cpabe, rsa_wrap
from server.metadata import mongo
from server.revocation import versioning
from server.audit import audit_log
from server.abac import pdp


@pytest.fixture(autouse=True)
def clean_store():
    for col in (mongo.users_col, mongo.files_col, mongo.versions_col, mongo.audit_col, mongo.policies_col):
        col.delete_many({})
    yield


def _user(username, role, dept, clearance):
    mongo.users_col.insert_one({"username": username, "password": "x", "active": True,
                                "attributes": {"role": role, "department": dept, "clearance": clearance}})


def test_compile_policy_uses_current_versions():
    assert versioning.compile_policy("(Cardiology and level3) or admin") == \
        "(cardiology_v1 and level3_v1) or admin_v1"
    mongo.versions_col.insert_one({"attribute": "cardiology", "version": 2, "revocations": []})
    assert versioning.compile_policy("cardiology and level3") == "cardiology_v2 and level3_v1"


def test_clearance_is_a_ladder():
    tokens = versioning.subject_tokens({"role": "Nurse", "department": "Cardiology", "clearance": 3})
    assert {"level1", "level2", "level3"} <= set(tokens)
    assert "level4" not in tokens


def test_revocation_bumps_version_and_marks_files_stale():
    _user("alice", "Doctor", "Cardiology", 3)
    _user("bob", "Nurse", "Cardiology", 2)
    mongo.files_col.insert_one({"file_id": "f1", "policy": "cardiology_v1 and level2_v1",
                                "policy_display": "cardiology and level2"})
    mongo.files_col.insert_one({"file_id": "f2", "policy": "oncology_v1 and level1_v1",
                                "policy_display": "oncology and level1"})

    result = versioning.revoke_attribute("bob", "department", "Oncology")

    assert result["bumped"] == {"cardiology": 2}
    assert result["stale_files"] == ["f1"]
    assert mongo.files_col.find_one({"file_id": "f1"})["stale"] is True
    # ABAC directory updated instantly
    assert mongo.users_col.find_one({"username": "bob"})["attributes"]["department"] == "Oncology"
    # Bob never receives the retired cardiology_v1 again, even if re-granted the
    # department later (he would only get v2). Alice keeps v1 and gains v2.
    bob_regranted = versioning.key_attributes("bob", {"role": "Nurse", "department": "Cardiology", "clearance": 2})
    assert "cardiology_v1" not in bob_regranted and "cardiology_v2" in bob_regranted
    alice_attrs = versioning.key_attributes("alice", {"role": "Doctor", "department": "Cardiology", "clearance": 3})
    assert {"cardiology_v1", "cardiology_v2"} <= set(alice_attrs)


def test_lazy_rewrap_locks_out_old_key_without_touching_ciphertext():
    pk, msk = cpabe.setup()
    record = b"synthetic ECG report"
    env = uploader.prepare_envelope(record, "cardiology_v1 and level2_v1", pk)
    bob_old_key = cpabe.keygen(pk, msk, ["nurse_v1", "cardiology_v1", "level1_v1", "level2_v1"])
    alice_key = cpabe.keygen(pk, msk, ["doctor_v1", "cardiology_v1", "cardiology_v2", "level1_v1", "level2_v1"])

    # Before re-wrap Bob's stale key still opens the CP-ABE layer (ABAC is what stops him).
    assert downloader.decrypt_envelope(env, pk, abe_sk=bob_old_key) == record

    # Alice reads, recovers the DEK and re-wraps only the 32-byte key under v2.
    dek = cpabe.decrypt(pk, alice_key, env["wrapped_dek_abe"])
    assert len(dek) == 32
    ciphertext_before = env["ciphertext"]
    env["wrapped_dek_abe"] = cpabe.encrypt(pk, dek, "cardiology_v2 and level2_v1")

    assert env["ciphertext"] == ciphertext_before
    assert downloader.decrypt_envelope(env, pk, abe_sk=alice_key) == record
    with pytest.raises(PermissionError):
        downloader.decrypt_envelope(env, pk, abe_sk=bob_old_key)


def test_suspended_user_is_denied_by_pdp():
    from usecase.healthcare_demo import DEFAULT_POLICIES
    from server.abac import pap
    for p in DEFAULT_POLICIES:
        pap.add_policy(dict(p))
    attrs = {"subject": {"id": "alice", "role": "Doctor", "department": "Cardiology", "clearance": 3, "status": "active"},
             "resource": {"owner": "carol", "department": "Cardiology", "clearance_required": 2},
             "action": {"name": "read"}, "environment": {"hour": 10, "local_hour": 10}}
    assert pdp.evaluate(attrs) == "Permit"
    attrs["subject"]["status"] = "suspended"
    assert pdp.evaluate(attrs) == "Deny"
    # Attribute references: a different department is denied.
    attrs["subject"]["status"] = "active"
    attrs["resource"]["department"] = "Oncology"
    assert pdp.evaluate(attrs) == "Deny"


def test_audit_chain_detects_tampering():
    for i in range(5):
        audit_log.append("alice", "download", f"f{i}", "permit", "")
    assert audit_log.verify_chain()["valid"] is True

    entry = mongo.audit_col.find_one({"seq": 3})
    entry["decision"] = "deny"
    mongo.audit_col.replace_one({"seq": 3}, entry)

    result = audit_log.verify_chain()
    assert result["valid"] is False
    assert result["broken_at"] == 3


def test_direct_share_permits_recipient_only():
    from usecase.healthcare_demo import DEFAULT_POLICIES
    from server.abac import pap
    for p in DEFAULT_POLICIES:
        pap.add_policy(dict(p))
    base = {"resource": {"owner": "bob", "department": "Oncology", "clearance_required": 2, "recipients": ["alice"]},
            "action": {"name": "read"}, "environment": {"hour": 10, "local_hour": 10}}
    alice = {"id": "alice", "role": "Doctor", "department": "Cardiology", "clearance": 3, "status": "active"}
    eve = {"id": "eve", "role": "Doctor", "department": "Cardiology", "clearance": 3, "status": "active"}
    assert pdp.evaluate({**base, "subject": alice}) == "Permit"
    assert pdp.evaluate({**base, "subject": eve}) == "Deny"
