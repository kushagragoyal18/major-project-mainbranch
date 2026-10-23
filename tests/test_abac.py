import pytest
import os
import datetime
import json
import base64
import jwt
from flask import Flask
from server import app as flask_app
from server.auth import jwt_helper
from server.abac import pap, pip, pdp
from server.storage.local_store import LocalStore
from client.crypto import cpabe


# -----------------------------------------------------------------------------
# In-Memory MongoDB Mock Collection
# -----------------------------------------------------------------------------
class MockCollection:
    """In-memory mock for PyMongo collection objects to isolate tests from running DBs."""
    def __init__(self):
        self.store = {}

    def find_one(self, filter_dict, projection=None):
        key = list(filter_dict.keys())[0]
        val = filter_dict[key]
        for doc in self.store.values():
            if doc.get(key) == val:
                ret = doc.copy()
                if projection and "_id" in projection and projection["_id"] == 0:
                    ret.pop("_id", None)
                return ret
        return None

    def insert_one(self, doc):
        doc_id = doc.get("username") or doc.get("file_id") or doc.get("policy_id") or os.urandom(8).hex()
        doc = doc.copy()
        doc["_id"] = doc_id
        self.store[doc_id] = doc
        
        class InsertResult:
            acknowledged = True
            inserted_id = doc_id
        return InsertResult()

    def replace_one(self, filter_dict, replacement, upsert=False):
        key = list(filter_dict.keys())[0]
        val = filter_dict[key]
        doc_id = replacement.get("policy_id") or replacement.get("file_id") or replacement.get("username") or val
        replacement = replacement.copy()
        replacement["_id"] = doc_id
        self.store[doc_id] = replacement
        
        class ReplaceResult:
            acknowledged = True
            matched_count = 1
            modified_count = 1
        return ReplaceResult()

    def delete_one(self, filter_dict):
        key = list(filter_dict.keys())[0]
        val = filter_dict[key]
        to_delete = None
        for k, v in self.store.items():
            if v.get(key) == val:
                to_delete = k
                break
        if to_delete:
            del self.store[to_delete]
            deleted = 1
        else:
            deleted = 0
            
        class DeleteResult:
            deleted_count = deleted
        return DeleteResult()

    def delete_many(self, filter_dict):
        self.store.clear()

    def find(self, filter_dict, projection=None):
        return list(self.store.values())


@pytest.fixture(autouse=True)
def mock_db(monkeypatch):
    """Fixture replacing PyMongo database collections with in-memory MockCollections."""
    mock_users = MockCollection()
    mock_files = MockCollection()
    mock_policies = MockCollection()
    
    # Patch mongo collection variables in different modules
    monkeypatch.setattr("server.abac.pap.policies_col", mock_policies)
    monkeypatch.setattr("server.abac.pip.users_col", mock_users)
    monkeypatch.setattr("server.abac.pip.files_col", mock_files)
    
    monkeypatch.setattr("server.metadata.mongo.users_col", mock_users)
    monkeypatch.setattr("server.metadata.mongo.files_col", mock_files)
    monkeypatch.setattr("server.metadata.mongo.policies_col", mock_policies)
    monkeypatch.setattr("server.app.users_col", mock_users)
    monkeypatch.setattr("server.app.files_col", mock_files)
    monkeypatch.setattr("server.app.abe_params_col", MockCollection())
    
    return {
        "users": mock_users,
        "files": mock_files,
        "policies": mock_policies
    }


# -----------------------------------------------------------------------------
# 1. JWT Authentication Helper Tests
# -----------------------------------------------------------------------------
def test_jwt_generation_and_decoding():
    """Verify that JWT helper correctly signs and verifies user attributes."""
    username = "dr_alice"
    attrs = {"role": "Doctor", "department": "Cardiology", "clearance": 3}
    
    # Generate token
    token = jwt_helper.generate_token(username, attrs)
    assert isinstance(token, str)
    
    # Decode token
    claims = jwt_helper.decode_token(token)
    assert claims["sub"] == username
    assert claims["attributes"]["role"] == "Doctor"
    assert claims["attributes"]["clearance"] == 3

    # Verify invalid signature throws InvalidTokenError
    with pytest.raises(jwt.InvalidTokenError):
        jwt_helper.decode_token(token, secret="wrong_secret_key")


# -----------------------------------------------------------------------------
# 2. Local Storage Provider Tests
# -----------------------------------------------------------------------------
def test_local_storage_provider(tmp_path):
    """Verify ObjectStore filesystem provider read, write, and delete operations."""
    store = LocalStore(base_dir=str(tmp_path))
    file_id = "test-doc-123"
    payload = b"enc_ciphertext_blob_bytes"
    
    # Save file
    assert store.put(file_id, payload) is True
    
    # Read file
    data = store.get(file_id)
    assert data == payload
    
    # Verify missing file raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        store.get("missing-key")
        
    # Delete file
    assert store.delete(file_id) is True
    assert store.delete(file_id) is False  # Second delete returns False


# -----------------------------------------------------------------------------
# 3. PDP ABAC Engine Evaluations
# -----------------------------------------------------------------------------
def test_pdp_abac_gating(mock_db):
    """Verify PDP correctly reasons over clearance tiers and time-of-day policies."""
    # Define a sample policy:
    # Only Cardiologists with clearance >= 3 can read Cardiology records during business hours (9-17)
    cardio_policy = {
        "policy_id": "cardio_read_policy",
        "target": {
            "action": "read",
            "resource": {
                "department": "Cardiology"
            }
        },
        "rules": [
            {
                "rule_id": "cardio_rule",
                "effect": "permit",
                "condition": {
                    "and": [
                        {"eq": ["subject.role", "Doctor"]},
                        {"eq": ["subject.department", "Cardiology"]},
                        {"gte": ["subject.clearance", 3]},
                        {"gte": ["environment.hour", 9]},
                        {"lte": ["environment.hour", 17]}
                    ]
                }
            }
        ]
    }
    
    pap.add_policy(cardio_policy)
    
    # Case 1: Permitted User accessing inside business hours
    attrs_permit = {
        "subject": {"role": "Doctor", "department": "Cardiology", "clearance": 3},
        "resource": {"department": "Cardiology", "clearance_required": 3},
        "action": {"name": "read"},
        "environment": {"hour": 14, "ip": "127.0.0.1"}
    }
    assert pdp.evaluate(attrs_permit) == "Permit"

    # Case 2: Wrong clearance (Denied)
    attrs_low_clearance = {
        "subject": {"role": "Doctor", "department": "Cardiology", "clearance": 2},
        "resource": {"department": "Cardiology", "clearance_required": 3},
        "action": {"name": "read"},
        "environment": {"hour": 14, "ip": "127.0.0.1"}
    }
    assert pdp.evaluate(attrs_low_clearance) == "Deny"

    # Case 3: Outside business hours (Denied)
    attrs_after_hours = {
        "subject": {"role": "Doctor", "department": "Cardiology", "clearance": 3},
        "resource": {"department": "Cardiology", "clearance_required": 3},
        "action": {"name": "read"},
        "environment": {"hour": 20, "ip": "127.0.0.1"}
    }
    assert pdp.evaluate(attrs_after_hours) == "Deny"


# -----------------------------------------------------------------------------
# 4. Flask API Server Route Integration Tests
# -----------------------------------------------------------------------------
@pytest.fixture
def client(tmp_path, monkeypatch):
    """Flask client setup utilizing local temporary storage."""
    temp_store = LocalStore(base_dir=str(tmp_path))
    monkeypatch.setattr("server.app.storage", temp_store)
    
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as client:
        yield client


def test_flask_api_full_flow(client, mock_db):
    """Test full HTTP API flows: registration, login, policy creation, upload, gated download, transform."""
    # 1. Register Alice (Doctor, Cardiology, Clearance 3)
    reg_resp = client.post("/register", json={
        "username": "alice",
        "password": "password123",
        "role": "Doctor",
        "department": "Cardiology",
        "clearance": 3
    })
    assert reg_resp.status_code == 201

    # 2. Login
    login_resp = client.post("/login", json={
        "username": "alice",
        "password": "password123"
    })
    assert login_resp.status_code == 200
    login_data = login_resp.get_json()
    token = login_data["token"]
    abe_sk = login_data["abe_sk"]
    
    auth_headers = {"Authorization": f"Bearer {token}"}

    # 3. Add ABAC policy (allow Doctors with clearance >= 3 to read Cardiology)
    policy = {
        "policy_id": "cardio_read",
        "target": {"action": "read", "resource": {"department": "Cardiology"}},
        "rules": [{
            "effect": "permit",
            "condition": {
                "and": [
                    {"eq": ["subject.role", "Doctor"]},
                    {"gte": ["subject.clearance", 3]}
                ]
            }
        }]
    }
    # Policy administration (PAP) requires an administrator token.
    admin_token = jwt_helper.generate_token("root", {"role": "Admin", "department": "Security", "clearance": 5})
    pol_resp = client.post("/policies", json=policy, headers={"Authorization": f"Bearer {admin_token}"})
    assert pol_resp.status_code == 201

    # Fetch ABE parameters from server
    abe_params_resp = client.get("/abe-params")
    assert abe_params_resp.status_code == 200
    abe_pk = abe_params_resp.get_json()["pk"]

    # 4. Client-side Upload preparation
    file_bytes = b"Patient record contents..."
    from client import uploader
    envelope = uploader.prepare_envelope(
        file_bytes=file_bytes,
        policy_str="CARDIOLOGY and LEVEL3",
        abe_pk=abe_pk
    )

    # Upload to server
    upload_resp = client.post("/upload", headers=auth_headers, json={
        "file_id": "record-44",
        "filename": "alice_record.enc",
        "department": "Cardiology",
        "clearance_required": 3,
        "envelope": envelope
    })
    assert upload_resp.status_code == 201

    # 5. Download Gated check (Gated read allowed)
    download_resp = client.get("/download/record-44", headers=auth_headers)
    assert download_resp.status_code == 200
    download_data = download_resp.get_json()
    assert "envelope" in download_data
    
    # Decrypt standard
    from client import downloader
    dec_bytes = downloader.decrypt_envelope(
        envelope=download_data["envelope"],
        abe_pk=abe_pk,
        abe_sk=abe_sk
    )
    assert dec_bytes == file_bytes

    # 6. Transform pairings check
    # Generate transform key
    tk, dk = cpabe.generate_transform_key(abe_pk, abe_sk)
    
    transform_resp = client.post("/transform/record-44", headers=auth_headers, json={
        "tk": tk
    })
    assert transform_resp.status_code == 200
    ct_prime = transform_resp.get_json()["ct_prime"]
    
    # Decrypt transformed
    dec_bytes_trans = downloader.decrypt_envelope(
        envelope=download_data["envelope"],
        abe_pk=abe_pk,
        ct_prime=ct_prime,
        dk=dk
    )
    assert dec_bytes_trans == file_bytes

    # 7. Deny Unauthorized download attempts
    # Register Eve (Nurse, Oncology, Clearance 1)
    client.post("/register", json={
        "username": "eve",
        "password": "password456",
        "role": "Nurse",
        "department": "Oncology",
        "clearance": 1
    })
    eve_login = client.post("/login", json={"username": "eve", "password": "password456"}).get_json()
    eve_headers = {"Authorization": f"Bearer {eve_login['token']}"}

    # Eve attempts download (blocked by ABAC PDP)
    blocked_resp = client.get("/download/record-44", headers=eve_headers)
    assert blocked_resp.status_code == 403
    assert "Access Denied" in blocked_resp.get_json()["error"]
