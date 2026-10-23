"""
MongoDB Metadata Storage Module
Implements Specification Section: §6.1 (Components), §7 (Tech Stack), §8 (Repo Structure)
Implements Objectives: O3 (Context-aware enforcement), O4 (Efficient revocation)

This module handles connection orchestration to MongoDB using pymongo.
It exposes collections for managing:
1. User metadata (registered user accounts and public RSA/device certificates).
2. File metadata (file cryptographic envelopes, uploader info, and access policy records).
3. Access Control Policies (JSON-based ABAC rules for PDP evaluations).
4. Audit Trails (for security tracking and tamper evidence).
5. Attribute versions (for attribute-versioning revocation, §6.4).

Backend selection (env METADATA_BACKEND):
    - "mongo": always use MongoDB.
    - "local": use the JSON-file-backed collection below (no daemon needed).
    - "auto" (default): ping MongoDB once; fall back to "local" if it is unreachable.

# FALLBACK: The local backend exists so a live demo never fails because the
# MongoDB daemon is down. It implements only the subset of the PyMongo
# collection API that this project uses.
"""

import os
import json
import copy
import uuid
import threading
import logging

logger = logging.getLogger(__name__)

# Fetch MongoDB URI from environment variables (defaulting to localhost)
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/secure_storage")
METADATA_BACKEND = os.getenv("METADATA_BACKEND", "auto").lower()
LOCAL_METADATA_PATH = os.getenv(
    "LOCAL_METADATA_PATH",
    os.path.join(os.getenv("LOCAL_STORAGE_DIR", "./local_storage"), "_metadata.json"),
)


# -----------------------------------------------------------------------------
# Local JSON-file-backed fallback
# -----------------------------------------------------------------------------
def _matches(doc: dict, filter_dict: dict) -> bool:
    """Evaluates a (small) subset of MongoDB query syntax against one document."""
    for key, cond in (filter_dict or {}).items():
        actual = doc.get(key)
        if isinstance(cond, dict) and any(k.startswith("$") for k in cond):
            for op, val in cond.items():
                if op == "$in" and actual not in val:
                    return False
                if op == "$ne" and actual == val:
                    return False
                if op == "$exists" and (key in doc) != bool(val):
                    return False
                if op == "$regex" and (not isinstance(actual, str) or val not in actual):
                    return False
        elif actual != cond:
            return False
    return True


def _project(doc: dict, projection: dict | None) -> dict:
    ret = copy.deepcopy(doc)
    if projection and projection.get("_id") == 0:
        ret.pop("_id", None)
    return ret


class _Result:
    """Mimics the result objects returned by PyMongo write operations."""

    def __init__(self, **kw):
        self.acknowledged = True
        self.__dict__.update(kw)


class LocalDatabase:
    """Holds every local collection and persists them to a single JSON file."""

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self.lock = threading.RLock()
        self.data: dict[str, list] = {}
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
            except (OSError, ValueError):
                logger.warning("Local metadata file unreadable; starting empty.")
                self.data = {}

    def flush(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f)
        os.replace(tmp, self.path)

    def __getitem__(self, name: str) -> "LocalCollection":
        return LocalCollection(self, name)


class LocalCollection:
    """Subset of the PyMongo Collection API, backed by LocalDatabase."""

    def __init__(self, database: LocalDatabase, name: str):
        self.database = database
        self.name = name

    @property
    def _docs(self) -> list:
        return self.database.data.setdefault(self.name, [])

    def find_one(self, filter_dict=None, projection=None, sort=None):
        docs = self.find(filter_dict, projection, sort=sort)
        return docs[0] if docs else None

    def find(self, filter_dict=None, projection=None, sort=None, limit=0):
        with self.database.lock:
            docs = [_project(d, projection) for d in self._docs if _matches(d, filter_dict)]
        if sort:
            for key, direction in reversed(sort):
                docs.sort(key=lambda d: (d.get(key) is None, d.get(key)), reverse=direction < 0)
        return docs[:limit] if limit else docs

    def count_documents(self, filter_dict=None):
        return len(self.find(filter_dict))

    def insert_one(self, doc):
        with self.database.lock:
            doc.setdefault("_id", uuid.uuid4().hex)
            self._docs.append(copy.deepcopy(doc))
            self.database.flush()
        return _Result(inserted_id=doc["_id"])

    def replace_one(self, filter_dict, replacement, upsert=False):
        with self.database.lock:
            for i, d in enumerate(self._docs):
                if _matches(d, filter_dict):
                    new_doc = copy.deepcopy(replacement)
                    new_doc["_id"] = d.get("_id")
                    self._docs[i] = new_doc
                    self.database.flush()
                    return _Result(matched_count=1, modified_count=1)
            if upsert:
                self.insert_one(copy.deepcopy(replacement))
            return _Result(matched_count=0, modified_count=0)

    def update_one(self, filter_dict, update, upsert=False):
        with self.database.lock:
            for d in self._docs:
                if _matches(d, filter_dict):
                    d.update(copy.deepcopy(update.get("$set", {})))
                    for k, v in update.get("$inc", {}).items():
                        d[k] = d.get(k, 0) + v
                    self.database.flush()
                    return _Result(matched_count=1, modified_count=1)
            if upsert:
                doc = dict(filter_dict)
                doc.update(update.get("$set", {}))
                doc.update(update.get("$inc", {}))
                self.insert_one(doc)
            return _Result(matched_count=0, modified_count=0)

    def update_many(self, filter_dict, update):
        count = 0
        with self.database.lock:
            for d in self._docs:
                if _matches(d, filter_dict):
                    d.update(copy.deepcopy(update.get("$set", {})))
                    count += 1
            self.database.flush()
        return _Result(matched_count=count, modified_count=count)

    def delete_one(self, filter_dict):
        with self.database.lock:
            for i, d in enumerate(self._docs):
                if _matches(d, filter_dict):
                    del self._docs[i]
                    self.database.flush()
                    return _Result(deleted_count=1)
        return _Result(deleted_count=0)

    def delete_many(self, filter_dict):
        with self.database.lock:
            before = len(self._docs)
            self.database.data[self.name] = [d for d in self._docs if not _matches(d, filter_dict)]
            self.database.flush()
            return _Result(deleted_count=before - len(self._docs))


# -----------------------------------------------------------------------------
# Backend selection
# -----------------------------------------------------------------------------
client = None
BACKEND = "local"


def _connect_mongo():
    from pymongo import MongoClient
    # SECURITY: In production, this client should use TLS/SSL authentication and credentials.
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=1500)
    if METADATA_BACKEND == "auto":
        mongo_client.admin.command("ping")
    return mongo_client


if METADATA_BACKEND in ("auto", "mongo"):
    try:
        client = _connect_mongo()
        BACKEND = "mongo"
    except Exception as e:  # pragma: no cover - depends on host environment
        logger.warning(f"MongoDB unreachable ({e}); using local JSON metadata store.")

if BACKEND == "mongo":
    db = client.get_database("secure_storage")
else:
    db = LocalDatabase(LOCAL_METADATA_PATH)

# Expose collections
users_col = db["users"]
files_col = db["files"]
policies_col = db["policies"]
audit_col = db["audit_logs"]
versions_col = db["attribute_versions"]


def get_db():
    """
    Returns the active database instance (MongoDB or the local fallback).
    """
    return db


def check_connection() -> bool:
    """
    Checks if the metadata store is reachable.

    Returns:
        bool: True if connection is healthy, False otherwise.
    """
    if BACKEND == "local":
        return True
    try:
        # The ping command is cheap and checks database availability
        client.admin.command('ping')
        return True
    except Exception as e:
        logger.error(f"MongoDB connection check failed: {e}")
        return False
