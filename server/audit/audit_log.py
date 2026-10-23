"""
Tamper-Evident Audit Log Module
Implements Specification Section: §9 (Phase 4), §10 (Security Requirements)
Implements Objectives: O4 (Efficient revocation), O5 (Integrity & authenticity)

Every security-relevant event (login, upload, access decision, revocation, policy
change, lazy re-wrap) is appended to an audit trail. Entries are hash-chained:

    hash_n = SHA-256( prev_hash || canonical_json(entry_n without hash) )

Changing, deleting or reordering any past entry breaks every hash after it, so
`verify_chain()` can prove the log has not been edited after the fact.
"""

import json
import hashlib
import threading
import datetime
from server.metadata import mongo

GENESIS_HASH = "0" * 64
_lock = threading.Lock()


def _col():
    # Resolved at call time so tests can monkeypatch mongo.audit_col.
    return mongo.audit_col


def _entry_hash(prev_hash: str, body: dict) -> str:
    """Computes the chained SHA-256 over the canonical JSON of an entry."""
    # SECURITY: sort_keys + compact separators give a canonical byte encoding,
    # so the same entry always hashes to the same value.
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def append(actor: str, action: str, resource: str = None, decision: str = "info", detail: str = "") -> dict:
    """
    Appends one event to the hash-chained log.

    Args:
        actor (str): Username (or "system") performing the action.
        action (str): Short machine name, e.g. "download", "revoke_attribute".
        resource (str, optional): File ID, policy ID, or username affected.
        decision (str): "permit", "deny" or "info".
        detail (str): Human-readable context.

    Returns:
        dict: The stored entry including its chain hash.
    """
    with _lock:
        last = _col().find_one({}, {"_id": 0}, sort=[("seq", -1)])
        prev_hash = last["hash"] if last else GENESIS_HASH
        body = {
            "seq": (last["seq"] + 1) if last else 1,
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"),
            "actor": actor or "anonymous",
            "action": action,
            "resource": resource,
            "decision": decision,
            "detail": detail,
            "prev_hash": prev_hash,
        }
        body["hash"] = _entry_hash(prev_hash, body)
        _col().insert_one(dict(body))
        return body


def list_entries(limit: int = 200) -> list[dict]:
    """Returns the most recent entries, newest first."""
    return list(_col().find({}, {"_id": 0}, sort=[("seq", -1)], limit=limit))


def verify_chain() -> dict:
    """
    Recomputes every hash in order and reports the first broken link, if any.

    Returns:
        dict: {"valid": bool, "entries": int, "broken_at": seq | None}
    """
    entries = list(_col().find({}, {"_id": 0}, sort=[("seq", 1)]))
    prev_hash = GENESIS_HASH
    for entry in entries:
        body = {k: v for k, v in entry.items() if k != "hash"}
        if entry.get("prev_hash") != prev_hash or _entry_hash(prev_hash, body) != entry.get("hash"):
            return {"valid": False, "entries": len(entries), "broken_at": entry.get("seq")}
        prev_hash = entry["hash"]
    return {"valid": True, "entries": len(entries), "broken_at": None, "head": prev_hash}
