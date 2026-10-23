"""
Attribute Versioning & Lazy Re-Wrap Module
Implements Specification Section: §6.4 (Revocation), §9 (Phase 4)
Implements Objectives: O4 (Efficient revocation), O7 (Publishable contribution)

How revocation works in this system
-----------------------------------
Every CP-ABE attribute carries a version, e.g. `cardiology_v1`. Policies written
by people ("cardiology and level3") are *compiled* against the current versions
before the DEK is wrapped ("cardiology_v1 and level3_v1").

When an attribute is revoked from a user:
1. ABAC layer (instant): the user's attribute is removed from the directory, so
   the PIP/PDP deny the very next request.
2. CP-ABE layer (cryptographic, lazy): the attribute's version is bumped to v2.
   Every file whose compiled policy mentions `cardiology_v1` is flagged `stale`.
   Non-revoked holders receive keys containing both v1 and v2 (their history);
   the revoked user's old key only ever had v1.
3. On the next legitimate access, the client re-wraps the *32-byte DEK* under
   the recompiled policy (v2) and uploads only the new wrapped key. The file
   ciphertext is never touched. After that, the revoked key is cryptographically
   useless against this file even if the ABAC layer were bypassed.

Re-wrap cost is O(32 bytes) per file instead of O(file size) — see
evaluation/revocation_cost_model.py.
"""

import re
from server.metadata import mongo

TOKEN_RE = re.compile(r"[a-zA-Z0-9_\-:]+|\(|\)")
OPERATORS = {"and", "or"}


def slug(value) -> str:
    """Normalises a human attribute value ("Cardiology", "Nurse Practitioner") to a token."""
    return re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")


def get_versions() -> dict[str, int]:
    """Returns {attribute: current_version}. Attributes never revoked are at version 1."""
    return {d["attribute"]: int(d["version"]) for d in mongo.versions_col.find({}, {"_id": 0})}


def current_version(attribute: str) -> int:
    return get_versions().get(slug(attribute), 1)


def subject_tokens(attributes: dict) -> list[str]:
    """
    Expands a user's directory attributes into plain CP-ABE attribute tokens.

    Clearance is expressed as a ladder: clearance 3 yields level1, level2 and
    level3, so a policy requiring "level2" is satisfied by anyone at 2 or above.
    """
    tokens = [slug(attributes.get("role", "user")), slug(attributes.get("department", "default"))]
    clearance = int(attributes.get("clearance", 1))
    tokens += [f"level{i}" for i in range(1, clearance + 1)]
    return tokens


def key_attributes(username: str, attributes: dict) -> list[str]:
    """
    Builds the full attribute list placed in a user's CP-ABE secret key: each
    plain token plus every version of it the user has legitimately held.
    """
    versions = get_versions()
    revoked = _revoked_pairs(username)

    out = []
    for token in subject_tokens(attributes):
        out.append(token)  # legacy/unversioned token (kept for backwards compatibility)
        for v in range(1, versions.get(token, 1) + 1):
            # SECURITY: never re-issue a version that was retired *because of* this user.
            if (token, v) in revoked:
                continue
            out.append(f"{token}_v{v}")
    return out


def _revoked_pairs(username: str) -> set[tuple[str, int]]:
    pairs = set()
    for doc in mongo.versions_col.find({}, {"_id": 0}):
        for rev in doc.get("revocations", []):
            if rev.get("username") == username:
                # The user loses every version up to and including the one retired.
                for v in range(1, int(rev["retired_version"]) + 1):
                    pairs.add((doc["attribute"], v))
    return pairs


def compile_policy(policy: str, versions: dict[str, int] = None) -> str:
    """
    Rewrites a human policy into a versioned policy.

    "(cardiology and level3) or admin"  ->  "(cardiology_v2 and level3_v1) or admin_v1"
    """
    versions = versions if versions is not None else get_versions()
    out = []
    for tok in TOKEN_RE.findall(policy):
        low = tok.lower()
        if tok in ("(", ")") or low in OPERATORS:
            out.append(low)
        else:
            base = re.sub(r"_v\d+$", "", slug(tok))
            out.append(f"{base}_v{versions.get(base, 1)}")
    return " ".join(out).replace("( ", "(").replace(" )", ")")


def policy_attributes(policy: str) -> set[str]:
    """Returns the base attribute names referenced by a (human or compiled) policy."""
    return {
        re.sub(r"_v\d+$", "", slug(t))
        for t in TOKEN_RE.findall(policy)
        if t not in ("(", ")") and t.lower() not in OPERATORS
    }


def revoke_attribute(username: str, attribute_field: str, new_value=None) -> dict:
    """
    Revokes one directory attribute from a user (ABAC: instant; CP-ABE: lazy).

    Args:
        username: The user losing the attribute.
        attribute_field: "role", "department" or "clearance".
        new_value: Replacement value (e.g. new department, or lower clearance).

    Returns:
        dict describing what changed, for the UI and audit log.
    """
    user = mongo.users_col.find_one({"username": username})
    if not user:
        raise KeyError(f"Unknown user '{username}'")

    attrs = dict(user["attributes"])
    old_tokens = set(subject_tokens(attrs))
    if attribute_field == "clearance":
        attrs["clearance"] = int(new_value if new_value is not None else 1)
    else:
        attrs[attribute_field] = new_value if new_value not in (None, "") else "none"
    lost = sorted(old_tokens - set(subject_tokens(attrs)))

    # 1. ABAC layer — takes effect on the very next request.
    mongo.users_col.update_one({"username": username}, {"$set": {"attributes": attrs}})

    # 2. CP-ABE layer — bump versions of every token the user lost.
    versions = get_versions()
    bumped = {}
    for token in lost:
        old_v = versions.get(token, 1)
        new_v = old_v + 1
        doc = mongo.versions_col.find_one({"attribute": token}, {"_id": 0}) or {"attribute": token, "revocations": []}
        doc["version"] = new_v
        doc.setdefault("revocations", []).append({"username": username, "retired_version": old_v})
        mongo.versions_col.replace_one({"attribute": token}, doc, upsert=True)
        bumped[token] = new_v

    stale = mark_stale_files(set(bumped))
    return {"username": username, "attributes": attrs, "lost_tokens": lost, "bumped": bumped, "stale_files": stale}


def disable_user(username: str, active: bool) -> None:
    """Suspends or reinstates a user at the ABAC layer (instant)."""
    mongo.users_col.update_one({"username": username}, {"$set": {"active": bool(active)}})


def mark_stale_files(bumped_tokens: set[str]) -> list[str]:
    """Flags files whose wrapped DEK references an outdated attribute version."""
    if not bumped_tokens:
        return []
    stale = []
    for f in mongo.files_col.find({}, {"_id": 0}):
        if policy_attributes(f.get("policy", "")) & bumped_tokens:
            mongo.files_col.update_one({"file_id": f["file_id"]}, {"$set": {"stale": True}})
            stale.append(f["file_id"])
    return stale


def is_stale(file_record: dict) -> bool:
    """True if the file's compiled policy is behind the current attribute versions."""
    display = file_record.get("policy_display") or file_record.get("policy", "")
    return compile_policy(display) != file_record.get("policy") and "_v" in file_record.get("policy", "")
