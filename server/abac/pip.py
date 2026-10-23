"""
Policy Information Point (PIP) Module
Implements Specification Section: §6.1 (Components), §8 (Repo Structure)
Implements Objectives: O3 (Context-aware enforcement)

This module resolves dynamic attributes for policy evaluations. It retrieves subject
attributes from the database user registry, resource attributes from the file metadata
catalog, and environmental properties (like current UTC time and client IP address).
"""

import datetime
from server.metadata.mongo import users_col, files_col


def resolve_attributes(
    subject_id: str,
    resource_id: str = None,
    action: str = None,
    client_ip: str = "127.0.0.1",
    jwt_claims_attrs: dict = None
) -> dict:
    """
    Assembles and resolves all subject, resource, action, and environment attributes
    needed for PDP evaluation.
    
    Args:
        subject_id (str): The unique user ID of the requesting subject.
        resource_id (str, optional): The file ID being accessed.
        action (str, optional): The action performed ('read', 'write', etc.).
        client_ip (str, optional): The requesting IP address.
        jwt_claims_attrs (dict, optional): Subject attributes parsed from JWT claims, used if DB is missing.
        
    Returns:
        dict: A dictionary containing resolved categories:
            - "subject": role, department, clearance.
            - "resource": owner, department, clearance_required, size.
            - "action": action name.
            - "environment": hour, day_of_week, ip.
    """
    # 1. Resolve Subject Attributes
    # SECURITY: Query user directory from DB to get the most up-to-date attributes.
    # If not registered yet, fall back to JWT claims if provided, or default values.
    subject_attrs = {"role": "User", "department": "Default", "clearance": 1}
    user_record = users_col.find_one({"username": subject_id})
    
    if user_record and "attributes" in user_record:
        subject_attrs = dict(user_record["attributes"])
        # SECURITY: "active" is flipped by the revocation console; a suspended
        # user is denied on their very next request (instant ABAC revocation).
        subject_attrs["status"] = "active" if user_record.get("active", True) else "suspended"
    elif jwt_claims_attrs:
        subject_attrs = dict(jwt_claims_attrs)
    subject_attrs["id"] = subject_id
        
    # Ensure clearance is integer
    subject_attrs["clearance"] = int(subject_attrs.get("clearance", 1))

    # 2. Resolve Resource/Object Attributes
    resource_attrs = {}
    if resource_id:
        file_record = files_col.find_one({"file_id": resource_id})
        if file_record:
            # SECURITY: Fetch file classification requirements.
            # Extract metadata such as owner, department block, and clearance level required.
            resource_attrs = {
                "owner": file_record.get("owner"),
                "department": file_record.get("department", "Default"),
                "clearance_required": int(file_record.get("clearance_required", 1)),
                "size_bytes": int(file_record.get("size_bytes", 0)),
                "file_id": resource_id,
                # People the owner explicitly bound the file to (Tier 3 device wrap).
                "recipients": sorted((file_record.get("wrapped_dek_rsa_map") or {}).keys()),
            }

    # 3. Resolve Environment Attributes
    # SECURITY: Construct time-of-day attributes in UTC.
    # Enforces time-window restrictions (e.g. business hours check).
    now = datetime.datetime.now(datetime.timezone.utc)
    env_attrs = {
        "hour": now.hour,
        # Local wall-clock hour of the server, so business-hours rules read naturally.
        "local_hour": datetime.datetime.now().hour,
        "day_of_week": now.strftime("%A"),  # e.g., 'Monday', 'Tuesday'
        "ip": client_ip
    }

    # 4. Resolve Action Attributes
    action_attrs = {"name": action if action else "read"}

    return {
        "subject": subject_attrs,
        "resource": resource_attrs,
        "action": action_attrs,
        "environment": env_attrs
    }
