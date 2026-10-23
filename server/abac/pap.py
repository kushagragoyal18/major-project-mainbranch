"""
Policy Administration Point (PAP) Module
Implements Specification Section: §6.1 (Components), §8 (Repo Structure)
Implements Objectives: O3 (Context-aware enforcement)

This module handles administrative actions on security policies. It implements CRUD
operations on policy templates stored in MongoDB, allowing security officers
to define or modify ABAC rules.
"""

from server.metadata.mongo import policies_col


def add_policy(policy: dict) -> bool:
    """
    Saves a new ABAC policy to MongoDB.
    
    Args:
        policy (dict): The JSON-based policy object. Must have a unique 'policy_id'.
        
    Returns:
        bool: True if insertion/replacement succeeded.
    """
    if "policy_id" not in policy:
        raise ValueError("Policy must contain a unique 'policy_id' field.")
        
    # Replace existing policy if policy_id matches, or insert a new one
    result = policies_col.replace_one(
        {"policy_id": policy["policy_id"]},
        policy,
        upsert=True
    )
    return result.acknowledged


def get_policy(policy_id: str) -> dict:
    """
    Retrieves a policy by ID.
    
    Args:
        policy_id (str): The unique policy identifier.
        
    Returns:
        dict: The policy record or None if not found.
    """
    # Exclude MongoDB default internal _id from returned output
    return policies_col.find_one({"policy_id": policy_id}, {"_id": 0})


def get_all_policies() -> list[dict]:
    """
    Lists all stored ABAC policies.
    
    Returns:
        list[dict]: List of policy objects.
    """
    return list(policies_col.find({}, {"_id": 0}))


def delete_policy(policy_id: str) -> bool:
    """
    Deletes a policy by ID.
    
    Args:
        policy_id (str): The policy ID to remove.
        
    Returns:
        bool: True if deletion succeeded and deleted count > 0.
    """
    result = policies_col.delete_one({"policy_id": policy_id})
    return result.deleted_count > 0


def clear_policies() -> None:
    """
    Clears all policies in the collection. Useful for test cleanup.
    """
    policies_col.delete_many({})
