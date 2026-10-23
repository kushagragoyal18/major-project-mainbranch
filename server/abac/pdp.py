"""
Policy Decision Point (PDP) Module
Implements Specification Section: §6.1 (Components), §8 (Repo Structure)
Implements Objectives: O3 (Context-aware enforcement)

This module implements the core decision engine for ABAC. It takes the resolved
attribute dictionary and evaluates it against active policies stored in MongoDB.
It applies:
1. Deny-Override strategy (if any rule explicitly denies, access is denied).
2. Deny-by-Default strategy (if no policy explicitly allows, access is denied).
3. Complex boolean condition evaluation (and, or, not, comparisons).
"""

from server.abac import pap


def _resolve_path(path: str, attributes: dict):
    """
    Helper to resolve dotted attribute paths (e.g., 'subject.role' or 'resource.clearance_required')
    inside the nested attributes dictionary.
    """
    parts = path.split('.')
    current = attributes
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def evaluate_condition(condition: dict, attributes: dict) -> bool:
    """
    Recursively evaluates a JSON-based condition tree against a resolved attribute dictionary.
    
    Supported operators:
        - "and": list of conditions (all must be True)
        - "or": list of conditions (at least one must be True)
        - "not": nested condition (must be False)
        - Comparison operators: "eq", "neq", "gt", "gte", "lt", "lte"
        - Membership: "in" (target is a list, usually a "$resource.…" reference)
          Format: { "eq": ["path.to.attr", expected_value] }
    """
    if not isinstance(condition, dict) or not condition:
        return True  # Empty conditions default to True (satisfied)

    op = list(condition.keys())[0].lower()
    val = condition[op]

    if op == "and":
        if not isinstance(val, list):
            return False
        return all(evaluate_condition(cond, attributes) for cond in val)

    elif op == "or":
        if not isinstance(val, list):
            return False
        return any(evaluate_condition(cond, attributes) for cond in val)

    elif op == "not":
        return not evaluate_condition(val, attributes)

    # Comparison operators: expect a list [attribute_path, target_val]
    if not isinstance(val, list) or len(val) != 2:
        return False

    attr_path, target_val = val
    actual_val = _resolve_path(attr_path, attributes)

    # A target written as "$resource.department" is a reference to another
    # attribute, which lets a rule compare subject and resource directly
    # (e.g. "subject.department must equal resource.department").
    if isinstance(target_val, str) and target_val.startswith("$"):
        target_val = _resolve_path(target_val[1:], attributes)
        if target_val is None:
            return False

    # If attribute is missing, evaluate as False
    if actual_val is None:
        return False

    # Membership: {"in": ["subject.id", "$resource.recipients"]}
    if op == "in":
        return isinstance(target_val, (list, tuple, set)) and             str(actual_val).lower() in {str(v).lower() for v in target_val}

    if op == "eq":
        return str(actual_val).lower() == str(target_val).lower()
    elif op == "neq":
        return str(actual_val).lower() != str(target_val).lower()
    
    # Mathematical comparisons: convert both to float
    try:
        f_actual = float(actual_val)
        f_target = float(target_val)
    except (ValueError, TypeError):
        return False  # Non-numeric values fail comparison

    if op == "gt":
        return f_actual > f_target
    elif op == "gte":
        return f_actual >= f_target
    elif op == "lt":
        return f_actual < f_target
    elif op == "lte":
        return f_actual <= f_target

    return False


def is_target_applicable(target: dict, attributes: dict) -> bool:
    """
    Checks if a policy target matches the request attributes.
    Target evaluates matching action and resource details.
    """
    if not target:
        return True  # Empty target matches all requests

    # 1. Action check
    if "action" in target:
        requested_action = attributes.get("action", {}).get("name")
        target_action = target["action"]
        if requested_action and str(requested_action).lower() != str(target_action).lower():
            return False

    # 2. Resource check
    if "resource" in target:
        resource_target = target["resource"]
        resource_actual = attributes.get("resource", {})
        for key, val in resource_target.items():
            actual_val = resource_actual.get(key)
            if actual_val is None or str(actual_val).lower() != str(val).lower():
                return False

    return True


def explain(attributes: dict) -> dict:
    """
    Same algorithm as evaluate(), but also reports which policy/rule decided.
    Used by the UI to show *why* a request is permitted or denied.
    """
    matched = []
    decision = None
    for policy in pap.get_all_policies():
        if policy.get("enabled") is False or not is_target_applicable(policy.get("target", {}), attributes):
            continue
        for rule in policy.get("rules", []):
            if evaluate_condition(rule.get("condition", {}), attributes):
                effect = rule.get("effect", "deny").lower()
                matched.append({"policy_id": policy["policy_id"], "rule_id": rule.get("rule_id"), "effect": effect})
                if effect == "deny":
                    decision = "Deny"
    if decision is None:
        decision = "Permit" if any(m["effect"] == "permit" for m in matched) else "Deny"
    return {"decision": decision, "matched": matched}


def evaluate(attributes: dict) -> str:
    """
    Evaluates resolved attributes against all active policies.
    
    Args:
        attributes (dict): Resolved attributes from PIP.
        
    Returns:
        str: "Permit" or "Deny".
    """
    policies = pap.get_all_policies()
    
    # SECURITY: Deny-by-Default. If no policies are loaded or apply, access is denied.
    if not policies:
        return "Deny"

    permit_triggered = False
    deny_triggered = False

    for policy in policies:
        # Policies can be switched off from the PAP without being deleted.
        if policy.get("enabled") is False:
            continue
        target = policy.get("target", {})
        
        # Check if policy applies to this request target
        if not is_target_applicable(target, attributes):
            continue

        # Evaluate rules within the applicable policy
        rules = policy.get("rules", [])
        for rule in rules:
            effect = rule.get("effect", "deny").lower()
            condition = rule.get("condition", {})
            
            # Evaluate rule condition
            if evaluate_condition(condition, attributes):
                if effect == "deny":
                    # SECURITY: Deny-Override.
                    # If any applicable policy rule triggers a Deny, immediate abort.
                    deny_triggered = True
                    break
                elif effect == "permit":
                    permit_triggered = True
                    
        if deny_triggered:
            break

    if deny_triggered:
        return "Deny"
    elif permit_triggered:
        return "Permit"

    # Default fallback
    return "Deny"
