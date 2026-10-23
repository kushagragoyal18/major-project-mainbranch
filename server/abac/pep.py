"""
Policy Enforcement Point (PEP) Module
Implements Specification Section: §6.1 (Components), §8 (Repo Structure)
Implements Objectives: O3 (Context-aware enforcement)

This module implements the enforcement guard as a Flask decorator. It intercepts
requests, extracts the JWT claims, queries the PIP to resolve environment and object
attributes, requests a decision from the PDP, and gates or blocks request routing.
"""

import functools
from flask import request, jsonify, g
import jwt
from server.auth import jwt_helper
from server.abac import pip, pdp


def enforce_abac(action_name: str):
    """
    Flask route decorator to enforce ABAC on an endpoint.
    
    Args:
        action_name (str): The action being performed (e.g., 'read', 'write').
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # 1. Extract and Verify JWT Token from Authorization Header
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return jsonify({"error": "Unauthorized: Missing or malformed authorization header"}), 401

            token = auth_header.split(" ")[1]
            try:
                # SECURITY: Decode and verify JWT token signature
                claims = jwt_helper.decode_token(token)
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Unauthorized: JWT token has expired"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Unauthorized: Invalid JWT token"}), 401

            # Extract subject ID (username) and JWT attributes
            subject_id = claims.get("sub")
            jwt_attrs = claims.get("attributes", {})

            # 2. Extract Resource ID (file_id) from Route Parameters if present
            # Flask route parameters are passed in kwargs
            resource_id = kwargs.get("file_id")

            # 3. Fetch Client Environment IP
            client_ip = request.remote_addr or "127.0.0.1"

            # 4. Resolve Attributes via PIP
            resolved_attrs = pip.resolve_attributes(
                subject_id=subject_id,
                resource_id=resource_id,
                action=action_name,
                client_ip=client_ip,
                jwt_claims_attrs=jwt_attrs
            )

            # Store resolved attributes and claims in Flask global request context g
            # This makes them accessible to the route handler if needed.
            g.user_id = subject_id
            g.user_attributes = resolved_attrs["subject"]
            g.resolved_attributes = resolved_attrs

            # 5. Evaluate Decision via PDP
            decision = pdp.evaluate(resolved_attrs)

            # Record every decision in the hash-chained audit trail.
            from server.audit import audit_log
            if decision != "Permit":
                audit_log.append(subject_id, action_name, resource_id, "deny",
                                 "ABAC policy decision point denied the request")

            # 6. Enforce PEP Gate
            if decision == "Permit":
                # Access Allowed: proceed to the actual route handler
                return f(*args, **kwargs)
            else:
                # SECURITY: Access Denied. Return 403 Forbidden.
                # Do not disclose database details to prevent intelligence gathering.
                return jsonify({
                    "error": "Access Denied: Subject attributes or environment context do not satisfy policy."
                }), 403

        return decorated_function
    return decorator
