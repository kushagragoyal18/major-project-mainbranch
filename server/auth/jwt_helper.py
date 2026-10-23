"""
JWT Authentication Helper Module
Implements Specification Section: §6.1 (Components), §7 (Tech Stack), §8 (Repo Structure)
Implements Objectives: O3 (Context-aware enforcement)

This module handles token-based authentication for the server. It embeds the user's
ABAC subject attributes (role, department, clearance) directly inside the JWT payload.
This allows the server to verify the user's identity and load their profile parameters
efficiently during API gateway interceptions.
"""

import os
import datetime
import jwt

# Fetch JWT Secret from environment variables
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-dev-jwt-key-change-in-production")
ALGORITHM = "HS256"


def generate_token(
    user_id: str,
    attributes: dict,
    expires_in_seconds: int = 3600,
    secret: str = None
) -> str:
    """
    Generates a signed JWT token containing user attributes.
    
    Args:
        user_id (str): Unique username or user ID.
        attributes (dict): User's ABAC subject attributes (e.g. {"role": "Doctor", "clearance": 3}).
        expires_in_seconds (int): Expiration time in seconds. Defaults to 1 hour.
        secret (str, optional): Custom signing key. Defaults to system env JWT_SECRET.
        
    Returns:
        str: Encoded and signed JWT string.
    """
    key = secret if secret else JWT_SECRET
    
    # Calculate token expiration timestamp
    now = datetime.datetime.now(datetime.timezone.utc)
    expiration = now + datetime.timedelta(seconds=expires_in_seconds)
    
    # Construct payload claims
    # SECURITY: Including standard 'sub' (subject), 'exp' (expiration), and 'iat' (issued at) claims,
    # alongside custom subject profile attributes used in PDP evaluations.
    payload = {
        "sub": user_id,
        "iat": now,
        "exp": expiration,
        "attributes": {
            "role": attributes.get("role", "User"),
            "department": attributes.get("department", "Default"),
            "clearance": int(attributes.get("clearance", 1))
        }
    }
    
    # Encode and sign the token
    return jwt.encode(payload, key, algorithm=ALGORITHM)


def decode_token(token: str, secret: str = None) -> dict:
    """
    Decodes and validates a JWT token, returning its claims.
    
    Args:
        token (str): The signed JWT string.
        secret (str, optional): Custom signing key. Defaults to system env JWT_SECRET.
        
    Returns:
        dict: The decoded token payload dictionary containing claims.
        
    Raises:
        jwt.ExpiredSignatureError: If the token signature is expired.
        jwt.InvalidTokenError: If the token is structurally invalid or signature check fails.
    """
    key = secret if secret else JWT_SECRET
    
    # SECURITY: Verifying signature and expiration claims.
    # Throws ExpiredSignatureError or InvalidTokenError if verification fails.
    return jwt.decode(token, key, algorithms=[ALGORITHM])
