"""
Simulated Attribute-Based Encryption Module (CP-ABE Fallback)
Implements Specification Section: §4 (In Scope), §7, §9 (Phase 1 / Fallback)
Implements Objectives: O2 (Cryptographic authorisation), O4 (Efficient revocation)

This module provides a pure-Python simulation of Ciphertext-Policy Attribute-Based
Encryption (CP-ABE) matching the interface of the real Charm-Crypto implementation.
It evaluates policies containing standard boolean logic ('AND', 'OR', parentheses)
against user attribute lists. It uses symmetric keys and AES-GCM to simulate key
wrapping and outsourced decryption (transform/decrypt_transformed).

# FALLBACK: This module is a mock simulation and must only be used if Charm-Crypto
is not compiled or available.
"""

import os
import re
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# Standard constants for internal symmetric crypto of simulation
KEY_SIZE_BYTES = 32
NONCE_SIZE_BYTES = 12


def _b64e(data: bytes) -> str:
    """Helper to base64 encode bytes to string."""
    return base64.b64encode(data).decode('utf-8')


def _b64d(data: str) -> bytes:
    """Helper to base64 decode string to bytes."""
    return base64.b64decode(data.encode('utf-8'))


def _aes_encrypt(key: bytes, plaintext: bytes) -> dict:
    """Internal helper to encrypt plaintext using AES-GCM."""
    nonce = os.urandom(NONCE_SIZE_BYTES)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return {
        "ciphertext": _b64e(ciphertext),
        "nonce": _b64e(nonce),
        "tag": _b64e(encryptor.tag)
    }


def _aes_decrypt(key: bytes, ct_dict: dict) -> bytes:
    """Internal helper to decrypt ciphertext using AES-GCM."""
    try:
        ciphertext = _b64d(ct_dict["ciphertext"])
        nonce = _b64d(ct_dict["nonce"])
        tag = _b64d(ct_dict["tag"])
    except KeyError as e:
        raise ValueError(f"Malformed ciphertext dictionary: missing key {e}")

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        return decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag as e:
        raise ValueError("Decryption failed: Integrity check failed or invalid attributes.") from e


def evaluate_policy(policy_str: str, attributes: list[str]) -> bool:
    """
    Evaluates a boolean policy string against a list of user attributes.
    Supports attribute names, logical operators 'and', 'or', and parentheses.
    Evaluation is case-insensitive.
    
    Args:
        policy_str (str): Boolean logic string (e.g. '(CARDIOLOGY and LEVEL_3) or ADMIN')
        attributes (list[str]): List of attributes possessed by the user.
        
    Returns:
        bool: True if attributes satisfy the policy, False otherwise.
    """
    # Normalize policy string and tokenize
    # SECURITY: Standardizing formatting of policy string to prevent bypasses or malformed tokens.
    policy_str = policy_str.lower()
    tokens = re.findall(r'[a-zA-Z0-9_\-\:]+|\(|\)', policy_str)
    if not tokens:
        return True

    # Normalize user attributes to lowercase for matching
    attr_set = {a.lower().strip() for a in attributes}

    # Shunting-yard algorithm to convert infix to postfix
    precedence = {'or': 1, 'and': 2}
    output = []
    operators = []

    for token in tokens:
        if token == '(':
            operators.append(token)
        elif token == ')':
            while operators and operators[-1] != '(':
                output.append(operators.pop())
            if operators and operators[-1] == '(':
                operators.pop()
        elif token in precedence:
            while operators and operators[-1] in precedence and precedence[operators[-1]] >= precedence[token]:
                output.append(operators.pop())
            operators.append(token)
        else:
            # It's an attribute name
            output.append(token)

    while operators:
        output.append(operators.pop())

    # Evaluate postfix expression
    stack = []
    for token in output:
        if token == 'and':
            if len(stack) < 2:
                return False
            val2 = stack.pop()
            val1 = stack.pop()
            stack.append(val1 and val2)
        elif token == 'or':
            if len(stack) < 2:
                return False
            val2 = stack.pop()
            val1 = stack.pop()
            stack.append(val1 or val2)
        else:
            # Check if this attribute is possessed by the user
            stack.append(token in attr_set)

    if len(stack) == 1:
        return stack[0]
    return False


def setup() -> tuple[dict, dict]:
    """
    Sets up the simulated CP-ABE system parameters.
    Generates a master secret key (MSK) and a public key (PK).
    
    Returns:
        tuple: (PK, MSK) dictionaries.
    """
    # SECURITY: Generating a random master secret key for the simulated authority
    master_key = os.urandom(KEY_SIZE_BYTES)
    
    pk = {
        "type": "simulated_pk",
        "key": _b64e(master_key)
    }
    
    msk = {
        "type": "simulated_msk",
        "key": _b64e(master_key)
    }
    
    return pk, msk


def keygen(pk: dict, msk: dict, attributes: list[str]) -> dict:
    """
    Generates a simulated secret key (SK) for a user with the specified attributes.
    
    Args:
        pk (dict): Simulated Public Key.
        msk (dict): Simulated Master Secret Key.
        attributes (list[str]): List of attributes assigned to the user.
        
    Returns:
        dict: User secret key dictionary containing attributes and master key.
    """
    # SECURITY: SK binds user attributes with master key capabilities.
    # In simulated mode, the key simply embeds the attributes list and master key bytes.
    return {
        "type": "simulated_sk",
        "attributes": [a.lower().strip() for a in attributes],
        "key": msk["key"]
    }


def encrypt(pk: dict, message: bytes, policy_str: str) -> dict:
    """
    Encrypts (wraps) a symmetric key (DEK) under a CP-ABE access policy.
    
    Args:
        pk (dict): Simulated Public Key.
        message (bytes): Key to encrypt (usually 32 bytes).
        policy_str (str): Access policy boolean string.
        
    Returns:
        dict: Simulated ciphertext dictionary containing policy, ciphertext, nonce, and tag.
    """
    # Decode master key
    master_key = _b64d(pk["key"])
    
    # Encrypt the message with the master key using GCM
    enc_data = _aes_encrypt(master_key, message)
    
    # Pack policy alongside ciphertext metadata
    return {
        "type": "simulated_ct",
        "policy": policy_str,
        "ciphertext": enc_data["ciphertext"],
        "nonce": enc_data["nonce"],
        "tag": enc_data["tag"]
    }


def decrypt(pk: dict, sk: dict, ct: dict) -> bytes:
    """
    Decrypts (unwraps) the symmetric key if user attributes satisfy the policy.
    
    Args:
        pk (dict): Simulated Public Key.
        sk (dict): User Secret Key containing attributes.
        ct (dict): Simulated Ciphertext containing policy and ciphertext.
        
    Returns:
        bytes: Decrypted key bytes.
        
    Raises:
        ValueError: If policy check fails or ciphertext is tampered.
        PermissionError: If attributes do not satisfy the policy.
    """
    # SECURITY: Check attribute policy before performing decryption
    policy = ct.get("policy", "")
    user_attrs = sk.get("attributes", [])
    
    if not evaluate_policy(policy, user_attrs):
        raise PermissionError(
            f"Access Denied: Attributes {user_attrs} do not satisfy policy '{policy}'."
        )
        
    # Retrieve master key from secret key
    master_key = _b64d(sk["key"])
    
    # Perform decryption
    return _aes_decrypt(master_key, ct)


def generate_transform_key(pk: dict, sk: dict) -> tuple[dict, dict]:
    """
    Generates a Transformation Key (TK) and lightweight Decryption Key (DK).
    This implements outsourced decryption capability (§6.4, §10).
    
    Args:
        pk (dict): Public Key.
        sk (dict): Secret Key.
        
    Returns:
        tuple: (TK, DK) dictionaries.
    """
    # SECURITY: Generate a temporary random key 'z' for local decryption.
    # The uploader's key wrap is decrypted by the server using TK, then re-wrapped under 'z'.
    # The client uses DK (containing 'z') to perform a lightweight final decryption.
    z_key = os.urandom(KEY_SIZE_BYTES)
    
    tk = {
        "type": "simulated_tk",
        "attributes": sk["attributes"],
        "key": sk["key"],
        "z": _b64e(z_key)
    }
    
    dk = {
        "type": "simulated_dk",
        "z": _b64e(z_key)
    }
    
    return tk, dk


def transform(pk: dict, tk: dict, ct: dict) -> dict:
    """
    Server-side operation: decrypts the CP-ABE ciphertext using the transformation key (TK)
    and re-encrypts it under the temporary key 'z'.
    Does not expose plaintext to the server (conceptually, in a real bilinear pairings model).
    
    Args:
        pk (dict): Public Key.
        tk (dict): Transformation Key containing user attributes and 'z'.
        ct (dict): Ciphertext.
        
    Returns:
        dict: A transformed ciphertext dictionary (CT').
        
    Raises:
        ValueError: If decryption fails.
        PermissionError: If attributes do not satisfy the policy.
    """
    # Check policy satisfaction
    policy = ct.get("policy", "")
    user_attrs = tk.get("attributes", [])
    
    if not evaluate_policy(policy, user_attrs):
        raise PermissionError(
            f"Access Denied: User attributes do not satisfy policy '{policy}' during outsourced transformation."
        )
        
    # Decrypt original ciphertext using the master key embedded in TK
    master_key = _b64d(tk["key"])
    plaintext = _aes_decrypt(master_key, ct)
    
    # Re-encrypt plaintext under the temporary key 'z'
    z_key = _b64d(tk["z"])
    re_enc = _aes_encrypt(z_key, plaintext)
    
    return {
        "type": "simulated_ct_prime",
        "ciphertext": re_enc["ciphertext"],
        "nonce": re_enc["nonce"],
        "tag": re_enc["tag"]
    }


def decrypt_transformed(pk: dict, dk: dict, ct_prime: dict) -> bytes:
    """
    Client-side operation: performs a lightweight decryption of the transformed
    ciphertext using the lightweight Decryption Key (DK).
    
    Args:
        pk (dict): Public Key.
        dk (dict): Decryption Key containing 'z'.
        ct_prime (dict): Transformed Ciphertext.
        
    Returns:
        bytes: Decrypted key bytes.
    """
    z_key = _b64d(dk["z"])
    return _aes_decrypt(z_key, ct_prime)
