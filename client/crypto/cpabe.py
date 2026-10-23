"""
Main Attribute-Based Encryption Wrapper (CP-ABE / Charm-Crypto & Fallback)
Implements Specification Section: §4 (In Scope), §6.3, §6.4, §6.5 (Tier 2), §7, §9 (Phase 1)
Implements Objectives: O2 (Cryptographic authorisation), O4 (Efficient revocation)

This module is the primary entry point for CP-ABE operations. It dynamically attempts
to import Charm-Crypto libraries. If the import fails or ABE_MODE is configured as
'simulated', it falls back to the simulated version in cpabe_simulated.py.
Otherwise, it executes real bilinear pairing-based cryptography.

It implements a hybrid ABE encryption system:
1. A random group element M is chosen.
2. M is encrypted under the CP-ABE policy using Charm-Crypto BSW07.
3. A symmetric key is derived from M by hashing (SHA-256).
4. The actual DEK is encrypted with this symmetric key using AES-256-GCM.
5. Outsourced decryption utilizes the Green et al. method, delegating pairings
   to the server via a transformation key scaled by 1/z.
"""

import os
import sys
import hashlib
import logging
from client.crypto import cpabe_simulated

# Setup logger for warnings regarding cryptography fallbacks
logger = logging.getLogger(__name__)

# Check configuration from environment variables
ABE_MODE = os.getenv("ABE_MODE", "real").lower()

# Flag to indicate if real Charm-Crypto is loaded
CHARM_AVAILABLE = False

try:
    # Attempt to import Charm-Crypto dependencies
    from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
    from charm.toolbox.pairinggroup import PairingGroup, GT, ZR
    CHARM_AVAILABLE = True
except ImportError:
    CHARM_AVAILABLE = False
    logger.warning("Charm-Crypto is not installed. Falling back to Simulated CP-ABE.")

# Determine active module
# SECURITY: Fail open for developer usage but log warnings. For production, simulated mode should be disabled.
if CHARM_AVAILABLE and ABE_MODE == "real":
    USE_SIMULATED = False
    # Initialize the pairing group and BSW07 scheme
    # Using 'SS512' symmetric pairing group (fastest standard group in Charm)
    group = PairingGroup('SS512')
    cpabe = CPabe_BSW07(group)
else:
    USE_SIMULATED = True
    logger.info("Using Simulated CP-ABE for cryptographic operations.")


# Helper functions to serialize and deserialize Charm-Crypto objects
def _serialize_charm(obj):
    """Recursively serializes Charm-Crypto group elements to base64 strings."""
    if not CHARM_AVAILABLE:
        return obj
    import base64
    if isinstance(obj, dict):
        return {k: _serialize_charm(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_serialize_charm(v) for v in obj]
    elif isinstance(obj, bytes):
        return base64.b64encode(obj).decode('utf-8')
    elif isinstance(obj, str):
        return obj
    else:
        # Group elements or integers in Zr/G1/G2/GT
        try:
            serialized = group.serialize(obj)
            return {
                "__type__": "charm_element",
                "data": base64.b64encode(serialized).decode('utf-8')
            }
        except Exception:
            return str(obj)


def _deserialize_charm(obj):
    """Recursively deserializes base64 strings back to Charm-Crypto group elements."""
    if not CHARM_AVAILABLE:
        return obj
    import base64
    if isinstance(obj, dict):
        if obj.get("__type__") == "charm_element":
            data = base64.b64decode(obj["data"].encode('utf-8'))
            return group.deserialize(data)
        return {k: _deserialize_charm(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_deserialize_charm(v) for v in obj]
    elif isinstance(obj, str):
        return obj
    return obj


# Helper to derive a 256-bit symmetric key from a group element M in GT
def _derive_symmetric_key(group_element_M) -> bytes:
    serialized_m = group.serialize(group_element_M)
    return hashlib.sha256(serialized_m).digest()


# Helper to encrypt the DEK with derived key
def _encrypt_dek_with_key(key: bytes, dek: bytes) -> dict:
    from client.crypto import aes_gcm
    return aes_gcm.encrypt(key, dek)


# Helper to decrypt the DEK with derived key
def _decrypt_dek_with_key(key: bytes, dek_ct: dict) -> bytes:
    from client.crypto import aes_gcm
    # Convert base64 fields if they are strings
    import base64
    def get_bytes(field):
        val = dek_ct[field]
        return base64.b64decode(val.encode('utf-8')) if isinstance(val, str) else val

    return aes_gcm.decrypt(
        key=key,
        ciphertext=get_bytes("ciphertext"),
        nonce=get_bytes("nonce"),
        tag=get_bytes("tag")
    )


# -----------------------------------------------------------------------------
# Public API (delegates to real or simulated depending on configuration)
# -----------------------------------------------------------------------------

def is_simulated() -> bool:
    """Returns True if the active implementation is simulated."""
    return USE_SIMULATED


def setup() -> tuple[dict, dict]:
    """
    Sets up the CP-ABE scheme, generating master parameters.
    
    Returns:
        tuple[dict, dict]: (PK, MSK) serialized as JSON-friendly dictionaries.
    """
    if USE_SIMULATED:
        return cpabe_simulated.setup()
        
    # Real CP-ABE setup
    # pk contains public parameters, msk contains secret authority key
    pk_obj, msk_obj = cpabe.setup()
    return _serialize_charm(pk_obj), _serialize_charm(msk_obj)


def keygen(pk: dict, msk: dict, attributes: list[str]) -> dict:
    """
    Generates a user private key containing specified attributes.
    
    Args:
        pk (dict): Serialized Public Key.
        msk (dict): Serialized Master Secret Key.
        attributes (list[str]): List of attribute strings.
        
    Returns:
        dict: Serialized User Secret Key.
    """
    if USE_SIMULATED:
        return cpabe_simulated.keygen(pk, msk, attributes)

    # Deserialize parameters
    pk_obj = _deserialize_charm(pk)
    msk_obj = _deserialize_charm(msk)
    # Attributes must be capitalized and stripped for Charm policy consistency
    attrs_clean = [a.upper().strip() for a in attributes]
    
    sk_obj = cpabe.keygen(pk_obj, msk_obj, attrs_clean)
    
    # Store attributes inside serialized dict for client-side evaluation checks
    sk_serialized = _serialize_charm(sk_obj)
    sk_serialized["attributes"] = attrs_clean
    return sk_serialized


def encrypt(pk: dict, message: bytes, policy_str: str) -> dict:
    """
    Encrypts (wraps) a 32-byte DEK under a boolean policy.
    
    Args:
        pk (dict): Serialized Public Key.
        message (bytes): The 32-byte DEK.
        policy_str (str): Access control policy (e.g. '(CARDIOLOGY and LEVEL3) or ADMIN')
        
    Returns:
        dict: CP-ABE envelope containing the policy, CP-ABE encrypted key seed M,
              and AES-GCM encrypted DEK.
    """
    if USE_SIMULATED:
        return cpabe_simulated.encrypt(pk, message, policy_str)

    pk_obj = _deserialize_charm(pk)
    
    # SECURITY: Generate a random group element M in GT.
    # We encrypt M under CP-ABE, and use SHA-256(M) as a symmetric key to encrypt the DEK.
    M = group.random(GT)
    
    # Charm-Crypto expects policies with uppercase operators (AND, OR)
    policy_formatted = policy_str.upper()
    
    # Encrypt M under the policy
    ct_abe_obj = cpabe.encrypt(pk_obj, M, policy_formatted)
    
    # Derive the symmetric key from M
    sym_key = _derive_symmetric_key(M)
    
    # Encrypt the DEK using the derived symmetric key
    dek_enc = _encrypt_dek_with_key(sym_key, message)
    
    return {
        "type": "real_ct",
        "policy": policy_str,
        "ct_abe": _serialize_charm(ct_abe_obj),
        "dek_ct": {
            "ciphertext": _serialize_charm(dek_enc["ciphertext"]),
            "nonce": _serialize_charm(dek_enc["nonce"]),
            "tag": _serialize_charm(dek_enc["tag"])
        }
    }


def decrypt(pk: dict, sk: dict, ct: dict) -> bytes:
    """
    Decrypts the envelope and recovers the DEK if attributes satisfy the policy.
    
    Args:
        pk (dict): Serialized Public Key.
        sk (dict): Serialized User Secret Key.
        ct (dict): Serialized CP-ABE envelope.
        
    Returns:
        bytes: Decrypted 32-byte DEK.
    """
    if USE_SIMULATED:
        return cpabe_simulated.decrypt(pk, sk, ct)

    pk_obj = _deserialize_charm(pk)
    sk_obj = _deserialize_charm(sk)
    ct_abe_obj = _deserialize_charm(ct["ct_abe"])
    
    # SECURITY: Perform ABE decryption of the group element M
    try:
        M = cpabe.decrypt(pk_obj, sk_obj, ct_abe_obj)
    except Exception as e:
        raise PermissionError("Decryption failed: attributes do not satisfy the policy or key is corrupt.") from e
        
    if M is False or M is None:
        raise PermissionError("Access Denied: Attributes do not satisfy CP-ABE policy.")
        
    # Derive symmetric key from M
    sym_key = _derive_symmetric_key(M)
    
    # Decrypt the DEK
    return _decrypt_dek_with_key(sym_key, ct["dek_ct"])


def generate_transform_key(pk: dict, sk: dict) -> tuple[dict, dict]:
    """
    Generates a Transformation Key (TK) for server offloading and Decryption Key (DK).
    This implements outsourced decryption (§6.4, §10).
    
    Args:
        pk (dict): Serialized Public Key.
        sk (dict): Serialized User Secret Key.
        
    Returns:
        tuple[dict, dict]: (TK, DK) serialized dictionaries.
    """
    if USE_SIMULATED:
        return cpabe_simulated.generate_transform_key(pk, sk)

    # Deserialize sk
    sk_obj = _deserialize_charm(sk)

    # SECURITY: Choose a random z in ZR (bilinear pairing scalar group)
    z = group.random(ZR)
    z_inv = ~z  # Multiplicative inverse of z: 1/z

    # Scale the secret key components by 1/z.
    # This prevents the server from decrypting the actual M, as it only recovers M^(1/z).
    tk_obj = {
        "D": sk_obj["D"] ** z_inv,
        "D_y": {},
        "D_y_prime": {}
    }
    for attr, val in sk_obj["D_y"].items():
        tk_obj["D_y"][attr] = val ** z_inv
    for attr, val in sk_obj["D_y_prime"].items():
        tk_obj["D_y_prime"][attr] = val ** z_inv

    tk_serialized = _serialize_charm(tk_obj)
    # Server needs attributes to check policy satisfaction before transformation
    tk_serialized["attributes"] = sk.get("attributes", [])

    dk_serialized = {
        "type": "real_dk",
        "z": _serialize_charm(z)
    }

    return tk_serialized, dk_serialized


def transform(pk: dict, tk: dict, ct: dict) -> dict:
    """
    Server-side operation: runs Bilinear pairings using TK to reduce CP-ABE ciphertext
    to a simplified form (ct_prime) containing M^(1/z).
    
    Args:
        pk (dict): Serialized Public Key.
        tk (dict): Serialized Transformation Key.
        ct (dict): Serialized Ciphertext.
        
    Returns:
        dict: Transformed ciphertext containing M^(1/z) and the encrypted DEK.
    """
    if USE_SIMULATED:
        return cpabe_simulated.transform(pk, tk, ct)

    pk_obj = _deserialize_charm(pk)
    tk_obj = _deserialize_charm(tk)
    ct_abe_obj = _deserialize_charm(ct["ct_abe"])

    # SECURITY: Server runs CP-ABE decryption algorithm using tk_obj (scaled by 1/z).
    # The result of pairings will be M^(1/z) instead of M.
    try:
        M_prime = cpabe.decrypt(pk_obj, tk_obj, ct_abe_obj)
    except Exception as e:
        raise PermissionError("Transformation failed: attributes do not satisfy policy.") from e

    if M_prime is False or M_prime is None:
        raise PermissionError("Access Denied: Attributes do not satisfy policy.")

    # Return M^(1/z) and the unchanged encrypted DEK component
    return {
        "type": "real_ct_prime",
        "M_prime": _serialize_charm(M_prime),
        "dek_ct": ct["dek_ct"]
    }


def decrypt_transformed(pk: dict, dk: dict, ct_prime: dict) -> bytes:
    """
    Client-side operation: performs a single group exponentiation to recover M
    from M^(1/z), then decrypts the DEK.
    
    Args:
        pk (dict): Serialized Public Key.
        dk (dict): Serialized Decryption Key containing z.
        ct_prime (dict): Serialized Transformed Ciphertext.
        
    Returns:
        bytes: Decrypted 32-byte DEK.
    """
    if USE_SIMULATED:
        return cpabe_simulated.decrypt_transformed(pk, dk, ct_prime)

    dk_obj = _deserialize_charm(dk)
    M_prime = _deserialize_charm(ct_prime["M_prime"])
    z = dk_obj["z"]

    # SECURITY: Client exponentiates the transformed seed: (M^(1/z))^z = M.
    # Since only the client has z (inside DK), only the client can recover M and the DEK.
    M = M_prime ** z

    # Derive symmetric key and decrypt DEK
    sym_key = _derive_symmetric_key(M)
    return _decrypt_dek_with_key(sym_key, ct_prime["dek_ct"])
