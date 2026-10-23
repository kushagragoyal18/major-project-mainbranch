"""
Uploader Module (Three-Tier Key Wrapping & Envelope Generation)
Implements Specification Section: §6.2 (Upload Flow), §6.5 (Three-Tier Key Hierarchy), §10 (Security Requirements)
Implements Objectives: O1 (Confidentiality), O2 (Cryptographic Authorisation), O5 (Integrity & Authenticity)

This module implements the uploader-side data flow. It:
1. Generates a fresh random 256-bit symmetric Data Encryption Key (DEK).
2. Encrypts the raw file bytes using AES-256-GCM under this DEK (Tier 1).
3. Encrypts the DEK under a CP-ABE policy (Tier 2).
4. Optionally wraps the DEK under a recipient's public RSA key (Tier 3 device binding).
5. Computes a SHA-256 hash of the ciphertext.
6. Signs the hash using the sender's private RSA key (RSA-PSS) for authenticity.
7. Packages all components into a JSON-serializable dictionary with base64 encoding.
"""

import base64
from client.crypto import aes_gcm, rsa_wrap, cpabe, hashing


def _b64e(data: bytes) -> str:
    """Helper to base64 encode bytes to string."""
    return base64.b64encode(data).decode('utf-8')


def prepare_envelope(
    file_bytes: bytes,
    policy_str: str,
    abe_pk: dict,
    recipient_pub_key=None,
    sender_priv_key=None
) -> dict:
    """
    Encrypts a file and packages its DEK into a secure three-tier wrapped envelope.
    
    Args:
        file_bytes (bytes): The raw file bytes to encrypt.
        policy_str (str): The CP-ABE policy string to apply (e.g. 'CARDIOLOGY and LEVEL3').
        abe_pk (dict): The serialized CP-ABE Public Key parameter.
        recipient_pub_key (RSAPublicKey, optional): The recipient's RSA public key for device binding.
        sender_priv_key (RSAPrivateKey, optional): The sender's RSA private key for signing.
        
    Returns:
        dict: A JSON-serializable dictionary representing the cryptographic envelope:
            - "ciphertext" (str): Base64-encoded file ciphertext.
            - "nonce" (str): Base64-encoded GCM nonce.
            - "tag" (str): Base64-encoded GCM tag.
            - "wrapped_dek_abe" (dict): Serialization of CP-ABE wrapped DEK.
            - "wrapped_dek_rsa" (str, optional): Base64-encoded RSA-wrapped DEK.
            - "signature" (str, optional): Base64-encoded RSA-PSS signature.
            - "checksum" (str): SHA-256 hex checksum of original plaintext file bytes.
            - "policy" (str): Access policy.
    """
    # -------------------------------------------------------------------------
    # Tier 1: Generate Symmetric Key (DEK) and Encrypt File Contents
    # -------------------------------------------------------------------------
    # SECURITY: Generate a fresh, random 256-bit symmetric key from CSPRNG
    dek = aes_gcm.generate_key()
    
    # SECURITY: Encrypt plaintext using AES-256-GCM.
    # The GCM mode binds confidentiality and integrity together.
    enc_data = aes_gcm.encrypt(dek, file_bytes)
    
    # -------------------------------------------------------------------------
    # Tier 2: Wrap DEK under CP-ABE Access Policy
    # -------------------------------------------------------------------------
    # SECURITY: Encrypt DEK using CP-ABE.
    # If using the Charm wrapper, it generates a hybrid envelope.
    wrapped_dek_abe = cpabe.encrypt(abe_pk, dek, policy_str)
    
    # -------------------------------------------------------------------------
    # Tier 3 (Optional): Wrap DEK under Recipient's RSA Public Key (Device Binding)
    # -------------------------------------------------------------------------
    wrapped_dek_rsa_str = None
    if recipient_pub_key:
        # SECURITY: Encrypt the same 32-byte DEK using RSA-OAEP with SHA-256.
        # This binds access to a specific recipient user's device/hardware key.
        wrapped_rsa_bytes = rsa_wrap.wrap_key(recipient_pub_key, dek)
        wrapped_dek_rsa_str = _b64e(wrapped_rsa_bytes)
        
    # -------------------------------------------------------------------------
    # Integrity and Authenticity: Compute Hash & Digital Signature
    # -------------------------------------------------------------------------
    # Calculate SHA-256 digest of original file bytes for post-decrypt validation
    original_checksum = hashing.compute_sha256_hex(file_bytes)
    
    signature_str = None
    if sender_priv_key:
        # SECURITY: Compute SHA-256 of the ciphertext bytes.
        # Then, sign the digest using RSA-PSS padding to ensure non-repudiation.
        cipher_hash = hashing.compute_sha256(enc_data["ciphertext"])
        signature_bytes = rsa_wrap.sign(sender_priv_key, cipher_hash)
        signature_str = _b64e(signature_bytes)
        
    # Build and return the serializable envelope structure
    envelope = {
        "ciphertext": _b64e(enc_data["ciphertext"]),
        "nonce": _b64e(enc_data["nonce"]),
        "tag": _b64e(enc_data["tag"]),
        "wrapped_dek_abe": wrapped_dek_abe,
        "policy": policy_str,
        "checksum": original_checksum
    }
    
    if wrapped_dek_rsa_str:
        envelope["wrapped_dek_rsa"] = wrapped_dek_rsa_str
        
    if signature_str:
        envelope["signature"] = signature_str
        
    return envelope
