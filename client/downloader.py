"""
Downloader Module (Signature Verification & Three-Tier Decryption Flow)
Implements Specification Section: §6.3 (Download Flow), §6.5 (Three-Tier Key Hierarchy), §10 (Security Requirements)
Implements Objectives: O1 (Confidentiality), O2 (Cryptographic Authorisation), O5 (Integrity & Authenticity)

This module implements the downloader-side data flow. It:
1. Validates the uploader's signature (if sender public key is provided) to enforce
   authenticity before running heavy pairing or decryption algorithms.
2. Unwraps the symmetric Data Encryption Key (DEK) via one of three methods:
   - Method A: Transformed outsourced CP-ABE (using the server-computed transformed ciphertext).
   - Method B: Direct CP-ABE decryption (using the user's secret key).
   - Method C: RSA private key decryption (Tier 3 device binding unwrap).
3. Decrypts the file contents using AES-256-GCM under the recovered DEK.
4. Performs a final SHA-256 checksum verification to guarantee data integrity.
"""

import base64
from client.crypto import aes_gcm, rsa_wrap, cpabe, hashing
from cryptography.exceptions import InvalidTag


def _b64d(data: str) -> bytes:
    """Helper to base64 decode string to bytes."""
    return base64.b64decode(data.encode('utf-8'))


def decrypt_envelope(
    envelope: dict,
    abe_pk: dict,
    abe_sk: dict = None,
    recipient_priv_key=None,
    sender_pub_key=None,
    ct_prime: dict = None,
    dk: dict = None
) -> bytes:
    """
    Verifies the uploader's signature, decrypts the DEK, and recovers the original file plaintext.
    
    Args:
        envelope (dict): The cryptographic envelope dictionary generated during upload.
        abe_pk (dict): The serialized CP-ABE Public Key parameter.
        abe_sk (dict, optional): The user's serialized CP-ABE Secret Key.
        recipient_priv_key (RSAPrivateKey, optional): The recipient's RSA private key.
        sender_pub_key (RSAPublicKey, optional): The sender's RSA public key to verify authenticity.
        ct_prime (dict, optional): The transformed CP-ABE ciphertext if using outsourced decryption.
        dk (dict, optional): The client-side CP-ABE decryption key if using outsourced decryption.
        
    Returns:
        bytes: Decrypted original file bytes.
        
    Raises:
        ValueError: If signature verification fails, checksum fails, or key parameters are missing.
        PermissionError: If CP-ABE access policy is not satisfied.
    """
    # -------------------------------------------------------------------------
    # Decode Base64 Fields
    # -------------------------------------------------------------------------
    try:
        ciphertext = _b64d(envelope["ciphertext"])
        nonce = _b64d(envelope["nonce"])
        tag = _b64d(envelope["tag"])
    except KeyError as e:
        raise ValueError(f"Malformed envelope: missing required field {e}")

    # -------------------------------------------------------------------------
    # Authenticity: Verify Digital Signature
    # -------------------------------------------------------------------------
    # SECURITY: Signature verification is performed before running pairing/decryption.
    # This prevents Denial of Service (DoS) and active padding oracle attacks
    # by rejecting unauthenticated payloads early.
    if sender_pub_key and "signature" in envelope:
        signature = _b64d(envelope["signature"])
        cipher_hash = hashing.compute_sha256(ciphertext)
        
        is_authentic = rsa_wrap.verify(sender_pub_key, signature, cipher_hash)
        if not is_authentic:
            # SECURITY: Raise error immediately if the signature check fails.
            # Plaintext is never decrypted and ABE is not invoked.
            raise ValueError("Security Violation: Ciphertext signature is invalid or tampered.")

    # -------------------------------------------------------------------------
    # Recover DEK (Three-Tier Unwrapping Flow)
    # -------------------------------------------------------------------------
    dek = None
    
    # Mode A: Outsourced Decryption (using Server Transformed ABE + Client DK)
    if ct_prime and dk:
        # SECURITY: Decrypt using the lightweight z-key. The server has done the heavy
        # bilinear pairings but does not know z, so the server cannot read the DEK.
        dek = cpabe.decrypt_transformed(abe_pk, dk, ct_prime)
        
    # Mode B: Standard CP-ABE Decryption
    elif abe_sk:
        # SECURITY: Decrypt using the user's full ABE secret key containing attributes.
        # This will raise a PermissionError if the attributes do not satisfy the policy.
        dek = cpabe.decrypt(abe_pk, abe_sk, envelope["wrapped_dek_abe"])
        
    # Mode C: RSA Decryption (Device Binding Bypass/Path)
    elif recipient_priv_key and "wrapped_dek_rsa" in envelope:
        # SECURITY: Decrypt using recipient's private key (RSA-OAEP with SHA-256).
        # This binds access to a specific private key bound to the local device.
        wrapped_dek_rsa = _b64d(envelope["wrapped_dek_rsa"])
        dek = rsa_wrap.unwrap_key(recipient_priv_key, wrapped_dek_rsa)
        
    else:
        raise ValueError(
            "Decryption Configuration Error: No valid decryption keys or parameters provided."
        )

    if not dek:
        raise ValueError("Decryption failed: could not recover Data Encryption Key (DEK).")

    # -------------------------------------------------------------------------
    # Tier 1 Decryption: Symmetric Decrypt and Verify GCM Tag
    # -------------------------------------------------------------------------
    # SECURITY: Decrypting files with AES-256-GCM. The GCM engine verifies the tag
    # which ensures the payload was not modified during storage.
    try:
        plaintext = aes_gcm.decrypt(
            key=dek,
            ciphertext=ciphertext,
            nonce=nonce,
            tag=tag
        )
    except InvalidTag as e:
        # SECURITY: Map cryptographic errors to generic ValueErrors to prevent leaking cryptostate details.
        raise ValueError("Decryption failed: Ciphertext or tag has been tampered with.") from e

    # -------------------------------------------------------------------------
    # Integrity Check: Checksum Verification
    # -------------------------------------------------------------------------
    # SECURITY: Validate the final decrypted bytes against the original checksum.
    # This prevents any undetected file alterations.
    computed_checksum = hashing.compute_sha256_hex(plaintext)
    if computed_checksum != envelope["checksum"]:
        raise ValueError(
            "Integrity Compromised: Decrypted file checksum mismatch."
        )

    return plaintext
