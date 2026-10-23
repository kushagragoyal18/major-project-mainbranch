"""
Hashing Helper Module (SHA-256 Integrity Checks)
Implements Specification Section: §6.2, §6.3, §10
Implements Objectives: O5 (Integrity & Authenticity)

This module provides standard hashing helpers using SHA-256. Hashing is used
to verify that ciphertexts or metadata payloads have not been modified or corrupted
during transport or storage.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def compute_sha256(data: bytes) -> bytes:
    """
    Computes the SHA-256 hash of the input bytes.
    
    Args:
        data (bytes): Input data to hash.
        
    Returns:
        bytes: The 32-byte SHA-256 digest.
    """
    # SECURITY: Using SHA-256 to verify data integrity. It is collision-resistant
    # and widely standard for message digests.
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()


def compute_sha256_hex(data: bytes) -> str:
    """
    Computes the SHA-256 hash of the input bytes and returns it as a hex string.
    
    Args:
        data (bytes): Input data to hash.
        
    Returns:
        str: Hexadecimal string representation of the hash.
    """
    return compute_sha256(data).hex()
