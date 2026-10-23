"""
Symmetric Encryption Module (AES-256-GCM)
Implements Specification Section: §6.2, §6.3, §10
Implements Objectives: O1 (Confidentiality), O5 (Integrity & Authenticity)

This module handles client-side symmetric encryption of files using AES-256 in GCM mode.
GCM (Galois/Counter Mode) provides authenticated encryption, meaning it guarantees
both confidentiality (data cannot be read without the key) and integrity/authenticity
(data cannot be modified without detection).
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# SECURITY: The standard length for an AES-256 key is 32 bytes (256 bits).
KEY_SIZE_BYTES = 32

# SECURITY: GCM standard nonce length is 96 bits (12 bytes).
# Nonces must NEVER be reused with the same key, as doing so completely destroys
# the confidentiality and integrity guarantees of GCM mode.
NONCE_SIZE_BYTES = 12


def generate_key() -> bytes:
    """
    Generates a cryptographically secure random 256-bit AES key.
    
    Returns:
        bytes: 32 random bytes from the OS's cryptographically secure PRNG (CSPRNG).
    """
    # SECURITY: Using os.urandom to fetch entropy directly from the OS kernel,
    # ensuring the key is unpredictable and secure.
    return os.urandom(KEY_SIZE_BYTES)


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = None) -> dict:
    """
    Encrypts plaintext bytes using AES-256-GCM.
    
    Args:
        key (bytes): The 32-byte symmetric key.
        plaintext (bytes): The raw data to encrypt.
        associated_data (bytes, optional): Optional metadata to bind cryptographically to the ciphertext.
        
    Returns:
        dict: A dictionary containing:
            - 'ciphertext' (bytes): The encrypted payload.
            - 'nonce' (bytes): The 12-byte initialization vector.
            - 'tag' (bytes): The 16-byte authentication tag.
            
    Raises:
        ValueError: If key size is invalid.
    """
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"AES-256 key must be exactly {KEY_SIZE_BYTES} bytes. Got {len(key)} bytes.")

    # SECURITY: Generate a fresh, unique 12-byte nonce for this encryption operation.
    nonce = os.urandom(NONCE_SIZE_BYTES)

    # Initialize the AES-GCM cipher with PyCA Cryptography
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # If associated data (AAD) is provided, pass it to the encryptor.
    # AAD is authenticated (guaranteed not to have changed) but NOT encrypted.
    if associated_data:
        encryptor.authenticate_additional_data(associated_data)

    # Perform the encryption
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # SECURITY: Retrieve the 16-byte authentication tag.
    # This tag is a cryptographic checksum of the plaintext, nonce, and AAD,
    # protecting the message from tampering and active injection attacks.
    tag = encryptor.tag

    return {
        "ciphertext": ciphertext,
        "nonce": nonce,
        "tag": tag
    }


def decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes, associated_data: bytes = None) -> bytes:
    """
    Decrypts AES-256-GCM ciphertext and verifies its integrity.
    
    Args:
        key (bytes): The 32-byte symmetric key.
        ciphertext (bytes): The encrypted payload.
        nonce (bytes): The 12-byte initialization vector used during encryption.
        tag (bytes): The 16-byte authentication tag generated during encryption.
        associated_data (bytes, optional): Authenticated data that must match the original.
        
    Returns:
        bytes: The decrypted raw plaintext bytes.
        
    Raises:
        ValueError: If key or nonce parameters are malformed.
        InvalidTag: If the integrity check fails (data has been tampered with or key is incorrect).
    """
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"AES-256 key must be exactly {KEY_SIZE_BYTES} bytes.")
    if len(nonce) != NONCE_SIZE_BYTES:
        raise ValueError(f"Nonce must be exactly {NONCE_SIZE_BYTES} bytes.")

    # Initialize the AES-GCM cipher with the provided nonce and tag.
    # GCM requires the tag during decryption to perform authentication.
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

    # Authenticate AAD if provided
    if associated_data:
        decryptor.authenticate_additional_data(associated_data)

    # SECURITY: decrypt and verify tag.
    # The .finalize() method will raise an InvalidTag exception if the ciphertext,
    # nonce, tag, or AAD has been altered in any way. This prevents Chosen-Ciphertext Attacks (CCA).
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    except InvalidTag as e:
        # Re-raise or log as security breach attempt
        raise InvalidTag("Decryption failed: Ciphertext or tag has been tampered with.") from e
