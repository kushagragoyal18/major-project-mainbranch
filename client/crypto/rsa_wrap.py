"""
Asymmetric Cryptography Module (RSA-OAEP Key Wrap & RSA-PSS Signatures)
Implements Specification Section: §6.2, §6.3, §6.5 (Tier 3), §10
Implements Objectives: O5 (Integrity & Authenticity), O7 (Cost model / Per-user binding)

This module handles:
1. RSA key pair generation.
2. Serialization and deserialization of PEM key files.
3. RSA-OAEP (Optimal Asymmetric Encryption Padding) key wrapping. This binds the
   symmetric DEK to a specific recipient user/device.
4. RSA-PSS (Probabilistic Signature Scheme) signing and verification. This ensures
   non-repudiation (the author cannot deny uploading the file) and authenticity.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# SECURITY: 2048 bits is the minimum acceptable key size for RSA as of NIST guidelines.
# Standard public exponent is 65537 (F4).
RSA_KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537


def generate_key_pair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generates a new RSA private-public key pair.
    
    Returns:
        tuple: (RSAPrivateKey, RSAPublicKey) objects.
    """
    # SECURITY: Using standard exponent 65537 (2^16 + 1) which provides a good balance
    # between encryption speed and protection against small exponent attacks.
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private_key(private_key: rsa.RSAPrivateKey, passphrase: str = None) -> bytes:
    """
    Serializes private key object into PEM format (bytes).
    
    Args:
        private_key (RSAPrivateKey): The private key object to serialize.
        passphrase (str, optional): A password to encrypt the private key on disk.
        
    Returns:
        bytes: PEM-encoded private key.
    """
    if passphrase:
        encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        encryption_algorithm = serialization.NoEncryption()
        
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )


def deserialize_private_key(pem_data: bytes, passphrase: str = None) -> rsa.RSAPrivateKey:
    """
    Deserializes PEM-encoded bytes back into an RSAPrivateKey object.
    
    Args:
        pem_data (bytes): PEM-encoded private key.
        passphrase (str, optional): Passphrase if the key was encrypted.
        
    Returns:
        RSAPrivateKey: The loaded private key object.
    """
    return serialization.load_pem_private_key(
        pem_data,
        password=passphrase.encode() if passphrase else None,
        backend=default_backend()
    )


def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    """
    Serializes public key object into PEM format (bytes).
    
    Args:
        public_key (RSAPublicKey): The public key object to serialize.
        
    Returns:
        bytes: PEM-encoded public key.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
    """
    Deserializes PEM-encoded bytes back into an RSAPublicKey object.
    
    Args:
        pem_data (bytes): PEM-encoded public key.
        
    Returns:
        RSAPublicKey: The loaded public key object.
    """
    return serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )


def wrap_key(public_key: rsa.RSAPublicKey, key_to_wrap: bytes) -> bytes:
    """
    Wraps (encrypts) a symmetric key using RSA-OAEP.
    This serves as the Tier 3 key wrap.
    
    Args:
        public_key (RSAPublicKey): The public key of the recipient.
        key_to_wrap (bytes): The 32-byte symmetric key (DEK).
        
    Returns:
        bytes: RSA-OAEP encrypted key bytes.
    """
    # SECURITY: RSA-OAEP is used instead of PKCS#1 v1.5 padding to prevent padding oracle attacks.
    # We use SHA-256 as the hashing function for both the overall OAEP process and the MGF1 mask generation.
    wrapped = public_key.encrypt(
        key_to_wrap,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return wrapped


def unwrap_key(private_key: rsa.RSAPrivateKey, wrapped_key: bytes) -> bytes:
    """
    Unwraps (decrypts) a wrapped symmetric key using RSA-OAEP.
    
    Args:
        private_key (RSAPrivateKey): The private key of the recipient.
        wrapped_key (bytes): The RSA-OAEP encrypted key bytes.
        
    Returns:
        bytes: The unwrapped (decrypted) symmetric key bytes.
    """
    # SECURITY: Using matching OAEP padding with SHA-256 for decryption.
    unwrapped = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return unwrapped


def sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Computes an RSA-PSS signature over the data.
    Ensures non-repudiation and document authenticity.
    
    Args:
        private_key (RSAPrivateKey): Private key of the signer.
        data (bytes): The data (typically ciphertext) to sign.
        
    Returns:
        bytes: The signature bytes.
    """
    # SECURITY: Using PSS (Probabilistic Signature Scheme) padding which is
    # mathematically more secure than PKCS#1 v1.5 signatures.
    # SHA-256 is used to hash the message prior to signing.
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify(public_key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> bool:
    """
    Verifies an RSA-PSS signature against the original data.
    
    Args:
        public_key (RSAPublicKey): Public key of the signer.
        signature (bytes): The signature to verify.
        data (bytes): The original data that was signed.
        
    Returns:
        bool: True if signature is valid, False otherwise.
    """
    # SECURITY: Matches signing params (PSS padding with salt length MAX_LENGTH and SHA-256).
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
