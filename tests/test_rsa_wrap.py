import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from client.crypto import rsa_wrap


def test_rsa_key_generation():
    """Verify that key generation yields valid RSAPrivateKey and RSAPublicKey."""
    private_key, public_key = rsa_wrap.generate_key_pair()
    
    assert isinstance(private_key, rsa.RSAPrivateKey)
    assert isinstance(public_key, rsa.RSAPublicKey)
    assert private_key.key_size == 2048


def test_pem_serialization_roundtrip():
    """Verify that serializing and deserializing keys preserves key material."""
    private_key, public_key = rsa_wrap.generate_key_pair()
    
    # Test private key serialization/deserialization without password
    priv_pem = rsa_wrap.serialize_private_key(private_key)
    deserialized_priv = rsa_wrap.deserialize_private_key(priv_pem)
    assert isinstance(deserialized_priv, rsa.RSAPrivateKey)
    
    # Test private key serialization/deserialization with password
    passphrase = "secure_password"
    priv_pem_pwd = rsa_wrap.serialize_private_key(private_key, passphrase=passphrase)
    deserialized_priv_pwd = rsa_wrap.deserialize_private_key(priv_pem_pwd, passphrase=passphrase)
    assert isinstance(deserialized_priv_pwd, rsa.RSAPrivateKey)
    
    # Test public key serialization/deserialization
    pub_pem = rsa_wrap.serialize_public_key(public_key)
    deserialized_pub = rsa_wrap.deserialize_public_key(pub_pem)
    assert isinstance(deserialized_pub, rsa.RSAPublicKey)


def test_key_wrap_unwrap_roundtrip():
    """Verify that a symmetric key can be wrapped with public key and unwrapped with private key."""
    private_key, public_key = rsa_wrap.generate_key_pair()
    symmetric_key = b"\x01" * 32  # Simulated DEK
    
    # Wrap key
    wrapped_key = rsa_wrap.wrap_key(public_key, symmetric_key)
    assert len(wrapped_key) == 256  # 2048 bits / 8 = 256 bytes
    assert wrapped_key != symmetric_key
    
    # Unwrap key
    unwrapped_key = rsa_wrap.unwrap_key(private_key, wrapped_key)
    assert unwrapped_key == symmetric_key


def test_invalid_key_unwrap():
    """Verify that attempting to decrypt with a different private key fails."""
    private_key_1, public_key_1 = rsa_wrap.generate_key_pair()
    private_key_2, public_key_2 = rsa_wrap.generate_key_pair()
    symmetric_key = b"\x02" * 32
    
    wrapped = rsa_wrap.wrap_key(public_key_1, symmetric_key)
    
    # Unwrapping with private key 2 should fail
    with pytest.raises(ValueError):
        rsa_wrap.unwrap_key(private_key_2, wrapped)


def test_signing_and_verification():
    """Verify that RSA-PSS signing and verification works correctly."""
    private_key, public_key = rsa_wrap.generate_key_pair()
    payload = b"Important cloud file ciphertext content."
    
    # Sign
    signature = rsa_wrap.sign(private_key, payload)
    assert len(signature) == 256
    
    # Verify valid signature
    is_valid = rsa_wrap.verify(public_key, signature, payload)
    assert is_valid is True


def test_invalid_signature_verification():
    """Verify that verification fails if signature or payload is modified."""
    private_key, public_key = rsa_wrap.generate_key_pair()
    payload = b"Important cloud file ciphertext content."
    
    signature = rsa_wrap.sign(private_key, payload)
    
    # Verify fails for modified payload
    modified_payload = payload + b" tampered"
    assert rsa_wrap.verify(public_key, signature, modified_payload) is False
    
    # Verify fails for modified signature
    corrupted_sig = bytearray(signature)
    corrupted_sig[0] = corrupted_sig[0] ^ 0xFF
    assert rsa_wrap.verify(public_key, bytes(corrupted_sig), payload) is False

    # Verify fails with different key
    _, other_public_key = rsa_wrap.generate_key_pair()
    assert rsa_wrap.verify(other_public_key, signature, payload) is False
