import pytest
from cryptography.exceptions import InvalidTag
from client.crypto import aes_gcm


def test_generate_key():
    """Verify key generation produces 32-byte (256-bit) keys."""
    key = aes_gcm.generate_key()
    assert isinstance(key, bytes)
    assert len(key) == 32
    
    # Generate another key and ensure it is different (basic entropy check)
    key2 = aes_gcm.generate_key()
    assert key != key2


def test_encrypt_decrypt_roundtrip():
    """Verify that encrypted text can be decrypted back to plaintext."""
    key = aes_gcm.generate_key()
    plaintext = b"This is a secret message for secure cloud storage."
    
    # Perform encryption
    enc_data = aes_gcm.encrypt(key, plaintext)
    assert "ciphertext" in enc_data
    assert "nonce" in enc_data
    assert "tag" in enc_data
    
    assert len(enc_data["nonce"]) == 12
    assert len(enc_data["tag"]) == 16
    assert enc_data["ciphertext"] != plaintext

    # Perform decryption
    decrypted = aes_gcm.decrypt(
        key=key,
        ciphertext=enc_data["ciphertext"],
        nonce=enc_data["nonce"],
        tag=enc_data["tag"]
    )
    assert decrypted == plaintext


def test_associated_data_binding():
    """Verify that Associated Additional Data (AAD) is bound and authenticated."""
    key = aes_gcm.generate_key()
    plaintext = b"Patient record contents."
    aad = b"Owner ID: 12345"
    
    # Encrypt with AAD
    enc_data = aes_gcm.encrypt(key, plaintext, associated_data=aad)
    
    # Decrypt with matching AAD
    decrypted = aes_gcm.decrypt(
        key=key,
        ciphertext=enc_data["ciphertext"],
        nonce=enc_data["nonce"],
        tag=enc_data["tag"],
        associated_data=aad
    )
    assert decrypted == plaintext
    
    # Attempt decrypt with different AAD
    wrong_aad = b"Owner ID: 54321"
    with pytest.raises(InvalidTag):
        aes_gcm.decrypt(
            key=key,
            ciphertext=enc_data["ciphertext"],
            nonce=enc_data["nonce"],
            tag=enc_data["tag"],
            associated_data=wrong_aad
        )


def test_nonce_uniqueness():
    """Verify that multiple encryptions of the same plaintext yield different nonces/ciphertexts."""
    key = aes_gcm.generate_key()
    plaintext = b"Identical plaintext."
    
    enc1 = aes_gcm.encrypt(key, plaintext)
    enc2 = aes_gcm.encrypt(key, plaintext)
    
    assert enc1["nonce"] != enc2["nonce"]
    assert enc1["ciphertext"] != enc2["ciphertext"]
    assert enc1["tag"] != enc2["tag"]


def test_tampering_detection():
    """Verify that modifying the ciphertext or tag results in decryption failure (InvalidTag)."""
    key = aes_gcm.generate_key()
    plaintext = b"Important database record."
    enc_data = aes_gcm.encrypt(key, plaintext)
    
    # Tamper with ciphertext
    corrupted_ct = bytearray(enc_data["ciphertext"])
    corrupted_ct[0] = corrupted_ct[0] ^ 0xFF  # Flip first byte
    
    with pytest.raises(InvalidTag):
        aes_gcm.decrypt(
            key=key,
            ciphertext=bytes(corrupted_ct),
            nonce=enc_data["nonce"],
            tag=enc_data["tag"]
        )

    # Tamper with tag
    corrupted_tag = bytearray(enc_data["tag"])
    corrupted_tag[0] = corrupted_tag[0] ^ 0xFF
    
    with pytest.raises(InvalidTag):
        aes_gcm.decrypt(
            key=key,
            ciphertext=enc_data["ciphertext"],
            nonce=enc_data["nonce"],
            tag=bytes(corrupted_tag)
        )


def test_wrong_key_decryption():
    """Verify that decrypting with the wrong key fails."""
    key = aes_gcm.generate_key()
    wrong_key = aes_gcm.generate_key()
    plaintext = b"Target payload."
    
    enc_data = aes_gcm.encrypt(key, plaintext)
    
    with pytest.raises(InvalidTag):
        aes_gcm.decrypt(
            key=wrong_key,
            ciphertext=enc_data["ciphertext"],
            nonce=enc_data["nonce"],
            tag=enc_data["tag"]
        )


def test_invalid_parameters():
    """Verify that providing invalid key or nonce size raises ValueError."""
    key = aes_gcm.generate_key()
    plaintext = b"Data"
    
    # Key too short
    with pytest.raises(ValueError):
        aes_gcm.encrypt(key[:-1], plaintext)
        
    # Nonce too short during decryption
    enc_data = aes_gcm.encrypt(key, plaintext)
    with pytest.raises(ValueError):
        aes_gcm.decrypt(
            key=key,
            ciphertext=enc_data["ciphertext"],
            nonce=enc_data["nonce"][:-1],
            tag=enc_data["tag"]
        )
