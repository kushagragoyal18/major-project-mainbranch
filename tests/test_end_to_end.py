import pytest
import base64
from cryptography.exceptions import InvalidTag
from client.crypto import cpabe, rsa_wrap
from client import uploader, downloader

# Test payloads
ORIGINAL_DATA = b"This is confidential healthcare data: Patient Alice has clearance 3."
POLICY = "CARDIOLOGY and LEVEL3"


@pytest.fixture
def crypto_setup():
    """Fixture providing PK, MSK, RSA keypairs for uploader and recipient."""
    pk, msk = cpabe.setup()
    
    # Uploader (Sender) RSA key pair
    uploader_priv, uploader_pub = rsa_wrap.generate_key_pair()
    
    # Recipient (Receiver) RSA key pair
    recipient_priv, recipient_pub = rsa_wrap.generate_key_pair()
    
    return {
        "pk": pk,
        "msk": msk,
        "uploader_priv": uploader_priv,
        "uploader_pub": uploader_pub,
        "recipient_priv": recipient_priv,
        "recipient_pub": recipient_pub
    }


def test_standard_abe_roundtrip(crypto_setup):
    """Verify that uploader and downloader can successfully encrypt and decrypt using CP-ABE."""
    cs = crypto_setup
    
    # Satisfying user attributes
    sk_sat = cpabe.keygen(cs["pk"], cs["msk"], ["cardiology", "level3"])
    
    # Uploader prepares envelope
    envelope = uploader.prepare_envelope(
        file_bytes=ORIGINAL_DATA,
        policy_str=POLICY,
        abe_pk=cs["pk"],
        sender_priv_key=cs["uploader_priv"]
    )
    
    # Downloader decrypts envelope (Method B: Direct ABE)
    decrypted = downloader.decrypt_envelope(
        envelope=envelope,
        abe_pk=cs["pk"],
        abe_sk=sk_sat,
        sender_pub_key=cs["uploader_pub"]
    )
    
    assert decrypted == ORIGINAL_DATA


def test_device_binding_rsa_roundtrip(crypto_setup):
    """Verify that uploader can optionally wrap the DEK under recipient's RSA public key (Tier 3)."""
    cs = crypto_setup
    
    # Uploader prepares envelope with recipient's public key
    envelope = uploader.prepare_envelope(
        file_bytes=ORIGINAL_DATA,
        policy_str=POLICY,
        abe_pk=cs["pk"],
        recipient_pub_key=cs["recipient_pub"],
        sender_priv_key=cs["uploader_priv"]
    )
    
    # Downloader decrypts using recipient's RSA private key (Method C: RSA unwrap)
    decrypted = downloader.decrypt_envelope(
        envelope=envelope,
        abe_pk=cs["pk"],
        recipient_priv_key=cs["recipient_priv"],
        sender_pub_key=cs["uploader_pub"]
    )
    
    assert decrypted == ORIGINAL_DATA


def test_outsourced_transform_roundtrip(crypto_setup):
    """Verify uploader/downloader flow using the server-side outsourced pairings transformation."""
    cs = crypto_setup
    
    # Satisfying ABE key
    sk_sat = cpabe.keygen(cs["pk"], cs["msk"], ["cardiology", "level3"])
    
    # Uploader prepares envelope
    envelope = uploader.prepare_envelope(
        file_bytes=ORIGINAL_DATA,
        policy_str=POLICY,
        abe_pk=cs["pk"],
        sender_priv_key=cs["uploader_priv"]
    )
    
    # Downloader (Client) generates transform key (TK) and local decrypt key (DK)
    tk, dk = cpabe.generate_transform_key(cs["pk"], sk_sat)
    
    # Server performs outsourced pairings transformation on ABE key wrap
    ct_prime = cpabe.transform(cs["pk"], tk, envelope["wrapped_dek_abe"])
    
    # Downloader decrypts using Method A (ct_prime + dk)
    decrypted = downloader.decrypt_envelope(
        envelope=envelope,
        abe_pk=cs["pk"],
        ct_prime=ct_prime,
        dk=dk,
        sender_pub_key=cs["uploader_pub"]
    )
    
    assert decrypted == ORIGINAL_DATA


def test_policy_violation_denial(crypto_setup):
    """Verify that a user who does not satisfy the ABE policy is denied access."""
    cs = crypto_setup
    
    # Unsatisfying ABE key (missing Level 3)
    sk_unsat = cpabe.keygen(cs["pk"], cs["msk"], ["cardiology", "level2"])
    
    # Prepare envelope
    envelope = uploader.prepare_envelope(
        file_bytes=ORIGINAL_DATA,
        policy_str=POLICY,
        abe_pk=cs["pk"],
        sender_priv_key=cs["uploader_priv"]
    )
    
    # Attempting direct ABE decrypt should raise PermissionError
    with pytest.raises(PermissionError):
        downloader.decrypt_envelope(
            envelope=envelope,
            abe_pk=cs["pk"],
            abe_sk=sk_unsat,
            sender_pub_key=cs["uploader_pub"]
        )

    # Attempting to generate a transform key and transform should fail server-side
    tk, dk = cpabe.generate_transform_key(cs["pk"], sk_unsat)
    with pytest.raises(PermissionError):
        cpabe.transform(cs["pk"], tk, envelope["wrapped_dek_abe"])


def test_signature_tampering_early_gate(crypto_setup):
    """Verify that modifying uploader's signature or ciphertext aborts decryption immediately."""
    cs = crypto_setup
    sk_sat = cpabe.keygen(cs["pk"], cs["msk"], ["cardiology", "level3"])
    
    envelope = uploader.prepare_envelope(
        file_bytes=ORIGINAL_DATA,
        policy_str=POLICY,
        abe_pk=cs["pk"],
        sender_priv_key=cs["uploader_priv"]
    )
    
    # Case 1: Tamper with signature
    tampered_envelope_sig = envelope.copy()
    sig_bytes = base64.b64decode(envelope["signature"].encode('utf-8'))
    corrupted_sig = bytearray(sig_bytes)
    corrupted_sig[0] = corrupted_sig[0] ^ 0xFF
    tampered_envelope_sig["signature"] = base64.b64encode(corrupted_sig).decode('utf-8')
    
    with pytest.raises(ValueError, match="Security Violation: Ciphertext signature is invalid"):
        downloader.decrypt_envelope(
            envelope=tampered_envelope_sig,
            abe_pk=cs["pk"],
            abe_sk=sk_sat,
            sender_pub_key=cs["uploader_pub"]
        )

    # Case 2: Tamper with ciphertext (signature check will detect mismatch with cipher hash)
    tampered_envelope_ct = envelope.copy()
    ct_bytes = base64.b64decode(envelope["ciphertext"].encode('utf-8'))
    corrupted_ct = bytearray(ct_bytes)
    corrupted_ct[0] = corrupted_ct[0] ^ 0xFF
    tampered_envelope_ct["ciphertext"] = base64.b64encode(corrupted_ct).decode('utf-8')
    
    with pytest.raises(ValueError, match="Security Violation: Ciphertext signature is invalid"):
        downloader.decrypt_envelope(
            envelope=tampered_envelope_ct,
            abe_pk=cs["pk"],
            abe_sk=sk_sat,
            sender_pub_key=cs["uploader_pub"]
        )


def test_data_tampering_detection_without_sig(crypto_setup):
    """Verify that modifying the ciphertext is caught by the GCM tag when signature verification is not used."""
    cs = crypto_setup
    sk_sat = cpabe.keygen(cs["pk"], cs["msk"], ["cardiology", "level3"])
    
    envelope = uploader.prepare_envelope(
        file_bytes=ORIGINAL_DATA,
        policy_str=POLICY,
        abe_pk=cs["pk"]
        # No signature
    )
    
    # Tamper with ciphertext
    tampered_envelope = envelope.copy()
    ct_bytes = base64.b64decode(envelope["ciphertext"].encode('utf-8'))
    corrupted_ct = bytearray(ct_bytes)
    corrupted_ct[0] = corrupted_ct[0] ^ 0xFF
    tampered_envelope["ciphertext"] = base64.b64encode(corrupted_ct).decode('utf-8')
    
    # AES-GCM decrypt should fail with InvalidTag (which decrypt wrapper turns into ValueError)
    with pytest.raises(ValueError, match="Ciphertext or tag has been tampered with"):
        downloader.decrypt_envelope(
            envelope=tampered_envelope,
            abe_pk=cs["pk"],
            abe_sk=sk_sat
        )


def test_checksum_integrity_validation(crypto_setup):
    """Verify that a modified checksum is detected even if decryption is successful."""
    cs = crypto_setup
    sk_sat = cpabe.keygen(cs["pk"], cs["msk"], ["cardiology", "level3"])
    
    envelope = uploader.prepare_envelope(
        file_bytes=ORIGINAL_DATA,
        policy_str=POLICY,
        abe_pk=cs["pk"]
    )
    
    # Tamper with the checksum in the metadata
    tampered_envelope = envelope.copy()
    tampered_envelope["checksum"] = "a" * 64  # Invalid sha256 hex
    
    with pytest.raises(ValueError, match="Integrity Compromised: Decrypted file checksum mismatch"):
        downloader.decrypt_envelope(
            envelope=tampered_envelope,
            abe_pk=cs["pk"],
            abe_sk=sk_sat
        )
