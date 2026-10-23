import pytest
from client.crypto import cpabe
from client.crypto import cpabe_simulated

# We will test both the active cpabe wrapper and the cpabe_simulated module explicitly
# to ensure they maintain identical APIs and pass the exact same correctness checks.
modules_to_test = [cpabe_simulated]
if not cpabe.is_simulated():
    modules_to_test.append(cpabe)


@pytest.mark.parametrize("crypto_mod", modules_to_test)
def test_setup(crypto_mod):
    """Verify setup produces public parameters (PK) and master secret key (MSK)."""
    pk, msk = crypto_mod.setup()
    assert isinstance(pk, dict)
    assert isinstance(msk, dict)
    assert pk["type"] in ["simulated_pk", "real_pk"]
    assert msk["type"] in ["simulated_msk", "real_msk"]


@pytest.mark.parametrize("crypto_mod", modules_to_test)
def test_keygen(crypto_mod):
    """Verify keygen generates a secret key (SK) containing user attributes."""
    pk, msk = crypto_mod.setup()
    attrs = ["CARDIOLOGY", "LEVEL3"]
    sk = crypto_mod.keygen(pk, msk, attrs)
    
    assert isinstance(sk, dict)
    # The attributes should be present and normalized in the key dict
    sk_attrs = [a.upper() for a in sk["attributes"]]
    assert "CARDIOLOGY" in sk_attrs
    assert "LEVEL3" in sk_attrs


@pytest.mark.parametrize("crypto_mod", modules_to_test)
def test_encrypt_decrypt_satisfied(crypto_mod):
    """Verify that a user who satisfies the access policy can decrypt the key."""
    pk, msk = crypto_mod.setup()
    message = b"symmetric-dek-bytes-32-length-ok"
    policy = "(CARDIOLOGY and LEVEL3) or ADMIN"
    
    # Encrypt
    ct = crypto_mod.encrypt(pk, message, policy)
    assert isinstance(ct, dict)
    assert ct["policy"] == policy
    
    # Decrypt with satisfying attributes (Cardiology + Level 3)
    sk_cardio_l3 = crypto_mod.keygen(pk, msk, ["Cardiology", "level3"])
    decrypted = crypto_mod.decrypt(pk, sk_cardio_l3, ct)
    assert decrypted == message

    # Decrypt with satisfying attributes (Admin)
    sk_admin = crypto_mod.keygen(pk, msk, ["admin"])
    decrypted_admin = crypto_mod.decrypt(pk, sk_admin, ct)
    assert decrypted_admin == message


@pytest.mark.parametrize("crypto_mod", modules_to_test)
def test_encrypt_decrypt_unsatisfied(crypto_mod):
    """Verify that a user who does not satisfy the policy is denied decryption."""
    pk, msk = crypto_mod.setup()
    message = b"symmetric-dek-bytes-32-length-ok"
    policy = "CARDIOLOGY and LEVEL3"
    
    ct = crypto_mod.encrypt(pk, message, policy)
    
    # Cardiology but not Level 3
    sk_cardio_only = crypto_mod.keygen(pk, msk, ["cardiology", "level2"])
    with pytest.raises(PermissionError):
        crypto_mod.decrypt(pk, sk_cardio_only, ct)

    # Admin (not satisfying this policy)
    sk_admin = crypto_mod.keygen(pk, msk, ["admin"])
    with pytest.raises(PermissionError):
        crypto_mod.decrypt(pk, sk_admin, ct)


@pytest.mark.parametrize("crypto_mod", modules_to_test)
def test_outsourced_decryption_flow(crypto_mod):
    """Verify that the outsourced decryption transformation works and client decrypts correctly."""
    pk, msk = crypto_mod.setup()
    message = b"symmetric-dek-bytes-32-length-ok"
    policy = "CARDIOLOGY and LEVEL3"
    
    ct = crypto_mod.encrypt(pk, message, policy)
    
    # Satisfying user: Cardiology + Level 3
    sk = crypto_mod.keygen(pk, msk, ["cardiology", "level3"])
    
    # Step 1: Client generates transformation key (TK) and local decryption key (DK)
    tk, dk = crypto_mod.generate_transform_key(pk, sk)
    assert isinstance(tk, dict)
    assert isinstance(dk, dict)
    
    # Step 2: Server performs transformation (offloaded bilinear pairings)
    ct_prime = crypto_mod.transform(pk, tk, ct)
    assert isinstance(ct_prime, dict)
    assert ct_prime["type"] in ["simulated_ct_prime", "real_ct_prime"]
    
    # Step 3: Client does lightweight local decryption using DK
    decrypted = crypto_mod.decrypt_transformed(pk, dk, ct_prime)
    assert decrypted == message


@pytest.mark.parametrize("crypto_mod", modules_to_test)
def test_outsourced_decryption_unsatisfied(crypto_mod):
    """Verify that the server-side transformation fails if attributes do not satisfy policy."""
    pk, msk = crypto_mod.setup()
    message = b"symmetric-dek-bytes-32-length-ok"
    policy = "CARDIOLOGY and LEVEL3"
    
    ct = crypto_mod.encrypt(pk, message, policy)
    
    # Unsatisfying user: Cardiology only
    sk_unsat = crypto_mod.keygen(pk, msk, ["cardiology"])
    tk_unsat, _ = crypto_mod.generate_transform_key(pk, sk_unsat)
    
    # Server transformation should raise PermissionError
    with pytest.raises(PermissionError):
        crypto_mod.transform(pk, tk_unsat, ct)


def test_simulated_policy_evaluator():
    """Directly test the simulated policy evaluator over various boolean expressions."""
    from client.crypto.cpabe_simulated import evaluate_policy
    
    attrs = ["cardiology", "level3", "admin"]
    
    assert evaluate_policy("cardiology", attrs) is True
    assert evaluate_policy("CARDIOLOGY", attrs) is True
    assert evaluate_policy("neurology", attrs) is False
    
    assert evaluate_policy("cardiology and level3", attrs) is True
    assert evaluate_policy("cardiology and level4", attrs) is False
    
    assert evaluate_policy("cardiology or level4", attrs) is True
    assert evaluate_policy("neurology or orthopedics", attrs) is False
    
    assert evaluate_policy("(cardiology and level4) or admin", attrs) is True
    assert evaluate_policy("(neurology or orthopedics) and admin", attrs) is False
    
    assert evaluate_policy("((cardiology and level3) or admin) and level3", attrs) is True
    assert evaluate_policy("((cardiology and level4) or admin) and level4", attrs) is False
