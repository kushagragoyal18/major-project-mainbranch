"""
Outsourced CP-ABE Decryption Transformation Module
Implements Specification Section: §6.3 (Download Flow), §6.4 (Outsourced Decryption), §10 (Security Requirements)
Implements Objectives: O2 (Cryptographic Authorisation), O4 (Efficient Revocation)

This module handles the server-side bilinear pairing calculations.
Given a uploader's CP-ABE ciphertext and a user's transformation key (TK),
the server evaluates the pairings and returns a transformed ciphertext (CT')
re-encrypted under the user's secret scalar 'z'. The server never learns the DEK
or original plaintext.
"""

from client.crypto import cpabe


def perform_transformation(pk: dict, tk: dict, file_record: dict) -> dict:
    """
    Performs the server-side outsourced pairings transform on the file's ABE key wrap.
    
    Args:
        pk (dict): Serialized CP-ABE Public Key parameters.
        tk (dict): Serialized user Transformation Key.
        file_record (dict): The file metadata record from MongoDB, which includes
                            the uploader's CP-ABE ciphertext envelope under "wrapped_dek_abe".
                            
    Returns:
        dict: The serialized transformed ciphertext (ct_prime) containing M^(1/z).
        
    Raises:
        ValueError: If file_record or ABE envelope is malformed.
        PermissionError: If attributes in TK do not satisfy the file's access policy.
    """
    if "wrapped_dek_abe" not in file_record:
        raise ValueError("Malformed file record: missing 'wrapped_dek_abe' field.")
        
    wrapped_dek_abe = file_record["wrapped_dek_abe"]

    # SECURITY: Server runs bilinear pairings using CP-ABE transform.
    # If the user's attributes (embedded inside TK) do not satisfy the ciphertext's policy,
    # the transform will raise a PermissionError.
    ct_prime = cpabe.transform(pk, tk, wrapped_dek_abe)
    
    return ct_prime
