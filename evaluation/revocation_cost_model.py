"""
Revocation Cost Model
Implements Specification Section: §6.4 (Revocation), §11 (Evaluation Deliverables)
Implements Objectives: O4 (Efficient revocation), O7 (Publishable contribution)

Revoking one attribute that guards N files of average size S:

    Naive re-encryption   : bytes = N · S            (download, decrypt, re-encrypt, upload every file)
    Lazy DEK re-wrap      : bytes = N · 32           (only the 32-byte DEK is re-wrapped, on next access)
                            + N · |CP-ABE header|    (the new wrapped-key header that is uploaded)

The ratio N·S / N·(32 + h) grows linearly with file size, so the benefit is
largest exactly where cloud storage is used most: large documents and images.
The model also measures real AES-GCM time for the naive case on this machine.
"""

import os
import json
import time
from client.crypto import aes_gcm, cpabe

DEK_BYTES = 32


def wrapped_header_bytes() -> int:
    """Size of one serialized CP-ABE wrapped DEK (what lazy re-wrap uploads)."""
    pk, _ = cpabe.setup()
    ct = cpabe.encrypt(pk, aes_gcm.generate_key(), "cardiology_v2 and level3_v1")
    return len(json.dumps(ct).encode())


def aes_throughput_mb_s(sample_mb: int = 8) -> float:
    key = aes_gcm.generate_key()
    data = os.urandom(sample_mb * 1024 * 1024)
    t0 = time.perf_counter()
    aes_gcm.encrypt(key, data)
    return sample_mb / max(time.perf_counter() - t0, 1e-9)


def compare(file_sizes_mb: list[float], files: int = 1000) -> list[dict]:
    """Returns one row per average file size comparing both strategies."""
    header = wrapped_header_bytes()
    mb_s = aes_throughput_mb_s(4)
    pk, _ = cpabe.setup()
    dek = aes_gcm.generate_key()
    t0 = time.perf_counter()
    for _ in range(50):
        cpabe.encrypt(pk, dek, "cardiology_v2 and level3_v1")
    rewrap_ms = (time.perf_counter() - t0) * 1000 / 50

    rows = []
    for mb in file_sizes_mb:
        full_bytes = int(files * mb * 1024 * 1024)
        lazy_bytes = files * (DEK_BYTES + header)
        rows.append({
            "file_mb": mb,
            "files": files,
            "full_reencrypt_bytes": full_bytes,
            "lazy_rewrap_bytes": lazy_bytes,
            # x2: decrypt + re-encrypt; transfer time ignored, so this is a lower bound.
            "full_reencrypt_s": round(2 * files * mb / mb_s, 3),
            "lazy_rewrap_s": round(files * rewrap_ms / 1000, 3),
            "reduction_x": round(full_bytes / lazy_bytes, 1),
        })
    return rows


if __name__ == "__main__":
    for row in compare([0.1, 1, 10, 100, 1000]):
        print(row)
