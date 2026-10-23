"""
Performance Evaluation Suite
Implements Specification Section: §11 (Evaluation Deliverables)
Implements Objectives: O6 (Evaluation)

Measures, on the machine it runs on:
    - AES-256-GCM encryption latency vs. file size
    - CP-ABE DEK wrap latency vs. policy complexity (number of attributes)
    - RSA-OAEP wrap / unwrap and RSA-PSS sign of a 32-byte DEK
    - End-to-end upload envelope preparation vs. file size

`run_quick()` is used by the web client (GET /api/bench) and finishes in about a
second. Running this file directly performs the full sweep and writes CSVs and
matplotlib charts to evaluation/results/:

    python -m evaluation.benchmarks
"""

import os
import csv
import time
import statistics
from client import uploader
from client.crypto import aes_gcm, cpabe, rsa_wrap, hashing
from evaluation import revocation_cost_model

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")


def _time_ms(fn, repeat: int = 5) -> float:
    """Median wall-clock time of fn() in milliseconds (median resists GC/OS jitter)."""
    samples = []
    fn()  # warm-up
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000)
    return round(statistics.median(samples), 4)


def bench_aes(sizes_kb: list[int], repeat: int = 5) -> list[dict]:
    key = aes_gcm.generate_key()
    out = []
    for kb in sizes_kb:
        data = os.urandom(kb * 1024)
        enc = _time_ms(lambda: aes_gcm.encrypt(key, data), repeat)
        ct = aes_gcm.encrypt(key, data)
        dec = _time_ms(lambda: aes_gcm.decrypt(key, ct["ciphertext"], ct["nonce"], ct["tag"]), repeat)
        out.append({"size_kb": kb, "encrypt_ms": enc, "decrypt_ms": dec,
                    "throughput_mb_s": round((kb / 1024) / (enc / 1000), 1) if enc else None})
    return out


def bench_cpabe(attr_counts: list[int], repeat: int = 5) -> list[dict]:
    pk, msk = cpabe.setup()
    dek = aes_gcm.generate_key()
    out = []
    for n in attr_counts:
        attrs = [f"attr{i}_v1" for i in range(n)]
        policy = " and ".join(attrs)
        sk = cpabe.keygen(pk, msk, attrs)
        wrap = _time_ms(lambda: cpabe.encrypt(pk, dek, policy), repeat)
        ct = cpabe.encrypt(pk, dek, policy)
        tk, dk = cpabe.generate_transform_key(pk, sk)
        transform = _time_ms(lambda: cpabe.transform(pk, tk, ct), repeat)
        ct_prime = cpabe.transform(pk, tk, ct)
        client = _time_ms(lambda: cpabe.decrypt_transformed(pk, dk, ct_prime), repeat)
        out.append({"attributes": n, "wrap_ms": wrap, "server_transform_ms": transform, "client_decrypt_ms": client})
    return out


def bench_rsa(repeat: int = 5) -> dict:
    priv, pub = rsa_wrap.generate_key_pair()
    dek = aes_gcm.generate_key()
    wrapped = rsa_wrap.wrap_key(pub, dek)
    digest = hashing.compute_sha256(dek)
    return {
        "wrap_ms": _time_ms(lambda: rsa_wrap.wrap_key(pub, dek), repeat),
        "unwrap_ms": _time_ms(lambda: rsa_wrap.unwrap_key(priv, wrapped), repeat),
        "sign_ms": _time_ms(lambda: rsa_wrap.sign(priv, digest), repeat),
    }


def bench_end_to_end(sizes_kb: list[int], repeat: int = 3) -> list[dict]:
    pk, _ = cpabe.setup()
    priv, _pub = rsa_wrap.generate_key_pair()
    out = []
    for kb in sizes_kb:
        data = os.urandom(kb * 1024)
        ms = _time_ms(lambda: uploader.prepare_envelope(data, "cardiology_v1 and level3_v1", pk, sender_priv_key=priv), repeat)
        out.append({"size_kb": kb, "upload_prepare_ms": ms})
    return out


def run_quick() -> dict:
    """Small sweep used by the live dashboard."""
    return {
        "engine": "simulated" if cpabe.is_simulated() else "charm-bsw07",
        "aes": bench_aes([16, 256, 1024, 4096, 16384], repeat=3),
        # Sub-millisecond operations need more samples for a stable median.
        "cpabe": bench_cpabe([1, 2, 4, 8, 16], repeat=21),
        "rsa": bench_rsa(repeat=9),
        "end_to_end": bench_end_to_end([16, 1024, 8192], repeat=2),
        "revocation": revocation_cost_model.compare([0.1, 1, 10, 100, 1000], files=1000),
    }


def _write_csv(name: str, rows: list[dict]):
    with open(os.path.join(RESULTS_DIR, name), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def run_full():
    """Full sweep: CSVs and PNG charts in evaluation/results/."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    os.makedirs(RESULTS_DIR, exist_ok=True)
    aes = bench_aes([1, 16, 128, 1024, 8192, 65536])
    abe = bench_cpabe([1, 2, 4, 8, 16, 32])
    e2e = bench_end_to_end([1, 16, 128, 1024, 8192, 65536])
    rev = revocation_cost_model.compare([0.1, 1, 10, 100, 1000], files=1000)
    _write_csv("aes_gcm.csv", aes)
    _write_csv("cpabe.csv", abe)
    _write_csv("end_to_end.csv", e2e)
    _write_csv("revocation_cost.csv", rev)

    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
    fig, ax = plt.subplots(figsize=(6, 3.6))
    ax.plot([r["size_kb"] for r in aes], [r["encrypt_ms"] for r in aes], marker="o", color="#0071e3", label="AES-256-GCM encrypt")
    ax.plot([r["size_kb"] for r in e2e], [r["upload_prepare_ms"] for r in e2e], marker="o", color="#86868b", label="Full upload envelope")
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("File size (KB)"); ax.set_ylabel("Latency (ms)"); ax.legend(frameon=False)
    fig.tight_layout(); fig.savefig(os.path.join(RESULTS_DIR, "latency_vs_size.png"), dpi=160)

    fig, ax = plt.subplots(figsize=(6, 3.6))
    ax.plot([r["attributes"] for r in abe], [r["wrap_ms"] for r in abe], marker="o", color="#0071e3", label="CP-ABE wrap")
    ax.plot([r["attributes"] for r in abe], [r["server_transform_ms"] for r in abe], marker="o", color="#86868b", label="Server transform")
    ax.plot([r["attributes"] for r in abe], [r["client_decrypt_ms"] for r in abe], marker="o", color="#34c759", label="Client decrypt")
    ax.set_xlabel("Attributes in policy"); ax.set_ylabel("Latency (ms)"); ax.legend(frameon=False)
    fig.tight_layout(); fig.savefig(os.path.join(RESULTS_DIR, "cpabe_vs_policy.png"), dpi=160)

    fig, ax = plt.subplots(figsize=(6, 3.6))
    ax.plot([r["file_mb"] for r in rev], [r["full_reencrypt_bytes"] for r in rev], marker="o", color="#86868b", label="Re-encrypt every file")
    ax.plot([r["file_mb"] for r in rev], [r["lazy_rewrap_bytes"] for r in rev], marker="o", color="#0071e3", label="Lazy DEK re-wrap")
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("Average file size (MB), 1,000 files"); ax.set_ylabel("Bytes re-processed"); ax.legend(frameon=False)
    fig.tight_layout(); fig.savefig(os.path.join(RESULTS_DIR, "revocation_cost.png"), dpi=160)
    print(f"Wrote results to {RESULTS_DIR}")


if __name__ == "__main__":
    run_full()
