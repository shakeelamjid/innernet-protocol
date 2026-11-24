"""Local CPU microbenchmark. NOT a VPN or public-network performance result."""
from __future__ import annotations

import json
import os
import secrets
import statistics
import time
from datetime import datetime, timezone

from innernet2 import codec
from innernet2.crypto import (derive, new_root, encrypt_chunk, decrypt_chunk,
                              interleave, deinterleave)


def run(size_mib=8, chunk_mib=1, k=4, n=6):
    blob = os.urandom(size_mib * 1048576)
    object_id = secrets.token_bytes(16)
    root = new_root()
    encode_seconds = 0.0
    decode_seconds = 0.0
    encrypt_seconds = 0.0
    decrypt_seconds = 0.0
    mix_seconds = 0.0
    unmix_seconds = 0.0
    bytes_stored = 0
    result = bytearray()
    for idx in range(0, len(blob), chunk_mib * 1048576):
        chunk = blob[idx: idx + chunk_mib * 1048576]
        index = idx // (chunk_mib * 1048576)
        start = time.perf_counter()
        ciphertext = encrypt_chunk(root, object_id, index, chunk)
        encrypt_seconds += time.perf_counter() - start
        start = time.perf_counter()
        scrambled = interleave(ciphertext, derive(root, f"data/interleave/{index}"), 4096)
        mix_seconds += time.perf_counter() - start
        start = time.perf_counter()
        shards = codec.encode(scrambled, k, n)
        encode_seconds += time.perf_counter() - start
        bytes_stored += sum(map(len, shards))
        start = time.perf_counter()
        recovered = codec.decode({j: shards[j] for j in range(k)}, k, n, len(scrambled))
        decode_seconds += time.perf_counter() - start
        start = time.perf_counter()
        cipher = deinterleave(recovered, derive(root, f"data/interleave/{index}"), 4096, len(ciphertext))
        unmix_seconds += time.perf_counter() - start
        start = time.perf_counter()
        plain = decrypt_chunk(root, object_id, index, cipher, len(chunk))
        decrypt_seconds += time.perf_counter() - start
        result.extend(plain)
    assert result == blob
    size_mib_real = len(blob) / 1048576
    timing = {"encrypt": encrypt_seconds, "interleave": mix_seconds, "erasure_encode": encode_seconds,
              "erasure_decode": decode_seconds, "deinterleave": unmix_seconds, "decrypt": decrypt_seconds}
    return {"benchmark": "INNERnet local CPU/NumPy prototype microbenchmark",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "input_mebibytes": size_mib_real, "chunk_mebibytes": chunk_mib,
            "data_profile": f"{k}-of-{n}", "codec": "unreviewed Python/NumPy reference",
            "network_included": False, "file_overhead_ratio": round(bytes_stored / len(blob), 5),
            "phase_seconds": {name: round(v, 6) for name, v in timing.items()},
            "phase_mebibytes_per_second": {name: round(size_mib_real / v, 2) for name, v in timing.items()},
            "total_seconds": round(sum(timing.values()), 6),
            "pipeline_mebibytes_per_second": round(size_mib_real / sum(timing.values()), 2),
            "roundtrip_verified": True}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
