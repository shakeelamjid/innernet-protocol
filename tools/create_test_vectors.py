"""Creates PUBLIC known-key interoperability vectors (never use keys for real data)."""
from __future__ import annotations

import json
from pathlib import Path

from innernet2 import codec
from innernet2.crypto import (derive, digest, encode_root, encrypt_chunk, encrypt_metadata,
                              interleave, lookup_id_from_public, new_root,
                              public_key_bytes, root_lookup, sign_directory, signing_key)


def create():
    root = bytes(range(32))  # intentionally public, non-random known test secret
    object_id = bytes(range(16))
    plaintext = bytes(range(256)) * 64
    ciphertext = encrypt_chunk(root, object_id, 0, plaintext)
    mixed = interleave(ciphertext, derive(root, "data/interleave/0"), 4096)
    shards = codec.encode(mixed, 4, 6)
    manifest = {
        "protocol_version": 2,
        "object_id": object_id.hex(),
        "filename": "test-vector.bin",
        "total_bytes": len(plaintext),
        "plaintext_sha256": digest(plaintext),
        "chunk_bytes": 1048576,
        "data_cell": 4096,
        "k": 4,
        "n": 6,
        "chunks": [{"fragments": [
            {"node": f"node-{i+1:02d}", "sha256": digest(shard), "bytes": len(shard)}
            for i, shard in enumerate(shards)
        ]}]
    }
    meta_cipher = encrypt_metadata(root, manifest, 0)
    meta_mixed = interleave(meta_cipher, derive(root, "metadata/interleave/0"), 64)
    index_shards = codec.encode(meta_mixed, 2, 3)
    index_locators = [{"node": f"node-{i+7:02d}", "sha256": digest(shard), "bytes": len(shard)}
                      for i, shard in enumerate(index_shards)]
    signed = sign_directory(root, {"protocol_version": 2, "sequence": 0,
                                   "cipher_length": len(meta_cipher),
                                   "index_cell": 64, "index_k": 2, "index_n": 3,
                                   "fragments": index_locators})
    return {"warning": "All keys here are public test material; never use for real storage.",
            "vector_version": 2, "root_secret_hex": root.hex(), "root_capability": encode_root(root),
            "root_lookup_id": root_lookup(root), "root_ed25519_public_key": public_key_bytes(signing_key(root).public_key()).hex(),
            "object_id": object_id.hex(), "input_size": len(plaintext),
            "input_sha256": digest(plaintext), "ciphertext_length": len(ciphertext),
            "ciphertext_sha256": digest(ciphertext), "ciphertext_first_32_hex": ciphertext[:32].hex(),
            "mixed_length": len(mixed), "mixed_sha256": digest(mixed),
            "data_shard_sha256": [digest(shard) for shard in shards],
            "metadata_ciphertext_length": len(meta_cipher), "metadata_ciphertext_sha256": digest(meta_cipher),
            "metadata_shard_sha256": [digest(shard) for shard in index_shards],
            "signed_root_record": signed}


if __name__ == "__main__":
    print(json.dumps(create(), indent=2))
