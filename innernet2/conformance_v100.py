"""Reproducible fixed-key ST80/OB80 primitives test vectors, NOT interoperability."""
from __future__ import annotations
import hashlib
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .native_udp import pub_bytes
from .bulk_v080 import _derive,_aad,_nonce,DOMAIN


def generate_vectors() -> dict:
    """Deterministic ephemeral *test* keys; never use them for deployment."""
    signer=Ed25519PrivateKey.from_private_bytes(bytes([17])*32)
    recipient=Ed25519PrivateKey.from_private_bytes(bytes([34])*32)
    ephem=X25519PrivateKey.from_private_bytes(bytes([51])*32)
    target=X25519PrivateKey.from_private_bytes(bytes([68])*32)
    from cryptography.hazmat.primitives import serialization
    target_pub=target.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    ident=bytes(range(16))
    sender=pub_bytes(signer);to=pub_bytes(recipient)
    key=_derive(ephem,target_pub,ident,sender,to)
    aad=_aad(ident,sender,to)
    plain=b'SYNTHETIC:v100-conformance-vector'
    cipher=ChaCha20Poly1305(key).encrypt(_nonce(0),plain,aad)
    signature=signer.sign(DOMAIN + aad)
    signer.public_key().verify(signature,DOMAIN+aad)
    recovered=ChaCha20Poly1305(key).decrypt(_nonce(0),cipher,aad)
    assert recovered==plain
    return {'version':'INN100-CONFORMANCE-1','warning':'PUBLIC TEST KEYS ONLY',
            'sender_pub_ed25519':sender.hex(),'recipient_pub_ed25519':to.hex(),
            'object_id':ident.hex(),'plain_hex':plain.hex(),
            'derived_key_hex':key.hex(),
            'encrypted_chunk_hex':cipher.hex(),
            'signed_aad_hex':signature.hex(),
            'ciphertext_sha256':hashlib.sha256(cipher).hexdigest()}


def main():
    print(json.dumps(generate_vectors(),indent=2))
if __name__=='__main__':main()
