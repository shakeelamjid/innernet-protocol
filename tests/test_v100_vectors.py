"""Deterministic vectors: values must be frozen after generation."""
from innernet2.conformance_v100 import generate_vectors

def test_known_answer_vectors():
    record=generate_vectors()
    assert record['version']=='INN100-CONFORMANCE-1'
    assert len(record['sender_pub_ed25519'])==64
    assert len(record['signed_aad_hex'])==128
    assert record['derived_key_hex']== '75e75968271b1012368632e22ccb3589552142705d2a06470c09fa212e02153f'
    assert record['ciphertext_sha256']== '0c48600b025d4ae6d2bf505c8f629b0d7013019f4a021c1e5523b685981ada05'
