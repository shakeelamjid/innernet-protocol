import os
import pytest
from innernet2.crypto import (new_v3_capabilities, parse_read_capability,
                              v3_admin_sign, verify_directory, root_lookup,
                              parse_root)


def test_reader_cannot_sign_directory_and_admin_is_independent():
    reader, admin = new_v3_capabilities()
    root, lookup, version3 = parse_read_capability(reader)
    assert version3 and len(root) == 32
    assert lookup != root_lookup(root)
    record = v3_admin_sign(admin, {'protocol_version': 3, 'sequence': 0}, reader)
    assert verify_directory(lookup, record)
    with pytest.raises(ValueError):
        v3_admin_sign(reader, {'sequence': 1}, reader)
    with pytest.raises(ValueError):
        parse_root(reader)
    another_reader, another_admin = new_v3_capabilities()
    with pytest.raises(ValueError):
        v3_admin_sign(another_admin, {'sequence': 1}, reader)
    with pytest.raises(ValueError):
        parse_read_capability(reader + '=')


def test_v3_mesh_roundtrip_and_reader_not_admin(mesh):
    client, directory, _ = mesh
    source = directory / 'secure-v3-input.bin'
    data = os.urandom(80000)
    source.write_bytes(data)
    result = client.upload_file(source, chunk_bytes=32768, capability_version=3)
    reader, admin = result['capability'], result['admin_capability']
    root, lookup, _ = parse_read_capability(reader)
    assert client.resolve(root, lookup_override=lookup)['sequence'] == 0
    assert not hasattr(client, '_v3_admin')
    restored = directory / 'secure-v3-restored.bin'
    assert client.restore_file(reader, restored)['bytes'] == len(data)
    assert restored.read_bytes() == data
    entry = client.resolve(root, lookup_override=lookup)
    assert verify_directory(lookup, v3_admin_sign(admin, entry, reader))
    with pytest.raises(ValueError):
        v3_admin_sign(reader, entry, reader)
