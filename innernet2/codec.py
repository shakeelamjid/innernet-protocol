"""Prototype systematic Reed-Solomon erasure coding over GF(256).

Research implementation only. This is not a production cryptographic library.
"""
from __future__ import annotations
import numpy as np

_EXP = [0] * 512
_LOG = [0] * 256
x = 1
for i in range(255):
    _EXP[i] = x
    _LOG[x] = i
    x <<= 1
    if x & 0x100:
        x ^= 0x11D
for i in range(255, 512):
    _EXP[i] = _EXP[i - 255]


def mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("zero has no multiplicative inverse")
    return _EXP[255 - _LOG[a]]


def matmul(a: list[list[int]], b: list[list[int]]) -> list[list[int]]:
    return [[_xor_mul(row, col) for col in zip(*b)] for row in a]


def _xor_mul(a, b) -> int:
    v = 0
    for x, y in zip(a, b):
        v ^= mul(x, y)
    return v


def invert_matrix(m: list[list[int]]) -> list[list[int]]:
    n = len(m)
    if any(len(r) != n for r in m):
        raise ValueError("matrix must be square")
    a = [list(row) + [int(i == j) for j in range(n)] for i, row in enumerate(m)]
    for i in range(n):
        pivot = next((r for r in range(i, n) if a[r][i] != 0), None)
        if pivot is None:
            raise ValueError("singular matrix")
        a[i], a[pivot] = a[pivot], a[i]
        scale = inv(a[i][i])
        a[i] = [mul(v, scale) for v in a[i]]
        for r in range(n):
            if r != i and a[r][i]:
                factor = a[r][i]
                a[r] = [v ^ mul(factor, w) for v, w in zip(a[r], a[i])]
    return [row[n:] for row in a]


def generator(k: int, n: int) -> list[list[int]]:
    if not (1 <= k <= n <= 255):
        raise ValueError("require 1 <= k <= n <= 255")
    vandermonde = []
    for i in range(1, n + 1):
        row, z = [], 1
        for _ in range(k):
            row.append(z)
            z = mul(z, i)
        vandermonde.append(row)
    return matmul(vandermonde, invert_matrix(vandermonde[:k]))


# Multiplication tables make the vector operations practical for a demonstration.
_MULT = np.zeros((256, 256), dtype=np.uint8)
for c in range(1, 256):
    for byte in range(1, 256):
        _MULT[c, byte] = mul(c, byte)


def _combine(coeffs: list[int], arrays: list[np.ndarray]) -> np.ndarray:
    output = np.zeros(len(arrays[0]), dtype=np.uint8)
    for coeff, arr in zip(coeffs, arrays):
        if coeff:
            output ^= _MULT[coeff, arr]
    return output


def encode(data: bytes, k: int, n: int) -> list[bytes]:
    """Return N same-sized shards; any K suffice for recovery."""
    g = generator(k, n)
    size = (len(data) + k - 1) // k
    padded = data.ljust(size * k, b"\0")
    arrays = [np.frombuffer(padded[i * size:(i + 1) * size], dtype=np.uint8) for i in range(k)]
    return [_combine(row, arrays).tobytes() for row in g]


def decode(available: dict[int, bytes], k: int, n: int, length: int) -> bytes:
    """Recover the original bytes from any K valid, indexed shards."""
    if len(available) < k:
        raise ValueError(f"need at least {k} shards; only {len(available)} available")
    selected = sorted(available)[:k]
    if any(not 0 <= i < n for i in selected):
        raise ValueError("invalid shard index")
    sizes = {len(available[i]) for i in selected}
    if len(sizes) != 1:
        raise ValueError("inconsistent shard lengths")
    rows = [generator(k, n)[i] for i in selected]
    inverse = invert_matrix(rows)
    arrays = [np.frombuffer(available[i], dtype=np.uint8) for i in selected]
    return b"".join(_combine(row, arrays).tobytes() for row in inverse)[:length]
