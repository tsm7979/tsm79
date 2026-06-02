"""
TSM Fabric — Ed25519 asymmetric signer (RFC 8032)
=================================================
A pure-standard-library Ed25519 implementation (only ``hashlib.sha512``), so the
fabric can issue **self-certifying, third-party-verifiable** identities and
attestations with **zero dependencies**. Validated against the official RFC 8032
§7.1 test vectors (see ``tests/test_ed25519.py``) — this is the standard
algorithm, not novel cryptography.

Why this matters: with the HMAC (HS256) signer, only the secret-holder can verify.
With Ed25519, anyone holding the *public* key can verify a token or attestation
without being able to forge one — the basis for self-certifying identity and
external audit.

⚠️ This is the readable RFC reference implementation: correct and dependency-free,
but **not constant-time**. For high-volume or adversarial production signing, back
the same :class:`Ed25519Signer` interface with libsodium / ``cryptography``.
"""
from __future__ import annotations

import hashlib
from typing import Optional, Tuple

from tsm.fabric.crypto import Signer, new_secret, sha256_hex

# ── RFC 8032 reference field/curve math (Ed25519) ─────────────────────────────

_b = 256
_q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493  # group order


def _h512(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _expmod(base: int, exp: int, mod: int) -> int:
    return pow(base, exp, mod)


def _inv(x: int) -> int:
    return _expmod(x, _q - 2, _q)


_d = -121665 * _inv(121666) % _q
_I = _expmod(2, (_q - 1) // 4, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = _expmod(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = 4 * _inv(5) % _q
_Bx = _xrecover(_By)
_B = (_Bx % _q, _By % _q)


def _edwards(p: Tuple[int, int], qq: Tuple[int, int]) -> Tuple[int, int]:
    x1, y1 = p
    x2, y2 = qq
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return (x3 % _q, y3 % _q)


def _scalarmult(p: Tuple[int, int], e: int) -> Tuple[int, int]:
    # Iterative double-and-add (avoids deep recursion).
    result = (0, 1)
    addend = p
    while e > 0:
        if e & 1:
            result = _edwards(result, addend)
        addend = _edwards(addend, addend)
        e >>= 1
    return result


def _encodeint(y: int) -> bytes:
    return y.to_bytes(_b // 8, "little")


def _encodepoint(p: Tuple[int, int]) -> bytes:
    x, y = p
    val = (y & ((1 << (_b - 1)) - 1)) | ((x & 1) << (_b - 1))
    return val.to_bytes(_b // 8, "little")


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _clamp(h: bytes) -> int:
    return 2 ** (_b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _b - 2))


def _publickey(sk: bytes) -> bytes:
    a = _clamp(_h512(sk))
    return _encodepoint(_scalarmult(_B, a))


def _hint(m: bytes) -> int:
    return int.from_bytes(_h512(m), "little")


def _signature(m: bytes, sk: bytes, pk: bytes) -> bytes:
    h = _h512(sk)
    a = _clamp(h)
    r = _hint(h[_b // 8:_b // 4] + m)
    big_r = _scalarmult(_B, r)
    s = (r + _hint(_encodepoint(big_r) + pk + m) * a) % _L
    return _encodepoint(big_r) + _encodeint(s)


def _isoncurve(p: Tuple[int, int]) -> bool:
    x, y = p
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _q == 0


def _decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _decodepoint(s: bytes) -> Tuple[int, int]:
    y = int.from_bytes(s, "little") & ((1 << (_b - 1)) - 1)
    x = _xrecover(y)
    if (x & 1) != _bit(s, _b - 1):
        x = _q - x
    p = (x, y)
    if not _isoncurve(p):
        raise ValueError("point not on curve")
    return p


def _checkvalid(sig: bytes, m: bytes, pk: bytes) -> bool:
    if len(sig) != _b // 4 or len(pk) != _b // 8:
        return False
    try:
        big_r = _decodepoint(sig[:_b // 8])
        big_a = _decodepoint(pk)
        s = _decodeint(sig[_b // 8:_b // 4])
        h = _hint(_encodepoint(big_r) + pk + m)
        return _scalarmult(_B, s) == _edwards(big_r, _scalarmult(big_a, h))
    except (ValueError, IndexError):
        return False


# ── public API ────────────────────────────────────────────────────────────────

def generate_keypair(seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Return ``(seed, public_key)``. ``seed`` is the 32-byte private key."""
    seed = seed or new_secret(32)
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    return seed, _publickey(seed)


class Ed25519Verifier(Signer):
    """Verify-only: holds just the public key. Cannot forge, only check."""

    alg = "Ed25519"

    def __init__(self, public_key: bytes) -> None:
        if len(public_key) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes")
        self._pub = bytes(public_key)
        self.key_id = sha256_hex(b"ed25519:" + self._pub)[:16]

    @property
    def public_key(self) -> bytes:
        return self._pub

    def sign(self, data: bytes) -> bytes:  # pragma: no cover - intentional
        raise NotImplementedError("Ed25519Verifier is verify-only (no private key)")

    def verify(self, data: bytes, sig: bytes) -> bool:
        return _checkvalid(bytes(sig), bytes(data), self._pub)


class Ed25519Signer(Signer):
    """Asymmetric signer. The public key (and a verify-only :class:`Ed25519Verifier`)
    can be shared so third parties verify without being able to sign."""

    alg = "Ed25519"

    def __init__(self, seed: Optional[bytes] = None) -> None:
        self._seed, self._pub = generate_keypair(seed)
        self.key_id = sha256_hex(b"ed25519:" + self._pub)[:16]

    @property
    def public_key(self) -> bytes:
        return self._pub

    @property
    def seed(self) -> bytes:
        return self._seed

    def sign(self, data: bytes) -> bytes:
        return _signature(bytes(data), self._seed, self._pub)

    def verify(self, data: bytes, sig: bytes) -> bool:
        return _checkvalid(bytes(sig), bytes(data), self._pub)

    def verifier(self) -> Ed25519Verifier:
        """A verify-only handle safe to hand to third parties."""
        return Ed25519Verifier(self._pub)
