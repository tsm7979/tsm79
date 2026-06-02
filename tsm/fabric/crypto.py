"""
TSM Fabric — crypto primitives
==============================
Signed, verifiable tokens and hashes for the trust fabric. **Pure standard
library** (``hashlib`` + ``hmac`` + ``secrets``) — no third-party crypto.

The default signer is HMAC-SHA256 (the same primitive behind JWT ``HS256`` and
signed cookies): a standard, well-understood construction, verified in constant
time via :func:`hmac.compare_digest`. We deliberately do **not** hand-roll novel
cryptography — that would be the opposite of "battle-tested".

``Signer`` is a small interface, so an asymmetric backend (Ed25519 via libsodium/
``cryptography``) can be dropped in for self-certifying, third-party-verifiable
identities without changing any caller. Until then the fabric is fully functional
with the symmetric signer.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Optional


def b64u_encode(data: bytes) -> str:
    """URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def new_secret(nbytes: int = 32) -> bytes:
    """A cryptographically secure random secret."""
    return secrets.token_bytes(nbytes)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Signer:
    """Interface: ``sign(bytes) -> bytes`` / ``verify(bytes, bytes) -> bool``."""

    alg: str = "none"
    key_id: str = ""

    def sign(self, data: bytes) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError

    def verify(self, data: bytes, sig: bytes) -> bool:  # pragma: no cover
        raise NotImplementedError


class HmacSigner(Signer):
    """HMAC-SHA256 signer (HS256). Symmetric: the holder of the secret can both
    sign and verify."""

    alg = "HS256"

    def __init__(self, secret: Optional[bytes] = None) -> None:
        if secret is None:
            secret = new_secret()
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        self._secret = secret
        # A public, non-secret identifier for the key (safe to log/share).
        self.key_id = hashlib.sha256(b"tsm-hs256:" + secret).hexdigest()[:16]

    def sign(self, data: bytes) -> bytes:
        return hmac.new(self._secret, data, hashlib.sha256).digest()

    def verify(self, data: bytes, sig: bytes) -> bool:
        return hmac.compare_digest(self.sign(data), sig)


def _canonical(obj: dict) -> bytes:
    """Deterministic JSON encoding (sorted keys, no whitespace) for signing."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sign_token(payload: dict, signer: Signer) -> str:
    """Produce a compact ``header.payload.signature`` token (JWT-shaped)."""
    header = {"alg": signer.alg, "kid": signer.key_id, "typ": "TSM"}
    h = b64u_encode(_canonical(header))
    p = b64u_encode(_canonical(payload))
    signing_input = f"{h}.{p}".encode("ascii")
    sig = b64u_encode(signer.sign(signing_input))
    return f"{h}.{p}.{sig}"


def verify_token(token: str, signer: Signer, *, now: Optional[float] = None) -> Optional[dict]:
    """Verify signature + ``exp``/``nbf``. Returns the payload, or ``None`` if the
    token is malformed, has a bad signature, or is outside its validity window."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    h, p, s = parts
    signing_input = f"{h}.{p}".encode("ascii")
    try:
        sig = b64u_decode(s)
    except Exception:
        return None
    if not signer.verify(signing_input, sig):
        return None
    try:
        payload = json.loads(b64u_decode(p))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    now = time.time() if now is None else now
    exp = payload.get("exp")
    if exp is not None and now > float(exp):
        return None
    nbf = payload.get("nbf")
    if nbf is not None and now < float(nbf):
        return None
    return payload
