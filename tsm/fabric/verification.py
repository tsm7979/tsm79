"""
TSM Fabric — Verification Engine
================================
"Can this be trusted?" — every consequential action emits a signed **attestation**
recording:

    who · did what · to what · when · why · under which policy

Attestations are **hash-chained** (each carries the previous entry's hash, like a
mini blockchain) so any insertion, deletion, or edit breaks the chain, and each is
**HMAC-signed** so forging one requires the signing key. Together that gives a
tamper-evident, authenticated provenance log — the audit substrate the rest of the
fabric (and external auditors) consume.

Pure standard library (:mod:`tsm.fabric.crypto`).
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import List, Optional, Tuple

from tsm.fabric.crypto import HmacSigner, Signer, b64u_decode, b64u_encode, sha256_hex

_GENESIS = "0" * 64


@dataclass(frozen=True)
class Attestation:
    seq: int
    id: str
    actor: str           # principal id that performed/triggered the action
    subject: str         # what it acted on (request id, resource, path)
    action: str          # what was done (e.g. "ai.request", "route", "block")
    decision: str        # the verdict/outcome (allow, block, quarantine, ...)
    policy_rule: str     # which rule/authority justified it
    reason: str          # human-readable why
    ts: float
    prev_hash: str
    hash: str
    sig: str

    def as_dict(self) -> dict:
        return {
            "seq": self.seq, "id": self.id, "actor": self.actor,
            "subject": self.subject, "action": self.action,
            "decision": self.decision, "policy_rule": self.policy_rule,
            "reason": self.reason, "ts": self.ts, "prev_hash": self.prev_hash,
            "hash": self.hash, "sig": self.sig,
        }


def _body(seq, aid, actor, subject, action, decision, policy_rule, reason, ts, prev_hash) -> bytes:
    """Canonical, deterministic encoding of the signed/hashed fields."""
    import json
    return json.dumps({
        "seq": seq, "id": aid, "actor": actor, "subject": subject,
        "action": action, "decision": decision, "policy_rule": policy_rule,
        "reason": reason, "ts": ts, "prev_hash": prev_hash,
    }, separators=(",", ":"), sort_keys=True).encode("utf-8")


class AttestationLog:
    """Append-only, hash-chained, signed attestation log."""

    def __init__(self, signer: Optional[Signer] = None) -> None:
        self._signer = signer or HmacSigner()
        self._entries: List[Attestation] = []
        self._last_hash = _GENESIS

    @property
    def key_id(self) -> str:
        return self._signer.key_id

    def attest(self, *, actor: str, action: str, subject: str = "",
               decision: str = "", policy_rule: str = "", reason: str = "") -> Attestation:
        seq = len(self._entries)
        aid = uuid.uuid4().hex
        ts = time.time()
        prev = self._last_hash
        digest = sha256_hex(_body(seq, aid, actor, subject, action, decision,
                                  policy_rule, reason, ts, prev))
        sig = b64u_encode(self._signer.sign(digest.encode("ascii")))
        att = Attestation(
            seq=seq, id=aid, actor=actor, subject=subject, action=action,
            decision=decision, policy_rule=policy_rule, reason=reason, ts=ts,
            prev_hash=prev, hash=digest, sig=sig,
        )
        self._entries.append(att)
        self._last_hash = digest
        return att

    def verify_chain(self) -> Tuple[bool, int]:
        """Return ``(ok, index)``. ``ok`` False => tampering at ``index``."""
        prev = _GENESIS
        for i, a in enumerate(self._entries):
            if a.prev_hash != prev:
                return (False, i)
            digest = sha256_hex(_body(a.seq, a.id, a.actor, a.subject, a.action,
                                      a.decision, a.policy_rule, a.reason, a.ts, a.prev_hash))
            if digest != a.hash:
                return (False, i)
            try:
                if not self._signer.verify(a.hash.encode("ascii"), b64u_decode(a.sig)):
                    return (False, i)
            except Exception:
                return (False, i)
            prev = a.hash
        return (True, len(self._entries))

    @property
    def entries(self) -> Tuple[Attestation, ...]:
        return tuple(self._entries)

    def __len__(self) -> int:
        return len(self._entries)
