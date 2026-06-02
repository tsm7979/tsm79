"""
TSM Fabric — Identity Engine
============================
"Who is requesting?" — first-class identities for every actor on the fabric:

    human · agent · model · service · device

Each :class:`Principal` carries a kind, a trust score (0–100), and attributes.
The registry issues signed, expiring **sessions** (HS256 tokens) and verifies
them. Trust scores move deterministically in response to signals (a verified
attestation raises trust; a violation lowers it), so downstream engines can gate
on ``identity.trust`` without re-deriving it.

Pure standard library (signing via :mod:`tsm.fabric.crypto`).
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Dict, Optional, Tuple

from tsm.fabric.crypto import HmacSigner, Signer, sign_token, verify_token


class IdentityKind(str, Enum):
    HUMAN = "human"
    AGENT = "agent"
    MODEL = "model"
    SERVICE = "service"
    DEVICE = "device"


# Default starting trust by kind. Agents are least trusted by default — they act
# autonomously and are the easiest thing for an attacker to impersonate or suborn.
_DEFAULT_TRUST: Dict[IdentityKind, float] = {
    IdentityKind.HUMAN: 70.0,
    IdentityKind.SERVICE: 60.0,
    IdentityKind.MODEL: 50.0,
    IdentityKind.DEVICE: 50.0,
    IdentityKind.AGENT: 40.0,
}


def _clamp(x: float) -> float:
    return max(0.0, min(100.0, float(x)))


@dataclass(frozen=True)
class Principal:
    id: str
    kind: IdentityKind
    display: str = ""
    trust_score: float = 50.0
    attributes: Dict[str, Any] = field(default_factory=dict)
    created: float = 0.0

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "display": self.display,
            "trust_score": round(self.trust_score, 2),
            "attributes": dict(self.attributes),
            "created": self.created,
        }


@dataclass(frozen=True)
class SessionInfo:
    principal: Principal
    scopes: Tuple[str, ...]
    issued: float
    expires: float
    token_id: str
    valid: bool = True


class IdentityRegistry:
    """In-memory registry of principals + signed session issuance/verification.

    A single ``Signer`` secures every session; swap in an asymmetric signer for
    third-party-verifiable sessions without touching callers."""

    def __init__(self, signer: Optional[Signer] = None, path: Optional[str] = None) -> None:
        self._signer = signer or HmacSigner()
        self._principals: Dict[str, Principal] = {}
        self._path = path
        if path:
            from tsm.fabric.store import load_json
            for pid, pd in (load_json(path, {}) or {}).items():
                try:
                    self._principals[pid] = Principal(
                        id=pd["id"], kind=IdentityKind(pd["kind"]),
                        display=pd.get("display", ""),
                        trust_score=float(pd.get("trust_score", 50.0)),
                        attributes=dict(pd.get("attributes", {})),
                        created=float(pd.get("created", 0.0)),
                    )
                except (KeyError, ValueError, TypeError):
                    continue

    def _persist(self) -> None:
        if self._path:
            from tsm.fabric.store import save_json
            save_json(self._path, {pid: p.as_dict() for pid, p in self._principals.items()})

    @property
    def key_id(self) -> str:
        return self._signer.key_id

    # ── principals ──────────────────────────────────────────────────────────

    def register(
        self,
        kind,
        display: str = "",
        attributes: Optional[Dict[str, Any]] = None,
        trust_score: Optional[float] = None,
        id: Optional[str] = None,
    ) -> Principal:
        kind = IdentityKind(kind)
        pid = id or f"{kind.value}:{uuid.uuid4().hex[:12]}"
        score = _DEFAULT_TRUST.get(kind, 50.0) if trust_score is None else float(trust_score)
        principal = Principal(
            id=pid,
            kind=kind,
            display=display or pid,
            trust_score=_clamp(score),
            attributes=dict(attributes or {}),
            created=time.time(),
        )
        self._principals[pid] = principal
        self._persist()
        return principal

    def get(self, principal_id: str) -> Optional[Principal]:
        return self._principals.get(principal_id)

    def adjust_trust(self, principal_id: str, delta: float, reason: str = "") -> Principal:
        principal = self._principals[principal_id]
        updated = replace(principal, trust_score=_clamp(principal.trust_score + delta))
        self._principals[principal_id] = updated
        self._persist()
        return updated

    # ── sessions ────────────────────────────────────────────────────────────

    def issue_session(self, principal_id: str, *, ttl: float = 3600.0,
                      scopes: Tuple[str, ...] = ()) -> str:
        principal = self._principals.get(principal_id)
        if principal is None:
            raise KeyError(f"unknown principal: {principal_id}")
        now = time.time()
        payload = {
            "sub": principal.id,
            "kind": principal.kind.value,
            "trust": principal.trust_score,
            "scopes": list(scopes),
            "iat": now,
            "exp": now + ttl,
            "jti": uuid.uuid4().hex,
        }
        return sign_token(payload, self._signer)

    def verify_session(self, token: str, *, now: Optional[float] = None) -> Optional[SessionInfo]:
        payload = verify_token(token, self._signer, now=now)
        if not payload:
            return None
        principal = self._principals.get(payload.get("sub", ""))
        if principal is None:
            return None
        return SessionInfo(
            principal=principal,
            scopes=tuple(payload.get("scopes", [])),
            issued=float(payload.get("iat", 0.0)),
            expires=float(payload.get("exp", 0.0)),
            token_id=payload.get("jti", ""),
            valid=True,
        )
