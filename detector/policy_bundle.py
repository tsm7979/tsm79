"""
Signed policy bundles — control/data-plane separation (architecture sec. 5-6).

The threat: if the policy-authoring surface (control plane / admin UI) is
compromised, an attacker could push malicious policy to the enforcement runtime
(data plane). Defense: the data plane only loads policy that is

    authored (DSL) -> compiled (deterministic IR) -> signed (Ed25519) -> loaded

and it REJECTS any bundle whose signature does not verify against a trusted
operator public key. The control plane can author; only the holder of the
operator private key can make policy the data plane will honour.

This is the same Ed25519 scheme the sovereign overlay uses, so the whole product
has one signature primitive.

Bundle wire format (JSON):
    {
      "ir":        { ...canonical IR... },
      "ir_sha256": "<hex>",                # integrity of the IR bytes
      "pubkey":    "<hex ed25519 pubkey>",
      "signature": "<hex ed25519 sig over canonical IR bytes>",
      "issued_at": <unix seconds>,
      "version":   <monotonic int>
    }

The signature covers the CANONICAL IR bytes (sorted-key, compact JSON) so the
same IR always produces the same signing input on any machine.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# ── Canonicalization ─────────────────────────────────────────────────────────
def canonical_bytes(ir: dict[str, Any]) -> bytes:
    """Deterministic byte encoding of the IR: sorted keys, no whitespace, UTF-8.
    Same IR -> same bytes on every machine -> stable signatures."""
    return json.dumps(ir, sort_keys=True, separators=(",", ":")).encode("utf-8")


def ir_digest(ir: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(ir)).hexdigest()


# ── DSL -> IR compiler ───────────────────────────────────────────────────────
# The DSL is a small, explicit rule language. Each rule:
#   { "id", "priority", "when": {<matchers>}, "action", "reason"?, "target"? }
# Compiling to IR validates structure, normalizes ordering, and freezes a
# deterministic representation the data plane executes.

_VALID_ACTIONS = {"block", "redact", "route_local", "quarantine", "allow"}
_VALID_MATCHERS = {
    "contains_pii", "severity", "risk_score_gte", "user_role",
    "model_prefix", "detector_signal", "known_bad", "obfuscation_gte",
    "any_of", "all_of", "not",
}


class PolicyCompileError(ValueError):
    """Raised when a DSL document is structurally invalid."""


def compile_dsl(doc: dict[str, Any]) -> dict[str, Any]:
    """Compile a DSL policy document into canonical IR. Validates every rule;
    raises PolicyCompileError on any structural problem (fail fast, no partial
    IR ever reaches the signer)."""
    if not isinstance(doc, dict):
        raise PolicyCompileError("policy document must be a mapping")

    rules_in = doc.get("rules")
    if not isinstance(rules_in, list) or not rules_in:
        raise PolicyCompileError("policy must contain a non-empty 'rules' list")

    compiled: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for i, r in enumerate(rules_in):
        if not isinstance(r, dict):
            raise PolicyCompileError(f"rule[{i}] must be a mapping")
        rid = r.get("id")
        if not rid or not isinstance(rid, str):
            raise PolicyCompileError(f"rule[{i}] missing string 'id'")
        if rid in seen_ids:
            raise PolicyCompileError(f"duplicate rule id: {rid}")
        seen_ids.add(rid)

        action = r.get("action")
        if action not in _VALID_ACTIONS:
            raise PolicyCompileError(
                f"rule '{rid}': action must be one of {sorted(_VALID_ACTIONS)}, got {action!r}"
            )
        if action == "route_local" and not r.get("target"):
            raise PolicyCompileError(f"rule '{rid}': route_local requires a 'target'")

        priority = r.get("priority", 100)
        if not isinstance(priority, int):
            raise PolicyCompileError(f"rule '{rid}': priority must be an int")

        when = r.get("when", {})
        _validate_matchers(rid, when)

        compiled.append({
            "id": rid,
            "priority": priority,
            "when": when,
            "action": action,
            **({"reason": str(r["reason"])} if r.get("reason") else {}),
            **({"target": str(r["target"])} if r.get("target") else {}),
        })

    # Deterministic order: by priority asc, then id. The data plane evaluates
    # first-match-wins, so order is part of the contract and must be frozen.
    compiled.sort(key=lambda x: (x["priority"], x["id"]))

    return {
        "schema": "tsm.policy.ir/v1",
        "workspace": str(doc.get("workspace", "default")),
        "rules": compiled,
    }


def _validate_matchers(rid: str, when: Any) -> None:
    if not isinstance(when, dict):
        raise PolicyCompileError(f"rule '{rid}': 'when' must be a mapping")
    for key, val in when.items():
        if key not in _VALID_MATCHERS:
            raise PolicyCompileError(
                f"rule '{rid}': unknown matcher '{key}' "
                f"(valid: {sorted(_VALID_MATCHERS)})"
            )
        if key in ("any_of", "all_of"):
            if not isinstance(val, list):
                raise PolicyCompileError(f"rule '{rid}': '{key}' must be a list")
            for sub in val:
                _validate_matchers(rid, sub)
        elif key == "not":
            _validate_matchers(rid, val)


# ── Signing / verification ───────────────────────────────────────────────────
@dataclass(frozen=True)
class SignedBundle:
    ir: dict[str, Any]
    ir_sha256: str
    pubkey: str
    signature: str
    issued_at: int
    version: int

    def to_json(self) -> str:
        return json.dumps({
            "ir": self.ir,
            "ir_sha256": self.ir_sha256,
            "pubkey": self.pubkey,
            "signature": self.signature,
            "issued_at": self.issued_at,
            "version": self.version,
        }, separators=(",", ":"))

    @staticmethod
    def from_json(s: str) -> "SignedBundle":
        d = json.loads(s)
        return SignedBundle(
            ir=d["ir"], ir_sha256=d["ir_sha256"], pubkey=d["pubkey"],
            signature=d["signature"], issued_at=int(d["issued_at"]),
            version=int(d["version"]),
        )


def sign_bundle(ir: dict[str, Any], private_key: Ed25519PrivateKey,
                *, version: int = 1) -> SignedBundle:
    """Sign compiled IR with an operator private key. Signature covers the
    canonical IR bytes."""
    body = canonical_bytes(ir)
    sig = private_key.sign(body)
    pub = private_key.public_key().public_bytes_raw()
    return SignedBundle(
        ir=ir,
        ir_sha256=hashlib.sha256(body).hexdigest(),
        pubkey=pub.hex(),
        signature=sig.hex(),
        issued_at=int(time.time()),
        version=version,
    )


class PolicyVerifyError(Exception):
    """Raised when a bundle fails verification — the data plane MUST reject it."""


def verify_bundle(bundle: SignedBundle, *, trusted_pubkeys: set[str]) -> dict[str, Any]:
    """Verify a signed bundle against a set of trusted operator pubkeys.
    Returns the IR on success; raises PolicyVerifyError on ANY failure.
    The data plane calls this before loading; a failure means reject + keep
    the last-known-good policy."""
    # 1. Is the signing key one we trust?
    if bundle.pubkey not in trusted_pubkeys:
        raise PolicyVerifyError(
            f"untrusted signing key {bundle.pubkey[:16]}... "
            f"(not in {len(trusted_pubkeys)} trusted keys)"
        )

    # 2. Does the IR digest match (integrity)?
    body = canonical_bytes(bundle.ir)
    actual_digest = hashlib.sha256(body).hexdigest()
    if actual_digest != bundle.ir_sha256:
        raise PolicyVerifyError("ir_sha256 mismatch: IR was altered after signing")

    # 3. Does the signature verify (authenticity)?
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(bundle.pubkey))
        pub.verify(bytes.fromhex(bundle.signature), body)
    except (InvalidSignature, ValueError) as e:
        raise PolicyVerifyError(f"signature verification failed: {e}") from e

    return bundle.ir


# ── End-to-end convenience ───────────────────────────────────────────────────
def author_and_sign(dsl_doc: dict[str, Any], private_key: Ed25519PrivateKey,
                    *, version: int = 1) -> SignedBundle:
    """DSL -> validated IR -> signed bundle, in one call (control-plane side)."""
    ir = compile_dsl(dsl_doc)
    return sign_bundle(ir, private_key, version=version)
