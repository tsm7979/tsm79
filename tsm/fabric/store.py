"""
TSM Fabric — persistence
========================
Durable storage so trust state and the audit trail survive process restarts.
Pure standard library; JSON / JSONL on disk.

  * ``persistent_signer(keyfile)`` — load (or create + save) the HMAC secret so a
    signer is stable across restarts. Without a stable key, previously-issued
    sessions and attestation signatures would no longer verify.
  * ``append_jsonl`` / ``read_jsonl`` — append-only log storage (attestations).
  * ``save_json`` / ``load_json`` — small mutable state (the principal registry),
    written atomically via a temp file + replace.

The key file holds a secret in cleartext (best-effort ``0600``); treat the fabric
state directory as sensitive, the same as any service's key material.
"""
from __future__ import annotations

import json
import os
import pathlib
from typing import Any, List, Optional

from tsm.fabric.crypto import HmacSigner, b64u_decode, b64u_encode, new_secret


def persistent_signer(keyfile: str) -> HmacSigner:
    """Return an HmacSigner whose secret is persisted at ``keyfile`` (created on
    first use), so signatures remain verifiable across restarts."""
    path = pathlib.Path(keyfile)
    if path.exists():
        secret = b64u_decode(path.read_text(encoding="ascii").strip())
    else:
        secret = new_secret()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(b64u_encode(secret), encoding="ascii")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass  # best-effort (e.g. Windows ACLs differ)
    return HmacSigner(secret)


def append_jsonl(path: str, obj: dict) -> None:
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n")


def read_jsonl(path: str) -> List[dict]:
    p = pathlib.Path(path)
    if not p.exists():
        return []
    out: List[dict] = []
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def save_json(path: str, obj: Any) -> None:
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    tmp.replace(p)  # atomic on the same filesystem


def load_json(path: str, default: Optional[Any] = None) -> Any:
    p = pathlib.Path(path)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default
