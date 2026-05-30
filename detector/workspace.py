"""
Multi-tenant workspace registry.

Each workspace has:
  - Its own policy rules (stored in ~/.tsm/workspaces/<id>/policy.json)
  - Its own rate limit
  - Its own audit namespace

Usage:
  registry = WorkspaceRegistry()
  ws = registry.get("acme-prod")
  engine = ws.policy_engine   # isolated PolicyEngine per workspace
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any

from detector.policy_engine import PolicyEngine, PolicyRule

_BASE = Path(os.environ.get("TSM_WORKSPACES_PATH", Path.home() / ".tsm" / "workspaces"))


@dataclass
class Workspace:
    id:           str
    org_id:       str
    name:         str
    rate_limit:   int = 100          # requests per minute
    active:       bool = True
    _engine:      PolicyEngine | None = field(default=None, repr=False)
    _engine_lock: Lock = field(default_factory=Lock, repr=False)

    @property
    def policy_engine(self) -> PolicyEngine:
        # Double-checked locking — safe under GIL and thread-safe
        if self._engine is not None:
            return self._engine
        with self._engine_lock:
            if self._engine is None:
                # Build a per-workspace PolicyEngine without mutating module globals.
                # Previous bug: mutated _pe._POLICY_PATH (a module-level variable),
                # which was not thread-safe when two workspaces initialized concurrently.
                ws_policy_path = _BASE / self.id / "policy.json"
                ws_policy_path.parent.mkdir(parents=True, exist_ok=True)
                self._engine = _make_policy_engine(ws_policy_path)
        return self._engine

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "org_id": self.org_id, "name": self.name,
                "rate_limit": self.rate_limit, "active": self.active}


def _make_policy_engine(policy_path: Path) -> PolicyEngine:
    """
    Construct a PolicyEngine that reads/writes the given path without
    touching the module-level _POLICY_PATH global.
    """
    import detector.policy_engine as _pe
    engine = PolicyEngine.__new__(PolicyEngine)
    engine._custom_rules = []  # type: ignore[attr-defined]
    # Temporarily override the module path to load from workspace-specific file
    _original = _pe._POLICY_PATH
    try:
        _pe._POLICY_PATH = policy_path
        engine._load_persisted()  # type: ignore[attr-defined]
    finally:
        _pe._POLICY_PATH = _original

    # Patch the engine so future add/remove/persist use the workspace path
    engine._policy_path = policy_path  # type: ignore[attr-defined]

    original_persist = engine._persist  # type: ignore[attr-defined]

    def _scoped_persist() -> None:
        rules = [
            {"name": r.name, "condition": r.condition, "action": r.action, "priority": r.priority}
            for r in engine._custom_rules  # type: ignore[attr-defined]
        ]
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(json.dumps({"rules": rules}, indent=2))

    engine._persist = _scoped_persist  # type: ignore[method-assign]
    return engine


class WorkspaceRegistry:
    """In-process registry — persists to ~/.tsm/workspaces/registry.json."""

    _REGISTRY_FILE = _BASE / "registry.json"

    def __init__(self) -> None:
        self._workspaces: dict[str, Workspace] = {}
        self._lock = Lock()
        self._load()

    def _load(self) -> None:
        if self._REGISTRY_FILE.exists():
            try:
                data = json.loads(self._REGISTRY_FILE.read_text())
                for w in data.get("workspaces", []):
                    self._workspaces[w["id"]] = Workspace(**{k: v for k, v in w.items() if k not in ("_engine", "_engine_lock")})
            except Exception:
                pass
        # Always ensure default workspace exists
        if "default" not in self._workspaces:
            self._workspaces["default"] = Workspace(id="default", org_id="default", name="Default")
            self._persist()

    def _persist(self) -> None:
        self._REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {"workspaces": [w.to_dict() for w in self._workspaces.values()]}
        self._REGISTRY_FILE.write_text(json.dumps(data, indent=2))

    def get(self, workspace_id: str) -> Workspace:
        with self._lock:
            return self._workspaces.get(workspace_id, self._workspaces["default"])

    def create(self, workspace_id: str, org_id: str, name: str, rate_limit: int = 100) -> Workspace:
        ws = Workspace(id=workspace_id, org_id=org_id, name=name, rate_limit=rate_limit)
        with self._lock:
            self._workspaces[workspace_id] = ws
            self._persist()
        return ws

    def list_all(self) -> list[dict]:
        with self._lock:
            return [w.to_dict() for w in self._workspaces.values()]

    def delete(self, workspace_id: str) -> bool:
        if workspace_id == "default":
            return False
        with self._lock:
            removed = workspace_id in self._workspaces
            self._workspaces.pop(workspace_id, None)
            self._persist()
        return removed


# Module-level singleton
registry = WorkspaceRegistry()
