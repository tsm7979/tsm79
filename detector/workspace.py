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

    @property
    def policy_engine(self) -> PolicyEngine:
        if self._engine is None:
            import detector.policy_engine as _pe
            ws_path = _BASE / self.id / "policy.json"
            ws_path.parent.mkdir(parents=True, exist_ok=True)
            original = _pe._POLICY_PATH
            _pe._POLICY_PATH = ws_path
            self._engine = PolicyEngine()
            _pe._POLICY_PATH = original
        return self._engine

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "org_id": self.org_id, "name": self.name,
                "rate_limit": self.rate_limit, "active": self.active}


class WorkspaceRegistry:
    """In-process registry — persists to ~/.tsm/workspaces/registry.json."""

    _REGISTRY_FILE = _BASE / "registry.json"

    def __init__(self) -> None:
        self._workspaces: dict[str, Workspace] = {}
        self._load()

    def _load(self) -> None:
        if self._REGISTRY_FILE.exists():
            try:
                data = json.loads(self._REGISTRY_FILE.read_text())
                for w in data.get("workspaces", []):
                    self._workspaces[w["id"]] = Workspace(**{k: v for k, v in w.items() if k != "_engine"})
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
        return self._workspaces.get(workspace_id, self._workspaces["default"])

    def create(self, workspace_id: str, org_id: str, name: str, rate_limit: int = 100) -> Workspace:
        ws = Workspace(id=workspace_id, org_id=org_id, name=name, rate_limit=rate_limit)
        self._workspaces[workspace_id] = ws
        self._persist()
        return ws

    def list_all(self) -> list[dict]:
        return [w.to_dict() for w in self._workspaces.values()]

    def delete(self, workspace_id: str) -> bool:
        if workspace_id == "default":
            return False
        removed = workspace_id in self._workspaces
        self._workspaces.pop(workspace_id, None)
        self._persist()
        return removed


# Module-level singleton
registry = WorkspaceRegistry()
