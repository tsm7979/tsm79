"""
TSM Fabric — Routing Engine
===========================
"Where should this go?" — turns a trust verdict (+ policy outcome) into a concrete
destination, with **direction-aware, fail-safe fallback**:

    local · remote · human · api · database · quarantine · blocked

The critical safety property: fallback only ever moves toward *safety*. If a
request was kept LOCAL because the data is sensitive and the local model is down,
it must **never** silently fall back to a REMOTE/cloud destination — it falls back
to a human or quarantine. Downgrading (REMOTE→LOCAL) is fine; upgrading exposure
is not. When nothing safe is available, it quarantines rather than fail open.

Pure standard library; decoupled from the engine (accepts a verdict string or any
object with a ``.value``).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Set


class Destination(str, Enum):
    LOCAL = "local"            # on-prem / local model — sensitive data stays put
    REMOTE = "remote"          # remote / cloud model
    HUMAN = "human"            # human review queue
    API = "api"
    DATABASE = "database"
    QUARANTINE = "quarantine"  # isolation sink (always available)
    BLOCKED = "blocked"        # denied — no destination


# Direction-aware fallbacks: every chain moves toward safety, never toward more
# exposure. Note LOCAL never falls back to REMOTE.
_FALLBACKS = {
    Destination.REMOTE: (Destination.LOCAL, Destination.HUMAN, Destination.QUARANTINE),
    Destination.LOCAL: (Destination.HUMAN, Destination.QUARANTINE),
    Destination.HUMAN: (Destination.QUARANTINE,),
    Destination.API: (Destination.HUMAN, Destination.QUARANTINE),
    Destination.DATABASE: (Destination.HUMAN, Destination.QUARANTINE),
    Destination.QUARANTINE: (),
    Destination.BLOCKED: (),
}

# Always-available local sinks.
_SINKS = {Destination.QUARANTINE, Destination.BLOCKED}

_ALIASES = {
    "cloud": Destination.REMOTE, "remote": Destination.REMOTE,
    "local": Destination.LOCAL, "on-prem": Destination.LOCAL, "onprem": Destination.LOCAL,
    "human": Destination.HUMAN, "review": Destination.HUMAN,
    "api": Destination.API, "database": Destination.DATABASE, "db": Destination.DATABASE,
    "quarantine": Destination.QUARANTINE, "isolate": Destination.QUARANTINE,
    "block": Destination.BLOCKED, "blocked": Destination.BLOCKED, "deny": Destination.BLOCKED,
}


def to_destination(name: str) -> Destination:
    return _ALIASES.get(str(name).lower().strip(), Destination.REMOTE)


@dataclass(frozen=True)
class RoutingDecision:
    destination: Destination
    reason: str
    rule: str
    degraded: bool = False   # True if we had to fall back from the primary choice

    def as_dict(self) -> dict:
        return {"destination": self.destination.value, "reason": self.reason,
                "rule": self.rule, "degraded": self.degraded}


class RoutingEngine:
    """Map a verdict (+ optional policy ``route`` target) to a safe destination.

    ``available`` is the set of currently-reachable destinations; ``None`` means
    everything is up. Sinks (quarantine/blocked) are always considered available.
    """

    def __init__(self, available: Optional[Set[Destination]] = None) -> None:
        self._available = available

    def is_available(self, dest: Destination) -> bool:
        if dest in _SINKS:
            return True
        return self._available is None or dest in self._available

    def route(self, *, verdict, policy_outcome=None, context=None) -> RoutingDecision:
        v = getattr(verdict, "value", None) or str(verdict)
        v = v.lower()

        if v == "block":
            return RoutingDecision(Destination.BLOCKED, "denied by trust decision",
                                   "verdict:block")
        if v == "escalate":
            return self._resolve(Destination.HUMAN, "human review required", "verdict:escalate")
        if v == "quarantine":
            return self._resolve(Destination.LOCAL, "isolate from cloud", "verdict:quarantine")

        # ALLOW: honour an explicit policy route target, else default to remote.
        primary, rule = Destination.REMOTE, "verdict:allow"
        if policy_outcome is not None and getattr(policy_outcome, "action", None) == "route" \
                and getattr(policy_outcome, "target", None):
            primary = to_destination(policy_outcome.target)
            rule = f"policy:{policy_outcome.matched_rule or 'route ' + policy_outcome.target}"
        return self._resolve(primary, "allowed", rule)

    def _resolve(self, primary: Destination, reason: str, rule: str) -> RoutingDecision:
        if self.is_available(primary):
            return RoutingDecision(primary, reason, rule, degraded=False)
        for fallback in _FALLBACKS.get(primary, ()):
            if self.is_available(fallback):
                return RoutingDecision(
                    fallback,
                    f"{reason}; {primary.value} unavailable → {fallback.value}",
                    f"{rule}:fallback", degraded=True)
        # Nothing safe reachable — quarantine, never fail open.
        return RoutingDecision(Destination.QUARANTINE,
                               f"{reason}; no safe destination available → quarantine",
                               f"{rule}:fail-safe", degraded=True)
