"""
TSM Engine
==========
The Autonomous Trust Engine — the ``AI -> Code -> Human`` triple fail-safe at the
centre of the TSM79 architecture.

    from tsm.engine import TrustEngine, CallableSource, Layer, Verdict, TrustContext, RiskTier
"""
from tsm.engine.adapters import (
    ai_layer,
    code_layer,
    constant_human,
    default_engine,
    human_layer,
    shannon_entropy,
)
from tsm.engine.trust_engine import (
    CallableSource,
    Layer,
    LayerReport,
    LayerSource,
    LayerStatus,
    Mode,
    RiskTier,
    TrustContext,
    TrustDecision,
    TrustEngine,
    Verdict,
    derive_risk,
)

__all__ = [
    # core
    "TrustEngine",
    "TrustContext",
    "TrustDecision",
    "LayerSource",
    "CallableSource",
    "LayerReport",
    "Layer",
    "Verdict",
    "LayerStatus",
    "RiskTier",
    "Mode",
    "derive_risk",
    # adapters
    "code_layer",
    "ai_layer",
    "human_layer",
    "constant_human",
    "default_engine",
    "shannon_entropy",
]
