"""
TSM Fabric — the sovereign trust fabric
=======================================
Trust orchestration for AI, agents, applications and infrastructure. AI is just
the first workload passing through it.

The fabric is built from independent engines that produce the primitives every
other layer consumes:

  * Identity      (``identity``)     — who is requesting?      first-class signed principals
  * Policy        (``policy_dsl``)   — what is allowed?        a real trust language
  * Verification  (``verification``) — can this be trusted?    signed, chained attestations

The AI→Code→Human arbiter (:mod:`tsm.engine`) and the Routing/Recovery engines
are consumers of these primitives.

Everything here is pure standard library — zero runtime dependencies.
"""
from tsm.fabric.crypto import (
    HmacSigner,
    Signer,
    b64u_decode,
    b64u_encode,
    new_secret,
    sha256_hex,
    sign_token,
    verify_token,
)
from tsm.fabric.ed25519 import Ed25519Signer, Ed25519Verifier, generate_keypair
from tsm.fabric.identity import (
    IdentityKind,
    IdentityRegistry,
    Principal,
    SessionInfo,
)
from tsm.fabric.policy_dsl import (
    Action,
    PolicyOutcome,
    PolicyParseError,
    PolicyProgram,
    Rule,
    parse,
)
from tsm.fabric.verification import Attestation, AttestationLog
from tsm.fabric.routing import Destination, RoutingDecision, RoutingEngine, to_destination
from tsm.fabric.recovery import Incident, RecoveryEngine, RecoveryStage, Transition
from tsm.fabric.fabric import FabricResult, TrustFabric
from tsm.fabric.store import persistent_signer

# Friendlier alias for the DSL compiler.
parse_policy = parse

__all__ = [
    # crypto
    "Signer", "HmacSigner", "new_secret", "sign_token", "verify_token", "sha256_hex",
    "b64u_encode", "b64u_decode",
    "Ed25519Signer", "Ed25519Verifier", "generate_keypair",
    # identity
    "IdentityKind", "Principal", "SessionInfo", "IdentityRegistry",
    # policy
    "parse", "parse_policy", "PolicyProgram", "PolicyOutcome", "Rule", "Action",
    "PolicyParseError",
    # verification
    "Attestation", "AttestationLog",
    # routing
    "RoutingEngine", "RoutingDecision", "Destination", "to_destination",
    # recovery
    "RecoveryEngine", "Incident", "RecoveryStage", "Transition",
    # unified facade
    "TrustFabric", "FabricResult",
    # persistence
    "persistent_signer",
]
