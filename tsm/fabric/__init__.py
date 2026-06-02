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
    new_secret,
    sha256_hex,
    sign_token,
    verify_token,
)
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

# Friendlier alias for the DSL compiler.
parse_policy = parse

__all__ = [
    # crypto
    "Signer", "HmacSigner", "new_secret", "sign_token", "verify_token", "sha256_hex",
    # identity
    "IdentityKind", "Principal", "SessionInfo", "IdentityRegistry",
    # policy
    "parse", "parse_policy", "PolicyProgram", "PolicyOutcome", "Rule", "Action",
    "PolicyParseError",
    # verification
    "Attestation", "AttestationLog",
]
