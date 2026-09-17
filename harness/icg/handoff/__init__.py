"""Handoff adapters.

A conformance module that tests an issuer or verifier eventually enters WAITING
because the *system under test* has to act: an issuer has to hand the suite's wallet
a credential offer, a verifier has to hand it an authorization request, and a human
normally uploads a screenshot for REVIEW results. Adapters perform those steps by
calling Inji's real APIs, so the suite's protocol checks run unchanged.
"""

from .base import HandoffAdapter, HandoffContext, Ledger
from .certify import CertifyHandoff
from .verify import VerifyHandoff

ADAPTERS: dict[str, type[HandoffAdapter]] = {
    "certify": CertifyHandoff,
    "verify": VerifyHandoff,
}

__all__ = ["ADAPTERS", "CertifyHandoff", "HandoffAdapter", "HandoffContext", "Ledger", "VerifyHandoff"]
