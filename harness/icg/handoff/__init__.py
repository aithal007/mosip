"""Handoff adapters.

A conformance module that tests an issuer or verifier eventually enters WAITING
because the *system under test* has to act: an issuer has to hand the suite's wallet
a credential offer, a verifier has to hand it an authorization request, and a human
normally uploads a screenshot for REVIEW results. Adapters perform those steps by
calling Inji's real APIs, so the suite's protocol checks run unchanged.

Two adapter styles are supported:

* :class:`HandoffAdapter` subclasses (in-process Python, e.g. ``CertifyHandoff``,
  ``VerifyHandoff``) - direct method calls, same process as the harness.
* :class:`ProtocolHandoffAdapter` wrapping a :class:`ProtocolClient` - NDJSON
  protocol over a subprocess, language-agnostic.
"""

from ..adapter_protocol import ProtocolClient, SubprocessAdapter
from .base import (
    HandoffAdapter,
    HandoffContext,
    Ledger,
    ProtocolAction,
    ProtocolExecuteResult,
    ProtocolHandoffAdapter,
)
from .certify import CertifyHandoff
from .protocol_certify import ProtocolCertifyHandler
from .protocol_verify import ProtocolVerifyHandler
from .verify import VerifyHandoff

ADAPTERS: dict[str, type[HandoffAdapter]] = {
    "certify": CertifyHandoff,
    "verify": VerifyHandoff,
}

PROTOCOL_HANDLERS: dict[str, type] = {
    "certify": ProtocolCertifyHandler,
    "verify": ProtocolVerifyHandler,
}

__all__ = [
    "ADAPTERS",
    "CertifyHandoff",
    "HandoffAdapter",
    "HandoffContext",
    "Ledger",
    "ProtocolAction",
    "ProtocolClient",
    "ProtocolExecuteResult",
    "ProtocolHandoffAdapter",
    "ProtocolCertifyHandler",
    "ProtocolVerifyHandler",
    "PROTOCOL_HANDLERS",
    "SubprocessAdapter",
    "VerifyHandoff",
]
