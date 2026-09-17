"""Inji Conformance Gate (icg).

Drives the OpenID Foundation conformance suite against Inji Certify (OID4VCI issuer)
and Inji Verify (OID4VP verifier), resolves the interactive "handoff" steps the suite
cannot perform on its own, and turns the outcome into benchmark-gated results that the
MOSIP api-testrig (TestNG) and CI can consume.
"""

__version__ = "0.1.0"
