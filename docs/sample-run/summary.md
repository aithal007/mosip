## Inji Conformance Gate — ✅ PASSED

Run `20260916190050` · mode `combined` · suite `release-v5.2.4`

| Component | Pass | Known issue | Stale | Skip | Regression | Incomplete |
|---|---|---|---|---|---|---|
| Inji Certify · OID4VCI issuer | 4 | 5 | 0 | 0 | 0 | 0 |
| Inji Verify · OID4VP verifier | 11 | 0 | 0 | 0 | 0 | 0 |

### ⚠️ Compatibility shims active in this run

| Component | Shim | Why | Issue |
|---|---|---|---|
| certify | authorization_endpoint added to OAuth authorization server metadata | Inji Certify advertises grant type authorization_code without authorization_endpoint (RFC 8414 section 2). The suite aborts all issuance modules at setup, hiding every other result. | https://github.com/inji/inji-certify/issues/941 |
| certify | credential issuer metadata served at the path-inserted well-known URL | OID4VCI 1.0 section 12.2.2 metadata location for issuers with a path component. | https://github.com/inji/inji-certify/issues/967 |

## Certification readiness (HAIP profile plans)

### Inji Certify (OID4VCI issuer) — `oid4vci-1_0-issuer-haip-test-plan`

The certifiable OID4VCI HAIP profile: authorization code flow with PAR, DPoP sender-constrained tokens and OAuth client attestation.

**Status:** ⛔ blocked by 4 capability gap(s)

| Capability | Supported | Tracking issue | Note |
|---|---|---|---|
| DPoP proofs validated and enforced on token and credential endpoints | ❌ | https://github.com/inji/inji-certify/issues/963 | 1.0.0-alpha.1 accepts the DPoP-variant flow; DPoP proof validation (DpopProofValidator) landed on develop afterwards. |
| client_auth_type=client_attestation (OAuth attestation-based client auth) | ❌ | — | Not implemented in Inji Certify or eSignet as of 1.0.0-alpha.1. |
| authorization_code grant with PAR against the configured AS | ❌ | https://github.com/mosip/esignet/issues/2234 | Depends on eSignet; PAR client assertion currently fails in the suite. |
| Credential issuer metadata at the path-inserted well-known URL | ❌ | https://github.com/inji/inji-certify/issues/967 | The harness gateway serves a compatibility route; the product fix is tracked upstream. |
| Nonce endpoint and jwt proof type (OID4VCI 1.0 Final) | ✅ | — | Available since Inji Certify 1.0.0-alpha.1. |

### Inji Verify (OID4VP verifier) — `oid4vp-1final-verifier-haip-test-plan`

The certifiable OID4VP HAIP profile: signed request objects fetched by reference, x509_hash client ids and encrypted direct_post.jwt responses.

**Status:** ⛔ blocked by 3 capability gap(s)

| Capability | Supported | Tracking issue | Note |
|---|---|---|---|
| response_mode=direct_post.jwt (encrypted authorization responses) | ❌ | https://github.com/inji/inji-verify/issues/2258 | Every verifier on the OIDF HAIP certified list uses direct_post.jwt. |
| client_id_prefix=x509_hash with signed request_uri | ❌ | https://github.com/inji/inji-verify/issues/2238 | Inji Verify 1.0 signs request objects only for decentralized_identifier client ids. |
| credential_format=iso_mdl (mdoc presentations) | ❌ | https://github.com/inji/inji-verify/issues/2271 | Required only for the mdoc variant of the HAIP plan. |
| SD-JWT VC with DCQL query language | ✅ | — | Available since Inji Verify 1.0.0-alpha.1. |

