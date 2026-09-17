# Findings from automated runs against Inji 1.0.0-alpha.1

These came out of the first automated runs on 16 Sep 2026: suite `release-v5.2.4`, images `injistack/inji-certify-with-plugins:1.0.0-alpha.1` and `injistack/inji-verify-service:1.0.0-alpha.1`. Evidence is in [sample-run/](sample-run/) and in the suite logs linked from the report.

## Inji Certify: OID4VCI issuer plan (SD-JWT VC, pre-authorized code)

| # | Module | Observation | Spec | Status in harness |
|---|---|---|---|---|
| C1 | `issuer-happy-flow` | A credential request carrying an unrecognised parameter fails JSON binding (`Unrecognized field … CredentialRequest, not marked as ignorable`). Error rendering then fails too (`HttpMediaTypeNotAcceptableException`), giving **HTTP 500** | Extension parameters must not break processing; errors use the credential error response | benchmark `KNOWN_ISSUE` |
| C2 | `issuer-happy-flow-additional-requests` | JWT proof with `iss = client_id` is rejected: `JWT iss claim has value inji-conformance-wallet, must be <empty>` | OID4VCI 1.0 App. F.1: omit `iss` only for *anonymous* pre-authorized access | benchmark `KNOWN_ISSUE` |
| C3 | `issuer-fail-unknown-credential-configuration` | Rejected, but without the `unknown_credential_configuration` error code | OID4VCI 1.0 §8.3.1.2 | benchmark `KNOWN_ISSUE` |
| C4 | `issuer-fail-on-access-token-in-query` | Access token in the URI query is not rejected with the expected status | RFC 6750 §2.3, FAPI 2.0 | benchmark `KNOWN_ISSUE` |
| C5 | `issuer-metadata-test-signed` | Signed issuer metadata (`Accept: application/jwt`) is not supported | OID4VCI 1.0 §12.2.3 | benchmark `KNOWN_ISSUE` |
| C6 | all issuance modules | OAuth AS metadata advertises `authorization_code` but has no `authorization_endpoint`, so the suite aborts setup | RFC 8414 §2 | gateway **shim** (disclosed in every report) |
| C7 | `issuer-metadata-test` | A credential configuration without a background image is serialised as `"background_image": null` (object required when present) | OID4VCI 1.0 App. A.1 metadata schema | worked around in the test credential config; should omit nulls |
| C8 | — | Metadata is not served at the path-inserted well-known URL for issuer ids with a path | OID4VCI 1.0 §12.2.2 ([#967](https://github.com/inji/inji-certify/issues/967)) | gateway **shim** |

Passing: metadata validation, rejection of an invalid `c_nonce`, rejection of an invalid proof signature, rejection of a missing proof.

## Inji Verify: OID4VP verifier plan (SD-JWT VC, redirect_uri, direct_post)

All 11 applicable modules pass. The 7 REVIEW results were resolved automatically: Inji Verify reported `SUCCESS` for the 4 valid presentations and `FAILED` for the tampered ones (KB-JWT signature, credential signature, sd_hash).

| # | Observation | Impact |
|---|---|---|
| V1 | `docker-compose/db-init/init.sql` on `release-1.0.x` predates the `vp_submission.response_code*` columns the 1.0.0-alpha.1 service queries, so every `direct_post` returns **HTTP 500** (`column v1_0.response_code does not exist`). The canonical `db_scripts/inji_verify/ddl` is correct | Anyone following the repo's compose setup gets a broken verifier. The harness initialises the database from the canonical DDL |

## Certification readiness

`python -m icg readiness` lists what blocks the HAIP profile plans, which are the only ones that count for OpenID self-certification:
- Verify needs `direct_post.jwt`, `x509_hash` signed requests and mdoc.
- Certify needs enforced DPoP, client attestation, the authorization code flow with PAR, and the path-inserted metadata URL.
