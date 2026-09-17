# Per-component handoff handling

In issuer and verifier test plans the conformance suite plays the **wallet**. A real wallet needs the system under test to start the interaction: an issuer shows a credential offer QR code, and a verifier shows an authorization request. The suite models this by moving the module to `WAITING` and asking a human to paste a URL. `run-test-plan.py` waits up to 240 s for the module to finish but never performs that step itself.

The **handoff agent** (`harness/icg/agent.py`) runs alongside it:

1. Poll `GET /api/runner/running` for module ids.
2. For each one, `GET /api/info/{id}`. Continue only if `status == WAITING`, and choose the adapter by test name (`oid4vci-*` → Certify, `oid4vp-*` → Verify).
3. `GET /api/runner/{id}` for `exposed` values and `browser` requests (`uriInputRequests`, `uploadsRequired`).
4. Act once per distinct `updated` timestamp, so modules that wait several times (offer, then tx_code, then a second client) are handled step by step.
5. Record every action in `handoff-ledger.json`. Failed actions are retried up to 3 times for the same state.

## Inji Verify (OID4VP verifier plan)

| Step | Call | Notes |
|---|---|---|
| Suite exposes `authorization_endpoint`, requests URI input | — | `https://localhost.emobix.co.uk:8443/test/a/<alias>/authorize` |
| Create the request | `POST {VERIFY_ADMIN_URL}/v2/vp-request` | `clientId = redirect_uri:<response_uri>`, DCQL for `urn:eudi:pid:1`, random 32-char nonce |
| Build the `openid4vp://` query | harness | Same parameters and order as the Inji Verify SDK `getAuthorizationRequestParams`: `client_id, state, response_mode, response_type, nonce, response_uri, dcql_query, client_metadata` |
| Deliver | `GET authorization_endpoint?<query>` | The suite then POSTs a VP token to Inji Verify's `response_uri` |
| Suite asks for evidence (REVIEW placeholder) | `GET /api/log/{id}/images` | Placeholder `src` tells the expected outcome |
| Read Inji's verdict | `GET {VERIFY_ADMIN_URL}/vp-result/{transactionId}` | `vpResultStatus` SUCCESS/FAILED, polled for up to 10 s |
| Upload evidence | `POST /api/log/{id}/images/{placeholder}` | PNG card (rendered without imaging libraries), which finishes the module as REVIEW |

Why `redirect_uri`: Inji Verify 1.0 sends **by-value, unsigned** requests for non-DID client ids and always answers at `<base>/v2/vp-submission/direct-post`. That matches the `redirect_uri` client identifier prefix with `request_method=url_query` and `response_mode=direct_post`, the same profile MOSIP tested manually.

The resolver's verdict follows `ICG_REVIEW_POLICY`:
- `resolve` (default): PASS only if Inji's result matches the expectation.
- `pass`: accept REVIEW results, as upstream CI does.
- `fail`: treat REVIEW as a failure.

## Inji Certify (OID4VCI issuer plan)

| Step | Call | Notes |
|---|---|---|
| Seed (once per run) | `POST {CERTIFY_ADMIN_URL}/credential-configurations` | Registers `InjiConformanceSdJwt` (`dc+sd-jwt`). The compose image only ships `ldp_vc`, which the suite does not test |
| Discover issuer id | `GET {CERTIFY_ADMIN_URL}/.well-known/openid-credential-issuer` | `credential_issuer` is injected as `${CERTIFY_ISSUER}` so metadata URLs match exactly |
| Suite exposes `credential_offer_endpoint` | — | Variant `vci_authorization_code_flow_variant=issuer_initiated`, `vci_grant_type=pre_authorization_code` |
| Mint an offer | `POST {CERTIFY_ADMIN_URL}/pre-authorized-data` | Claims and `tx_code` from `conformance/configs/certify/pre-authorized-offer.json` |
| Deliver | `GET credential_offer_endpoint?credential_offer_uri=<https URI>` | Unwrapped from `openid-credential-offer://?credential_offer_uri=…` |
| tx_code | config `vci.static_tx_code`, or `GET tx_code_endpoint?code=` | The same code is bound to the offer |

After delivery the suite runs the real pre-authorized flow against Certify through the gateway: metadata, token with DPoP, nonce, and credential request with JWT proof.

## Networking

- The suite dereferences every URL from inside its container. Inji is therefore exposed on https origins (`certify.inji.test`, `verify.inji.test`) through the gateway, which is network-aliased on the compose network. The suite accepts any certificate.
- The harness calls Inji's admin APIs from the host (`localhost:8090`, `localhost:8080`) or, inside the api-testrig, at `env.endpoint`.
- In a real MOSIP environment, admin and public URLs are the same https endpoint. Only `conformanceServer` needs to be reachable.
