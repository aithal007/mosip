# From a green gate to OpenID self-certification

The gate is a **regression** tool. It runs the alpha (non-certification) plans that Inji supports today, and tracks the known issues. OpenID Foundation certification for OID4VCI and OID4VP (open for self-certification since August 2026) counts **only the HAIP profile plans**:
- `oid4vci-1_0-issuer-haip-test-plan`
- `oid4vp-1final-verifier-haip-test-plan`

## 1. Close the readiness gaps

```bash
PYTHONPATH=harness python -m icg readiness
```
When a capability ships, set `"supported": true` for it in `conformance/plans/<component>.json`. Once every capability is supported, `--readiness` runs the HAIP plan as a report-only plan:
```bash
./run-conformance.sh --component verify --readiness
```

## 2. Produce a clean certification run

Certification requires **all** tests to pass with no expected failures and **no compatibility shims**. Before the certification run:
- **Shims:** remove every shim listed in the report (`deploy/gateway/nginx.conf`) and every benchmark entry.
- **Evidence:** REVIEW placeholders need evidence of the verifier's real UI or behaviour. The automated evidence card documents Inji's API verdict. For a submission, reviewers may expect a screenshot of the verifier product, so upload those through the suite UI or `POST /api/log/{id}/images/{placeholder}`.
- **Environment:** run against the exact deployment you certify (public https URL). You can use the hosted suite (`https://www.certification.openid.net`, with `CONFORMANCE_SERVER` and `CONFORMANCE_TOKEN`) or your own instance.

## 3. Build the certification package

Every run keeps the signed plan export zips in `results/<run>/exports/`. The certification package publishes the plan and makes it immutable. Create it with the upstream helper:

```python
# upstream/conformance-suite/scripts/conformance.py
await conformance.create_certification_package(plan_id, output_zip_directory="./")
```
or `POST /api/plan/{planId}/certificationpackage` (multipart, `clientSideData` may be empty for issuer and verifier tests).

## 4. Submit

1. Complete the OpenID Foundation certification request form. The signed *Certification of Conformance* PDF is submitted through the form, not inside the package.
2. Attach the certification package zip.
3. Pay the fee: **USD 700 for members, 3,500 for non-members**, per deployment and per specification (https://openid.net/certification/fees/). Open-source projects can ask the Foundation about a fee waiver. Inji is a Digital Public Good.
4. After approval, the implementation appears on https://openid.net/certification/certified-oid4vci-haip-final/ and https://openid.net/certification/certified-oid4vp-haip-final/.

## Keep it certified

Run the same HAIP plan in CI (`--readiness`) with an empty benchmark. From then on, any regression in a certified profile fails the build before release.
