# Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Exit code 2, "Gating plan … produced no results" | `run-test-plan.py` could not create the plan | Read `results/<run>/logs/<component>-run-test-plan.log`. Typical causes are a config rejected by the suite or wrong variant names |
| `FileNotFoundError: 'C'` in the run-test-plan log | An absolute Windows path was passed to run-test-plan.py, whose grammar uses `:` for module lists | Already handled: configs are passed relative to the scripts directory. Keep `results/` on the same drive as `upstream/` |
| Suite not ready / `wait` times out | Suite containers still starting, or port 8443 in use | `docker compose -p inji-conformance ps`, then `logs suite-server`. Free port 8443 |
| `localhost.emobix.co.uk` does not resolve | Offline or DNS filtering | Add `127.0.0.1 localhost.emobix.co.uk` to the hosts file |
| Gateway container exits: `host not found in upstream` | Old gateway config resolving upstreams at start | Use the repository `deploy/gateway/nginx.conf` (runtime DNS via `resolver 127.0.0.11`) |
| Suite gets `502` from `certify.inji.test` / `verify.inji.test` | That component's profile is not running, or it is still starting | `./run-conformance.sh --component …` starts the right profile. Check `docker compose … ps` health |
| Verify modules fail with `EnsureHttpStatusCodeIs200 … 500` and the service logs show `column v1_0.response_code does not exist` | Database created from the stale `docker-compose/db-init/init.sql` | Use the repo compose (canonical DDL). Reset the volume with `docker volume rm inji-conformance_verify-db` |
| Verify modules stay `WAITING` and then fail | Handoff failed (Verify API unreachable from the harness, or wrong `VERIFY_ADMIN_URL`) | `handoff-ledger.json` has `lastError`. Check `curl $VERIFY_ADMIN_URL/actuator/health` |
| REVIEW results are `INCOMPLETE` "no automated evidence" | The agent could not upload evidence, or `ICG_REVIEW_POLICY=resolve` with no transaction | Check the ledger for `review-evidence-uploaded` events. Use `ICG_REVIEW_POLICY=pass` only for exploratory runs |
| Certify seeding fails | Certify not healthy yet, or the `CERTIFY_VC_SIGN_EC_R1` key policy is missing in a custom database | Run `python -m icg seed-certify` after health is green. The compose `certify_init.sql` includes the key policy |
| Certify modules INTERRUPTED at `CheckServerConfiguration: authorization_endpoint` | Gateway shim not active (for example with `--no-up` against another deployment) | Expected without the shim: the module is classified against the benchmark. Enable the shim or record the gap |
| `VCICredentialIssuerMetadataValidation … background_image null` | A credential configuration without `background_image` | Include a display `background_image` (see `conformance/configs/certify/sd-jwt-credential-config.json`) |
| Plan aborted "3 consecutive test modules failed" | Upstream safety stop | The harness sets `CONFORMANCE_MAX_CONSECUTIVE_FAILURES=100`. Set it lower to restore the upstream behaviour |
| Stale data between runs | Suite MongoDB and Inji Postgres volumes persist | `./run-conformance.sh … --down` removes containers and volumes |
| Windows console `UnicodeEncodeError` | cp1252 console | The CLI switches stdout to UTF-8. With older Python, set `PYTHONIOENCODING=utf-8` |
| Java bridge: "Harness not found" | `conformanceHarnessHome` does not contain `harness/icg` | Set the property or env var. In the layered image it is `/home/inji/conformance-harness` |
