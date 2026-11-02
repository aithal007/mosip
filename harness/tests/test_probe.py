import httpx

from icg.probe import probe_preauth_replay, probe_unknown_configuration, probe_wrong_tx_code
from icg.settings import Settings


def settings():
    return Settings.from_env()


def client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def make_handler(*, reuse_ok: bool, tx_ok: bool = False):
    used = set()

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/pre-authorized-data"):
            body = request.content.decode()
            if "does-not-exist" in body:
                return httpx.Response(400, json={"error": "unknown"})
            return httpx.Response(200, json={"credential_offer_uri": "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fi.test%2Foffer%2F1"})
        if path == "/offer/1":
            return httpx.Response(200, json={"grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code": {"pre-authorized_code": "CODE"}}})
        if path.endswith("/oauth-authorization-server"):
            return httpx.Response(200, json={"token_endpoint": "https://i.test/token"})
        if path == "/token":
            form = request.content.decode()
            if "tx_code=000000" in form:
                return httpx.Response(200 if tx_ok else 400, json={})
            if "CODE" in form and "CODE" in used and not reuse_ok:
                return httpx.Response(400, json={"error": "invalid_grant"})
            used.add("CODE")
            return httpx.Response(200, json={"access_token": "t"})
        return httpx.Response(404)

    return handler


def test_unknown_configuration_rejected_passes():
    assert probe_unknown_configuration(client(make_handler(reuse_ok=False)), settings()).status == "PASS"


def test_replay_rejected_passes_and_accepted_fails():
    assert probe_preauth_replay(client(make_handler(reuse_ok=False)), settings()).status == "PASS"
    assert probe_preauth_replay(client(make_handler(reuse_ok=True)), settings()).status == "FAIL"


def test_wrong_tx_code():
    assert probe_wrong_tx_code(client(make_handler(reuse_ok=False)), settings()).status == "PASS"
    assert probe_wrong_tx_code(client(make_handler(reuse_ok=False, tx_ok=True)), settings()).status == "FAIL"


def test_corpus_probe_is_inconclusive_when_control_not_accepted(monkeypatch):
    from icg import probe
    from icg.handoff.verify import VerifyHandoff

    monkeypatch.setattr(VerifyHandoff, "_create_vp_request", lambda self, nonce=None: {"requestId": "r", "transactionId": "t"})
    monkeypatch.setattr(VerifyHandoff, "_fetch_vp_result", lambda self, tid, attempts=10, delay=1.0: ("FAILED", {}))
    out = probe.probe_sdjwt_corpus(client(lambda r: httpx.Response(200)), settings())
    assert [r.status for r in out] == ["SKIP"] and "inconclusive" in out[0].detail


def test_corpus_probe_flags_accepted_tampering(monkeypatch):
    from icg import probe
    from icg.handoff.verify import VerifyHandoff

    monkeypatch.setattr(VerifyHandoff, "_create_vp_request", lambda self, nonce=None: {"requestId": "r", "transactionId": "t"})
    monkeypatch.setattr(VerifyHandoff, "_fetch_vp_result", lambda self, tid, attempts=10, delay=1.0: ("SUCCESS", {}))
    out = probe.probe_sdjwt_corpus(client(lambda r: httpx.Response(200)), settings())
    assert out and all(r.status == "FAIL" for r in out)
