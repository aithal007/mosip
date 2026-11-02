"""Tests for the adapter protocol module."""

import io
import json
from unittest.mock import patch

import pytest

from icg.adapter_protocol import (
    PROTOCOL_VERSION,
    AdapterResponse,
    ProtocolClient,
    ProtocolHandler,
    SubprocessAdapter,
    _envelope,
    _parse_envelope,
    run_in_process,
)
from icg.handoff.protocol_certify import ProtocolCertifyHandler
from icg.handoff.protocol_verify import ProtocolVerifyHandler
from icg.settings import Settings


class _FakeHandler(ProtocolHandler):
    component = "test"
    version = "1.0.0"

    def __init__(self, settings):
        super().__init__(settings)
        self.calls = []

    def capabilities(self):
        return {"protocol": PROTOCOL_VERSION, "component": self.component, "version": self.version, "ops": ["init", "execute", "shutdown"]}

    def init(self, params):
        self.calls.append(("init", params))
        self._initialized = True
        return {"component": self.component, "initialized": True}

    def execute(self, params):
        self.calls.append(("execute", params))
        return {"handled": True, "ledger_updates": {"foo": "bar"}, "actions": [{"type": "visit", "data": {"url": "https://example"}}]}

    def shutdown(self):
        self.calls.append(("shutdown", {}))
        return {"component": self.component, "shutdown": True}


# -- envelope ------------------------------------------------------------------

def test_envelope_round_trip():
    env = _envelope("init", {"key": "value"}, 42)
    parsed = _parse_envelope(env)
    assert parsed == {"id": 42, "op": "init", "params": {"key": "value"}}


def test_parse_envelope_missing_fields():
    with pytest.raises(ValueError):
        _parse_envelope('{"id": 1}')
    with pytest.raises(ValueError):
        _parse_envelope('{"op": "init"}')


# -- ProtocolHandler dispatch --------------------------------------------------

def test_handler_dispatch_init_execute_shutdown():
    handler = _FakeHandler(settings=None)
    req_init = json.dumps({"id": 1, "op": "init", "params": {"x": 1}})
    req_exec = json.dumps({"id": 2, "op": "execute", "params": {"y": 2}})
    req_shutdown = json.dumps({"id": 3, "op": "shutdown", "params": {}})

    out = io.StringIO()
    run_in_process(handler, stdin=io.StringIO(req_init + "\n" + req_exec + "\n" + req_shutdown + "\n"), stdout=out)

    responses = [json.loads(line) for line in out.getvalue().strip().split("\n") if line.strip()]
    assert responses[0]["ok"] is True
    assert responses[0]["result"]["initialized"] is True
    assert responses[1]["ok"] is True
    assert responses[1]["result"]["handled"] is True
    assert responses[2]["ok"] is True
    assert responses[2]["result"]["shutdown"] is True


def test_handler_dispatch_unknown_op():
    handler = _FakeHandler(settings=None)
    req = json.dumps({"id": 1, "op": "bogus", "params": {}})
    out = io.StringIO()
    run_in_process(handler, stdin=io.StringIO(req + "\n"), stdout=out)
    resp = json.loads(out.getvalue().strip())
    assert resp["ok"] is False
    assert "error_code" in resp


def test_handler_capabilities():
    handler = _FakeHandler(settings=None)
    caps = handler.capabilities()
    assert caps["protocol"] == PROTOCOL_VERSION
    assert caps["component"] == "test"
    assert "init" in caps["ops"]


# -- ProtocolClient (SubprocessAdapter mock) -----------------------------------

def test_subprocess_adapter_init_execute_shutdown():
    # Use in-process ProtocolClient directly with a mock adapter
    handler = _FakeHandler(settings=None)

    class FakeAdapter:
        def __init__(self, handler):
            self._handler = handler
            self._initialized = False

        def capabilities(self):
            from icg.adapter_protocol import AdapterResponse
            return AdapterResponse(ok=True, result=self._handler.capabilities())

        def init(self, params):
            self._initialized = True
            return AdapterResponse(ok=True, result={"initialized": True})

        def execute(self, params):
            if not self._initialized:
                return AdapterResponse(ok=False, error_code="NotInitialized", message="not init")
            return AdapterResponse(ok=True, result=self._handler.execute(params))

        def shutdown(self):
            self._initialized = False
            return AdapterResponse(ok=True, result={"shutdown": True})

        def is_alive(self):
            return True

    client = ProtocolClient(FakeAdapter(handler))
    caps = client.capabilities
    assert caps.component == "test"
    assert caps.protocol == PROTOCOL_VERSION

    client.init_component(Settings.from_env())
    result = client.execute_step("M1", "test-module", {"exposed": {}, "browser": {}, "updated": "t1"}, {})
    assert result["handled"] is True
    assert result["ledger_updates"]["foo"] == "bar"

    client.shutdown()


# -- ProtocolCertifyHandler ----------------------------------------------------

def test_certify_protocol_handler_capabilities():
    handler = ProtocolCertifyHandler(Settings.from_env())
    caps = handler.capabilities()
    assert caps["component"] == "certify"
    assert "resolve_review" in caps["ops"]


def test_certify_protocol_handler_init():
    handler = ProtocolCertifyHandler(Settings.from_env())
    result = handler.init({})
    assert result["initialized"] is True
    assert handler._http is not None


def test_certify_protocol_handler_execute_no_endpoint():
    handler = ProtocolCertifyHandler(Settings.from_env())
    handler.init({})
    result = handler.execute({"module_id": "M1", "test_name": "oid4vci-1_0-issuer-happy-flow", "status": {"exposed": {}, "browser": {}}, "ledger": {}})
    assert result["handled"] is False


# -- ProtocolVerifyHandler -----------------------------------------------------

def test_verify_protocol_handler_capabilities():
    handler = ProtocolVerifyHandler(Settings.from_env())
    caps = handler.capabilities()
    assert caps["component"] == "verify"
    assert "resolve_review" in caps["ops"]


def test_verify_protocol_handler_init():
    handler = ProtocolVerifyHandler(Settings.from_env())
    result = handler.init({})
    assert result["initialized"] is True
    assert handler._http is not None


def test_verify_protocol_handler_execute_no_endpoint():
    handler = ProtocolVerifyHandler(Settings.from_env())
    handler.init({})
    result = handler.execute({"module_id": "M1", "test_name": "oid4vp-1final-verifier-happy-flow", "status": {"exposed": {}, "browser": {}}, "ledger": {}})
    assert result["handled"] is False


def test_build_authorization_query():
    from icg.handoff.protocol_verify import build_authorization_query, expected_outcome

    vp_request = {
        "transactionId": "txn_1",
        "requestId": "req_1",
        "authorizationDetails": {
            "responseType": "vp_token",
            "responseMode": "direct_post",
            "nonce": "n0nce-0123456789",
            "responseUri": "https://verify.inji.test/v1/verify/v2/vp-submission/direct-post",
            "dcqlQuery": {"credentials": [{"id": "pid", "format": "dc+sd-jwt"}]},
        },
    }
    client_id = "redirect_uri:https://verify.inji.test/v1/verify/v2/vp-submission/direct-post"
    params = dict(__import__("urllib.parse", fromlist=["parse_qsl"]).parse_qsl(build_authorization_query(client_id, vp_request)))
    assert params["client_id"] == client_id
    assert params["state"] == "req_1"
    assert params["response_uri"].endswith("/v2/vp-submission/direct-post")
    assert json.loads(params["dcql_query"])["credentials"][0]["format"] == "dc+sd-jwt"


def test_expected_outcome():
    from icg.handoff.protocol_verify import expected_outcome
    assert expected_outcome({"src": "ExpectVerifierSuccessfulVerificationPage"}) == "SUCCESS"
    assert expected_outcome({"src": "ExpectVerifierRejectedPresentationPage"}) == "FAILED"
    assert expected_outcome({"src": "Other"}) == "UNKNOWN"


# -- AdapterResponse -----------------------------------------------------------

def test_adapter_response_ok():
    resp = AdapterResponse(ok=True, result={"x": 1})
    assert resp.ok is True
    assert resp.result == {"x": 1}


def test_adapter_response_error():
    resp = AdapterResponse(ok=False, error_code="Boom", message="something broke")
    assert resp.ok is False
    assert resp.error_code == "Boom"
    assert resp.message == "something broke"
