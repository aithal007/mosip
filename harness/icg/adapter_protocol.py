"""Language-agnostic adapter protocol over NDJSON stdin/stdout.

The handoff agent no longer calls adapter methods directly. Instead it spawns an
adapter subprocess per component and speaks NDJSON to it:

  Request:  {"id": "<opaque>", "op": "init|execute|shutdown|capabilities", "params": {...}}
  Response: {"id": "<opaque>", "ok": true, "result": {...}}
            {"id": "<opaque>", "ok": false, "error_code": "...", "message": "..."}

Operations:
  --capabilities  print capabilities JSON and exit (dry-run, no subprocess needed)
  init            one-time setup with component settings
  execute         run one handoff step for a WAITING module
  shutdown        clean teardown

Each adapter subprocess handles one component for the lifetime of the harness run.
Adapter process crashes are treated as infrastructure errors: the module waits until
the upstream timeout and is recorded INCOMPLETE (fail closed).
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)

PROTOCOL_VERSION = 1

# ---------------------------------------------------------------------------
# Envelope helpers
# ---------------------------------------------------------------------------


def _envelope(op: str, params: dict[str, Any], req_id: str | int) -> str:
    return json.dumps({"id": req_id, "op": op, "params": params}, separators=(",", ":"))


def _parse_envelope(line: str) -> dict[str, Any]:
    obj = json.loads(line)
    if not isinstance(obj, dict) or "id" not in obj or "op" not in obj:
        raise ValueError(f"malformed envelope: {line[:200]}")
    return obj


@dataclass
class AdapterResponse:
    ok: bool
    result: Any = None
    error_code: str = ""
    message: str = ""


# ---------------------------------------------------------------------------
# In-process protocol handler (Python adapters run in-process by default)
# ---------------------------------------------------------------------------


class ProtocolHandler:
    """Base class for in-process protocol handlers. Subclasses implement
    :meth:`capabilities`, :meth:`init`, and :meth:`execute`.

    A handler is stateless across calls except what it stores in ``self.state``.
    The agent creates one handler instance per component per run.
    """

    component: str = ""
    version: str = "0.1.0"

    def __init__(self, settings: Any):
        self.settings = settings
        self.state: dict[str, Any] = {}
        self._initialized = False

    def capabilities(self) -> dict[str, Any]:
        """Declare supported operations and metadata."""
        return {
            "protocol": PROTOCOL_VERSION,
            "component": self.component,
            "version": self.version,
            "ops": ["init", "execute", "shutdown"],
        }

    def init(self, params: dict[str, Any]) -> dict[str, Any]:
        """One-time setup. Returns adapter info."""
        self._initialized = True
        return {"component": self.component, "initialized": True}

    def execute(self, params: dict[str, Any]) -> dict[str, Any]:
        """Run one handoff step for a WAITING module.

        ``params`` contains:
          - module_id: suite module id
          - test_name: suite test module name
          - status: suite runner status (exposed values, browser requests)
          - ledger: current ledger state for this module

        Returns a dict with:
          - handled: bool - whether this state was fully handled
          - ledger_updates: dict - values to merge into the module ledger entry
          - actions: list of {"type": "...", "data": {...}} actions for the agent
        """
        raise NotImplementedError

    def resolve_review(self, params: dict[str, Any]) -> dict[str, Any]:
        """Resolve a REVIEW placeholder for a module.

        ``params`` contains:
          - module_id: suite module id
          - test_name: suite test module name
          - placeholder: the placeholder dict from image_placeholders
          - ledger: current ledger state for this module

        Returns a dict with:
          - matched: bool - whether Inji's result matched the expectation
          - expected: str - expected outcome ("SUCCESS" | "FAILED" | "UNKNOWN")
          - actual: str - actual result from Inji
          - evidence_png_b64: str - base64 PNG evidence card (optional)
          - detail: dict - additional evidence details
        """
        raise NotImplementedError

    def shutdown(self) -> dict[str, Any]:
        """Clean teardown."""
        self._initialized = False
        return {"component": self.component, "shutdown": True}

    # -- dispatch -----------------------------------------------------------

    def dispatch(self, line: str) -> str:
        """Handle one NDJSON request line, return one NDJSON response line."""
        req = _parse_envelope(line)
        req_id = req["id"]
        op = req["op"]
        params = req.get("params", {}) or {}

        try:
            if op == "capabilities":
                result = self.capabilities()
            elif op == "init":
                result = self.init(params)
            elif op == "execute":
                if not self._initialized:
                    raise RuntimeError("adapter not initialized")
                result = self.execute(params)
            elif op == "shutdown":
                result = self.shutdown()
            else:
                raise ValueError(f"unknown op: {op}")
            return json.dumps(
                {"id": req_id, "ok": True, "result": result}, separators=(",", ":")
            )
        except Exception as exc:  # noqa: BLE001 - protocol boundary catches all
            log.exception("adapter op %s failed", op)
            return json.dumps(
                {
                    "id": req_id,
                    "ok": False,
                    "error_code": type(exc).__name__,
                    "message": str(exc),
                },
                separators=(",", ":"),
            )


def run_in_process(handler: ProtocolHandler, stdin=None, stdout=None) -> int:
    """Serve the protocol over stdin/stdout (for in-process adapters or tests).

    Reads NDJSON lines from stdin, writes NDJSON responses to stdout.
    Returns when EOF is reached on stdin.
    """
    inp = stdin or sys.stdin
    out = stdout or sys.stdout
    for line in inp:
        line = line.strip()
        if not line:
            continue
        try:
            resp = handler.dispatch(line)
        except Exception as exc:  # noqa: BLE001
            resp = json.dumps(
                {"id": None, "ok": False, "error_code": type(exc).__name__, "message": str(exc)},
                separators=(",", ":"),
            )
        out.write(resp + "\n")
        out.flush()
    return 0


# ---------------------------------------------------------------------------
# Subprocess adapter client (agent side)
# ---------------------------------------------------------------------------


@dataclass
class SubprocessAdapter:
    """Manages one adapter subprocess for one component.

    Spawns the adapter command, sends init/execute/shutdown over NDJSON,
    and tolerates a single transient failure per module step (the agent
    retries on the next poll).
    """

    command: list[str]
    cwd: Path | None = None
    env: dict[str, str] | None = None
    timeout_seconds: float = 30.0

    _proc: subprocess.Popen[str] | None = None
    _lock = threading.Lock()
    _counter = 0
    _initialized = False

    def _next_id(self) -> int:
        with self._lock:
            self._counter += 1
            return self._counter

    def _start(self) -> None:
        if self._proc is not None:
            return
        env = dict(self.env or {})
        self._proc = subprocess.Popen(
            self.command,
            cwd=str(self.cwd) if self.cwd else None,
            env=env or None,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        # Drain stderr in a background thread so the adapter can't deadlock
        # filling its stderr pipe while we wait on stdout.
        _stderr_buf: list[str] = []

        def _drain() -> None:
            assert self._proc is not None and self._proc.stderr is not None
            for line in self._proc.stderr:
                _stderr_buf.append(line.rstrip("\n"))

        t = threading.Thread(target=_drain, daemon=True)
        t.start()
        self._stderr_buf = _stderr_buf  # type: ignore[attr-defined]

    def _request(self, op: str, params: dict[str, Any]) -> AdapterResponse:
        self._start()
        assert self._proc is not None and self._proc.stdin is not None and self._proc.stdout is not None
        req_id = self._next_id()
        self._proc.stdin.write(_envelope(op, params, req_id) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:
            # Adapter exited unexpectedly
            self._close()
            return AdapterResponse(
                ok=False,
                error_code="AdapterExit",
                message=f"adapter exited during {op} (stderr: {self._tail_stderr()})",
            )
        resp = _parse_envelope(line.strip())
        ok = resp.get("ok", False)
        return AdapterResponse(
            ok=ok,
            result=resp.get("result"),
            error_code=resp.get("error_code", "") if not ok else "",
            message=resp.get("message", "") if not ok else "",
        )

    def capabilities(self) -> AdapterResponse:
        return self._request("capabilities", {})

    def init(self, params: dict[str, Any]) -> AdapterResponse:
        resp = self._request("init", params)
        if resp.ok:
            self._initialized = True
        return resp

    def execute(self, params: dict[str, Any]) -> AdapterResponse:
        if not self._initialized:
            return AdapterResponse(
                ok=False, error_code="NotInitialized", message="adapter not initialized"
            )
        return self._request("execute", params)

    def shutdown(self) -> AdapterResponse:
        resp = self._request("shutdown", {})
        self._close()
        return resp

    def _close(self) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
            self._proc.terminate()
            self._proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            try:
                self._proc.kill()
            except Exception:  # noqa: BLE001
                pass
        self._proc = None
        self._initialized = False

    def _tail_stderr(self) -> str:
        buf = getattr(self, "_stderr_buf", [])
        return "\n".join(buf[-10:]) if buf else ""

    def is_alive(self) -> bool:
        if self._proc is None:
            return False
        return self._proc.poll() is None


# ---------------------------------------------------------------------------
# Capabilities negotiation
# ---------------------------------------------------------------------------


@dataclass
class AdapterCapabilities:
    protocol: int
    component: str
    version: str
    ops: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_response(resp: AdapterResponse) -> "AdapterCapabilities":
        if not resp.ok or not isinstance(resp.result, dict):
            raise ValueError(f"cannot parse capabilities: {resp.message}")
        raw = resp.result
        return AdapterCapabilities(
            protocol=int(raw.get("protocol", 0)),
            component=str(raw.get("component", "")),
            version=str(raw.get("version", "0.1.0")),
            ops=list(raw.get("ops", [])),
            raw=raw,
        )


# ---------------------------------------------------------------------------
# Protocol client facade used by the handoff agent
# ---------------------------------------------------------------------------


class ProtocolClient:
    """High-level client used by HandoffAgent.

    Wraps SubprocessAdapter with capabilities negotiation and typed params
    for the handoff use case (module_id, test_name, status, ledger state).
    """

    def __init__(self, adapter: SubprocessAdapter):
        self.adapter = adapter
        self._caps: AdapterCapabilities | None = None

    @property
    def capabilities(self) -> AdapterCapabilities:
        if self._caps is None:
            self._caps = AdapterCapabilities.from_response(self.adapter.capabilities())
        return self._caps

    def init_component(self, settings: Any) -> None:
        resp = self.adapter.init(
            {
                "component": self.capabilities.component,
                "settings": self._settings_dict(settings),
            }
        )
        if not resp.ok:
            raise RuntimeError(f"adapter init failed: {resp.error_code} {resp.message}")

    @staticmethod
    def _settings_dict(settings: Any) -> dict[str, Any]:
        if settings is None:
            return {}
        return {
            "conformance_server": getattr(settings, "conformance_server", ""),
            "certify_admin_url": getattr(settings, "certify_admin_url", ""),
            "certify_public_url": getattr(settings, "certify_public_url", ""),
            "verify_admin_url": getattr(settings, "verify_admin_url", ""),
            "verify_public_url": getattr(settings, "verify_public_url", ""),
            "handoff_poll_seconds": getattr(settings, "handoff_poll_seconds", 1.0),
            "review_policy": getattr(settings, "review_policy", "resolve"),
            "warning_policy": getattr(settings, "warning_policy", "pass"),
        }

    def execute_step(
        self,
        module_id: str,
        test_name: str,
        status: dict[str, Any],
        ledger_state: dict[str, Any],
    ) -> dict[str, Any]:
        resp = self.adapter.execute(
            {
                "module_id": module_id,
                "test_name": test_name,
                "status": status,
                "ledger": ledger_state,
            }
        )
        if not resp.ok:
            raise RuntimeError(f"adapter execute failed: {resp.error_code} {resp.message}")
        return resp.result or {}

    def shutdown(self) -> None:
        try:
            self.adapter.shutdown()
        except Exception:  # noqa: BLE001
            log.warning("adapter shutdown raised, ignoring")
