"""Handoff agent: a background worker that runs alongside ``run-test-plan.py``.

``run-test-plan.py`` creates modules and waits (up to 240 s) for WAITING modules to
reach FINISHED, but it never drives an external issuer/verifier. The agent watches the
suite for WAITING modules and performs the component handoff, so the upstream
script can be used unmodified.
"""

from __future__ import annotations

import logging
import threading
import time
import traceback

from .handoff import HandoffAdapter, HandoffContext, Ledger
from .settings import Settings
from .suite_api import SuiteApi

log = logging.getLogger(__name__)

MAX_ATTEMPTS_PER_STATE = 3


class HandoffAgent:
    def __init__(self, settings: Settings, adapters: list[HandoffAdapter], ledger: Ledger):
        self.settings = settings
        self.adapters = adapters
        self.ledger = ledger
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="icg-handoff-agent", daemon=True)
        self._api = SuiteApi(settings.conformance_server, settings.conformance_token)

    def __enter__(self) -> "HandoffAgent":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=15)
        self._api.close()

    def _adapter_for(self, test_name: str) -> HandoffAdapter | None:
        return next((a for a in self.adapters if a.applies_to(test_name)), None)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:  # keep the agent alive; failures surface as INCOMPLETE modules
                log.warning("handoff agent poll failed:\n%s", traceback.format_exc())
            self._stop.wait(self.settings.handoff_poll_seconds)

    def poll_once(self) -> None:
        for module_id in self._api.running_test_ids():
            info = self._api.module_info(module_id)
            if not info or info.get("status") != "WAITING":
                continue
            test_name = str(info.get("testName", ""))
            adapter = self._adapter_for(test_name)
            if adapter is None:
                continue
            status = self._api.runner_status(module_id)
            if status is None:
                continue
            ctx = HandoffContext(module_id, test_name, status, self._api, self.settings, self.ledger)
            try:
                adapter.on_waiting(ctx)
            except Exception as exc:
                self._record_failure(ctx, exc)

    def _record_failure(self, ctx: HandoffContext, exc: Exception) -> None:
        state = self.ledger.get(ctx.module_id)
        attempts = int(state.get("failedAttempts", 0)) + 1
        self.ledger.update(ctx.module_id, failedAttempts=attempts, lastError=f"{type(exc).__name__}: {exc}")
        self.ledger.append_event(ctx.module_id, {"action": "handoff-error", "error": str(exc), "at": time.time()})
        if attempts < MAX_ATTEMPTS_PER_STATE:
            # Forget that this WAITING state was handled so the next poll retries it.
            self.ledger.update(ctx.module_id, lastHandledUpdate=None)
        log.error("[%s] %s: handoff failed (attempt %d): %s", ctx.module_id, ctx.test_name, attempts, exc)
