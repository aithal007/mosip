from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..adapter_protocol import ProtocolClient, SubprocessAdapter
from ..settings import Settings
from ..suite_api import SuiteApi

log = logging.getLogger(__name__)


class Ledger:
    """Thread-safe record of every handoff action, keyed by suite module id.

    The collector reads it afterwards to attach evidence (Inji transaction ids,
    review outcomes) to results, and it is written to disk for debugging.
    """

    def __init__(self, path: Path | None = None):
        self._path = path
        self._lock = threading.Lock()
        self._entries: dict[str, dict[str, Any]] = {}

    def get(self, module_id: str) -> dict[str, Any]:
        with self._lock:
            return dict(self._entries.get(module_id, {}))

    def update(self, module_id: str, **values: Any) -> None:
        with self._lock:
            self._entries.setdefault(module_id, {}).update(values)
            self._flush_locked()

    def append_event(self, module_id: str, event: dict[str, Any]) -> None:
        with self._lock:
            self._entries.setdefault(module_id, {}).setdefault("events", []).append(event)
            self._flush_locked()

    def snapshot(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return json.loads(json.dumps(self._entries))

    def _flush_locked(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._entries, indent=2, default=str), encoding="utf-8")


@dataclass
class HandoffContext:
    module_id: str
    test_name: str
    status: dict[str, Any]
    api: SuiteApi
    settings: Settings
    ledger: Ledger

    @property
    def exposed(self) -> dict[str, str]:
        return self.status.get("exposed") or {}

    @property
    def browser(self) -> dict[str, Any]:
        return self.status.get("browser") or {}

    @property
    def updated(self) -> str:
        return str(self.status.get("updated", ""))


class HandoffAdapter:
    """Base class. Subclasses implement :meth:`handle_waiting` and may override
    :meth:`resolve_review`.

    The agent calls :meth:`on_waiting` every poll while a module is WAITING. A module
    can wait several times (e.g. offer, then tx_code, then a second client), so an
    action is only taken once per distinct ``updated`` timestamp of the module.
    """

    component = ""
    test_name_prefixes: tuple[str, ...] = ()

    def __init__(self, settings: Settings):
        self.settings = settings

    def applies_to(self, test_name: str) -> bool:
        return test_name.startswith(self.test_name_prefixes)

    def on_waiting(self, ctx: HandoffContext) -> None:
        state = ctx.ledger.get(ctx.module_id)
        if state.get("lastHandledUpdate") == ctx.updated:
            return
        pending = self._pending_placeholders(ctx)
        if pending:
            for placeholder in pending:
                self.resolve_review(ctx, placeholder)
        elif self.handle_waiting(ctx) is False:
            # The suite has not exposed what the adapter needs yet: leave this state
            # unhandled so the next poll retries it.
            ctx.ledger.update(ctx.module_id, testName=ctx.test_name)
            return
        # Only mark the state handled once the action succeeded; a raised error is
        # retried by the agent (bounded by MAX_ATTEMPTS_PER_STATE).
        ctx.ledger.update(ctx.module_id, lastHandledUpdate=ctx.updated, testName=ctx.test_name)

    def handle_waiting(self, ctx: HandoffContext) -> bool | None:
        """Act on a WAITING module. Return ``False`` if not ready yet (retry next poll)."""
        raise NotImplementedError

    def resolve_review(self, ctx: HandoffContext, placeholder: dict[str, Any]) -> None:
        """Default: leave REVIEW placeholders for a human (normal certification runs)."""
        ctx.ledger.append_event(ctx.module_id, {"action": "review-left-for-human", "placeholder": placeholder.get("upload")})

    @staticmethod
    def _pending_placeholders(ctx: HandoffContext) -> list[dict[str, Any]]:
        if not ctx.browser.get("uploadsRequired"):
            return []
        return [
            entry
            for entry in ctx.api.image_placeholders(ctx.module_id)
            if entry.get("upload") and not entry.get("img")
        ]


# ---------------------------------------------------------------------------
# Protocol adapter bridge
# ---------------------------------------------------------------------------


@dataclass
class ProtocolAction:
    """An action the agent should perform on behalf of a protocol adapter."""

    type: str  # "visit" | "upload_image" | "append_event" | "set_ledger"
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProtocolExecuteResult:
    """Result returned by a protocol adapter's execute operation."""

    handled: bool
    ledger_updates: dict[str, Any] = field(default_factory=dict)
    actions: list[ProtocolAction] = field(default_factory=list)


class ProtocolHandoffAdapter(HandoffAdapter):
    """A :class:`HandoffAdapter` that delegates to a protocol adapter client.

    The protocol adapter (possibly in another language/process) owns the
    component-specific handoff logic. The bridge translates between the
    :class:`HandoffContext`-based in-process API and the NDJSON protocol.

    Suite API calls (visit, upload_image) and ledger mutations are performed by
    the agent through this bridge, so the protocol adapter never needs direct
    access to the suite or ledger objects.
    """

    def __init__(self, settings: Settings, client: ProtocolClient):
        super().__init__(settings)
        self._client = client

    def applies_to(self, test_name: str) -> bool:
        return test_name.startswith(self._client.capabilities.component + "-")

    def on_waiting(self, ctx: HandoffContext) -> None:
        state = ctx.ledger.get(ctx.module_id)
        if state.get("lastHandledUpdate") == ctx.updated:
            return

        # Ask the protocol adapter what to do for this WAITING state.
        try:
            result = self._client.execute_step(
                module_id=ctx.module_id,
                test_name=ctx.test_name,
                status=ctx.status,
                ledger_state=state,
            )
        except Exception as exc:  # adapter error -> retry on next poll
            log.error(
                "[%s] %s: protocol adapter execute failed: %s",
                ctx.module_id,
                ctx.test_name,
                exc,
            )
            ctx.ledger.update(ctx.module_id, lastError=str(exc))
            return

        parsed = self._parse_execute_result(result)

        # Apply ledger updates first
        if parsed.ledger_updates:
            ctx.ledger.update(ctx.module_id, **parsed.ledger_updates)

        # Execute actions through the agent (suite API access stays in-process)
        for action in parsed.actions:
            self._execute_action(ctx, action)

        # Check for pending review placeholders (adapter may not have resolved them)
        pending = self._pending_placeholders(ctx)
        if pending and not any(a.type == "upload_image" for a in parsed.actions):
            for placeholder in pending:
                self.resolve_review(ctx, placeholder)

        if parsed.handled:
            ctx.ledger.update(
                ctx.module_id, lastHandledUpdate=ctx.updated, testName=ctx.test_name
            )

    def _parse_execute_result(self, result: Any) -> ProtocolExecuteResult:
        if isinstance(result, dict):
            handled = bool(result.get("handled", False))
            updates = result.get("ledger_updates", {}) or {}
            actions = [
                ProtocolAction(type=str(a.get("type", "")), data=a.get("data", {}) or {})
                for a in (result.get("actions") or [])
            ]
            return ProtocolExecuteResult(handled=handled, ledger_updates=updates, actions=actions)
        # Backward compat: raw bool means handled
        return ProtocolExecuteResult(handled=bool(result))

    def _execute_action(self, ctx: HandoffContext, action: ProtocolAction) -> None:
        if action.type == "visit":
            url = str(action.data.get("url", ""))
            if url:
                response = ctx.api.visit(url)
                ctx.ledger.append_event(
                    ctx.module_id,
                    {
                        "action": "protocol-visit",
                        "url": url,
                        "suiteHttpStatus": response.status_code,
                    },
                )
        elif action.type == "upload_image":
            placeholder = str(action.data.get("placeholder", ""))
            data_url = str(action.data.get("data_url", ""))
            if placeholder and data_url:
                ctx.api.upload_placeholder_image(ctx.module_id, placeholder, data_url)
                ctx.ledger.append_event(
                    ctx.module_id,
                    {"action": "protocol-upload-image", "placeholder": placeholder},
                )
        elif action.type == "append_event":
            ctx.ledger.append_event(ctx.module_id, action.data.get("event", {}))
        elif action.type == "set_ledger":
            ctx.ledger.update(ctx.module_id, **action.data.get("values", {}))
        else:
            log.warning("unknown protocol action type: %s", action.type)

    def shutdown(self) -> None:
        try:
            self._client.shutdown()
        except Exception:  # noqa: BLE001
            log.warning("protocol client shutdown raised, ignoring")
