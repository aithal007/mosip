from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
        ctx.ledger.update(ctx.module_id, lastHandledUpdate=ctx.updated, testName=ctx.test_name)

        pending = self._pending_placeholders(ctx)
        if pending:
            for placeholder in pending:
                self.resolve_review(ctx, placeholder)
            return
        self.handle_waiting(ctx)

    def handle_waiting(self, ctx: HandoffContext) -> None:
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
