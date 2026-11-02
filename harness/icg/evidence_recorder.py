"""Protocol evidence recorder.

Captures every request/response between the handoff agent and Inji components
into per-module evidence bundles. Each bundle includes:

* A timestamped history of protocol steps (offer delivery, VP request creation,
  authorization request delivery, VP result polls, etc.)
* The raw request and response payloads (redacted of secrets where applicable)
* SHA-256 hashes of each entry for tamper evidence

Bundles are written to ``results/<run-id>/evidence/<module-id>.json`` and
referenced from ``ModuleResult.evidence`` so reports and certification packages
can link to them.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import logging

log = logging.getLogger(__name__)


@dataclass
class EvidenceEntry:
    """One protocol step in a module's evidence bundle."""

    step: str  # "vp-request", "authorization-request", "vp-result-poll", etc.
    timestamp: str
    request: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)
    sha256: str = ""

    def compute_hash(self) -> str:
        payload = json.dumps(
            {"step": self.step, "timestamp": self.timestamp, "request": self.request, "response": self.response},
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()[:16]


@dataclass
class EvidenceBundle:
    """Complete evidence bundle for one module."""

    module_id: str
    component: str
    entries: list[EvidenceEntry] = field(default_factory=list)

    def add_entry(
        self,
        step: str,
        request: dict[str, Any] | None = None,
        response: dict[str, Any] | None = None,
    ) -> EvidenceEntry:
        entry = EvidenceEntry(
            step=step,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            request=request or {},
            response=response or {},
        )
        entry.sha256 = entry.compute_hash()
        self.entries.append(entry)
        log.debug("evidence[%s] %s sha256=%s", self.module_id, step, entry.sha256)
        return entry

    def to_dict(self) -> dict[str, Any]:
        return {
            "moduleId": self.module_id,
            "component": self.component,
            "entryCount": len(self.entries),
            "entries": [
                {
                    "step": e.step,
                    "timestamp": e.timestamp,
                    "request": e.request,
                    "response": e.response,
                    "sha256": e.sha256,
                }
                for e in self.entries
            ],
        }

    def verify_hashes(self) -> list[str]:
        """Return list of steps whose stored hash doesn't match recomputation."""
        bad: list[str] = []
        for entry in self.entries:
            if entry.compute_hash() != entry.sha256:
                bad.append(entry.step)
        return bad


class EvidenceRecorder:
    """Manages per-module evidence bundles for a run."""

    def __init__(self, evidence_dir: Path):
        self._dir = evidence_dir
        self._dir.mkdir(parents=True, exist_ok=True)
        self._bundles: dict[str, EvidenceBundle] = {}

    def bundle_for(self, module_id: str, component: str) -> EvidenceBundle:
        bundle = self._bundles.get(module_id)
        if bundle is None:
            bundle = EvidenceBundle(module_id=module_id, component=component)
            self._bundles[module_id] = bundle
        return bundle

    def write_all(self) -> dict[str, str]:
        """Write all bundles to disk and return {module_id: path}."""
        paths: dict[str, str] = {}
        for module_id, bundle in self._bundles.items():
            path = self._dir / f"{module_id}.json"
            path.write_text(json.dumps(bundle.to_dict(), indent=2), encoding="utf-8")
            paths[module_id] = str(path)
        return paths

    def verify_all(self) -> dict[str, list[str]]:
        """Verify all bundle hashes. Returns {module_id: [bad_steps]}."""
        return {mid: b.verify_hashes() for mid, b in self._bundles.items() if b.verify_hashes()}
