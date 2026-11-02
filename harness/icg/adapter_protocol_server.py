"""Subprocess adapter server entry point.

Usage: python -m icg.adapter_protocol_server <component> [--haip]

Spawns a protocol handler for the given component and serves the NDJSON protocol
over stdin/stdout. Used when ICG_ADAPTER_SUBPROCESS=1 to run adapters in isolated
processes.
"""

from __future__ import annotations

import sys

from .adapter_protocol import run_in_process
from .handoff import PROTOCOL_HANDLERS
from .settings import Settings


def main() -> int:
    args = sys.argv[1:]
    haip = False
    if "--haip" in args:
        haip = True
        args.remove("--haip")
    if len(args) < 1:
        print("usage: python -m icg.adapter_protocol_server <component> [--haip]", file=sys.stderr)
        return 2
    component = args[0]
    handler_cls = PROTOCOL_HANDLERS.get(component)
    if handler_cls is None:
        print(f"unknown component: {component}", file=sys.stderr)
        return 2
    settings = Settings.from_env()
    handler = handler_cls(settings, haip=haip)
    return run_in_process(handler)


if __name__ == "__main__":
    sys.exit(main())
