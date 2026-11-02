"""Suite version compatibility check.

Before running conformance plans, the harness verifies that the running OpenID
conformance suite tag matches the pinned `CONFORMANCE_SUITE_VERSION`. This
catches silent drift between the harness expectations and the suite under test
(e.g. after an upstream upgrade changed plan names, templates, or API shapes).

The suite exposes its version tag via ``GET /api/server`` (when available).
If the tag doesn't match, the harness fails fast with exit code 2 (infrastructure
error) rather than producing misleading results.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

log = logging.getLogger(__name__)


class SuiteVersionMismatch(RuntimeError):
    """Raised when the running suite tag doesn't match the pinned version."""


def check_suite_version(
    base_url: str,
    expected_tag: str,
    token: str = "",
    timeout: float = 10.0,
) -> str | None:
    """Query the suite's /api/server endpoint and compare its tag.

    Returns the actual tag string if the check passes (or if the endpoint is
    unavailable and we can't determine the tag). Raises SuiteVersionMismatch
    if the tag is available but doesn't match expected_tag.
    """
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    url = base_url.rstrip("/") + "/api/server"
    try:
        with httpx.Client(verify=False, timeout=timeout, headers=headers) as http:
            response = http.get(url)
    except httpx.HTTPError as exc:
        log.warning("could not query suite /api/server for version check: %s", exc)
        return None

    if response.status_code != 200:
        log.warning(
            "suite /api/server returned HTTP %s; skipping version check",
            response.status_code,
        )
        return None

    try:
        data = response.json()
    except ValueError:
        log.warning("suite /api/server returned non-JSON; skipping version check")
        return None

    actual_tag = (
        data.get("tag")
        or data.get("version")
        or data.get("suiteVersion")
        or data.get("release")
    )
    if not actual_tag:
        log.warning("suite /api/server response has no tag/version field; skipping version check")
        return None

    if str(actual_tag) != expected_tag:
        raise SuiteVersionMismatch(
            f"suite tag mismatch: expected {expected_tag}, running {actual_tag}. "
            f"Update deploy/versions.env CONFORMANCE_SUITE_VERSION or align the running suite."
        )

    log.info("suite version check passed: %s", actual_tag)
    return str(actual_tag)


def extract_suite_info(data: dict[str, Any]) -> dict[str, str]:
    """Extract useful suite metadata from /api/server response."""
    return {
        "tag": str(data.get("tag", "")),
        "version": str(data.get("version", "")),
        "buildTime": str(data.get("buildTime", "")),
        "gitCommit": str(data.get("gitCommit", "")),
    }
