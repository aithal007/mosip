"""Thin synchronous client for the OpenID conformance suite REST API.

Plan creation and module execution are left to the upstream ``run-test-plan.py``;
this client only covers what the handoff agent and the collector need. Endpoint
shapes were taken from the suite's TestRunnerApi, TestPlanApi, LogApi and ImageAPI.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

log = logging.getLogger(__name__)


class SuiteApiError(RuntimeError):
    pass


class SuiteApi:
    def __init__(self, base_url: str, token: str = "", timeout: float = 30.0):
        if not base_url.endswith("/"):
            base_url += "/"
        self.base_url = base_url
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        # Local suites use a self-signed certificate; run-test-plan.py disables
        # verification in dev mode for the same reason.
        self._http = httpx.Client(verify=False, timeout=timeout, headers=headers)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "SuiteApi":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- helpers ---------------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self.base_url}api/{path.lstrip('/')}"

    def _get_json(self, path: str, *, allow_404: bool = False) -> Any:
        response = self._http.get(self._url(path))
        if allow_404 and response.status_code == 404:
            return None
        if response.status_code != 200:
            raise SuiteApiError(f"GET {path} -> HTTP {response.status_code}: {response.text[:300]}")
        return response.json()

    def log_detail_url(self, module_id: str) -> str:
        return f"{self.base_url}log-detail.html?log={module_id}"

    def plan_detail_url(self, plan_id: str) -> str:
        return f"{self.base_url}plan-detail.html?plan={plan_id}"

    # -- server ----------------------------------------------------------------

    def is_ready(self) -> bool:
        try:
            response = self._http.get(self._url("runner/available"), timeout=10)
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    # -- running tests ---------------------------------------------------------

    def running_test_ids(self) -> list[str]:
        return list(self._get_json("runner/running") or [])

    def runner_status(self, module_id: str) -> dict[str, Any] | None:
        """In-memory status: exposed values, browser/uri-input requests. None once evicted."""
        return self._get_json(f"runner/{module_id}", allow_404=True)

    def module_info(self, module_id: str) -> dict[str, Any] | None:
        """Persisted info: testName, status, result, variant, planId."""
        return self._get_json(f"info/{module_id}", allow_404=True)

    def module_log(self, module_id: str) -> list[dict[str, Any]]:
        return list(self._get_json(f"log/{module_id}") or [])

    def plan(self, plan_id: str) -> dict[str, Any]:
        return self._get_json(f"plan/{plan_id}")

    # -- interactions ----------------------------------------------------------

    def visit(self, url: str, *, follow_redirects: bool = False) -> httpx.Response:
        """Perform a front-channel request against one of the suite's test endpoints
        (for example the verifier test's authorization_endpoint)."""
        return self._http.get(url, follow_redirects=follow_redirects)

    def image_placeholders(self, module_id: str) -> list[dict[str, Any]]:
        return list(self._get_json(f"log/{module_id}/images") or [])

    def upload_placeholder_image(self, module_id: str, placeholder: str, data_url: str) -> None:
        if not data_url.startswith(("data:image/png;", "data:image/jpeg;")):
            raise ValueError("The suite only accepts PNG or JPEG data URLs")
        response = self._http.post(
            self._url(f"log/{module_id}/images/{placeholder}"),
            content=data_url.encode("ascii"),
            headers={"Content-Type": "text/plain"},
        )
        if response.status_code != 200:
            raise SuiteApiError(
                f"Image upload for {module_id}/{placeholder} failed: HTTP {response.status_code} {response.text[:300]}"
            )
