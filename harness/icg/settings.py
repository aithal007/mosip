"""Environment-driven settings.

Every value can be overridden with an environment variable of the same name, which is
also how the api-testrig bridge passes ``env.endpoint``-derived URLs down to the harness.

Two URLs exist per Inji component because the harness and the conformance suite see the
services from different network positions:

* ``*_ADMIN_URL``  - where the harness calls Inji's own APIs (create offer, create VP request).
* ``*_PUBLIC_URL`` - the externally visible URL that the suite container dereferences
                     (credential_issuer, response_uri). In a real MOSIP environment both
                     are the same https URL; in docker-compose they differ.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _env(name: str, default: str) -> str:
    value = os.environ.get(name, "").strip()
    return value or default


def _strip_slash(url: str) -> str:
    return url.rstrip("/")


@dataclass(frozen=True)
class Settings:
    conformance_server: str
    conformance_server_mtls: str
    conformance_token: str
    suite_scripts_dir: Path
    suite_version: str
    certify_admin_url: str
    certify_public_url: str
    verify_admin_url: str
    verify_public_url: str
    python_executable: str
    handoff_poll_seconds: float
    review_policy: str
    warning_policy: str

    @property
    def dev_mode(self) -> bool:
        return not self.conformance_token

    def template_variables(self) -> dict[str, str]:
        """Variables available as ${NAME} inside conformance/configs/*.json templates."""
        return {
            "CERTIFY_PUBLIC_URL": self.certify_public_url,
            "VERIFY_PUBLIC_URL": self.verify_public_url,
            "VERIFY_RESPONSE_URI": f"{self.verify_public_url}/v2/vp-submission/direct-post",
            "CONFORMANCE_SERVER": self.conformance_server,
        }

    @staticmethod
    def from_env() -> "Settings":
        server = _env("CONFORMANCE_SERVER", "https://localhost.emobix.co.uk:8443/")
        if not server.endswith("/"):
            server += "/"
        return Settings(
            conformance_server=server,
            conformance_server_mtls=_env("CONFORMANCE_SERVER_MTLS", "https://localhost.emobix.co.uk:8444/"),
            conformance_token=os.environ.get("CONFORMANCE_TOKEN", "").strip(),
            suite_scripts_dir=Path(
                _env("CONFORMANCE_SUITE_SCRIPTS", str(REPO_ROOT / "upstream" / "conformance-suite" / "scripts"))
            ),
            suite_version=_env("CONFORMANCE_SUITE_VERSION", "release-v5.2.4"),
            certify_admin_url=_strip_slash(_env("CERTIFY_ADMIN_URL", "http://localhost:8090/v1/certify")),
            certify_public_url=_strip_slash(_env("CERTIFY_PUBLIC_URL", "https://certify.inji.test/v1/certify")),
            verify_admin_url=_strip_slash(_env("VERIFY_ADMIN_URL", "http://localhost:8080/v1/verify")),
            verify_public_url=_strip_slash(_env("VERIFY_PUBLIC_URL", "https://verify.inji.test/v1/verify")),
            python_executable=_env("ICG_PYTHON", ""),
            handoff_poll_seconds=float(_env("ICG_HANDOFF_POLL_SECONDS", "1.0")),
            # How suite REVIEW results count once the review resolver has attached evidence:
            #   resolve - PASS only if Inji's own verification result matches the expectation
            #   pass    - treat REVIEW as PASS (upstream CI behaviour)
            #   fail    - treat REVIEW as FAIL (strict)
            review_policy=_env("ICG_REVIEW_POLICY", "resolve"),
            # WARNING results: "pass" (default, logged) or "fail" (strict).
            warning_policy=_env("ICG_WARNING_POLICY", "pass"),
        )
