"""Tests for evidence_recorder and suite_version modules."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from icg.evidence_recorder import EvidenceBundle, EvidenceEntry, EvidenceRecorder
from icg.suite_version import check_suite_version, SuiteVersionMismatch, extract_suite_info


# -- EvidenceEntry ------------------------------------------------------------

def test_evidence_entry_hash_deterministic():
    entry = EvidenceEntry(
        step="vp-request",
        timestamp="2026-01-01T00:00:00Z",
        request={"clientId": "test"},
        response={"status": 200},
    )
    h1 = entry.compute_hash()
    h2 = entry.compute_hash()
    assert h1 == h2
    assert len(h1) == 16


def test_evidence_entry_hash_changes_on_tamper():
    entry = EvidenceEntry(
        step="vp-request",
        timestamp="2026-01-01T00:00:00Z",
        request={"clientId": "test"},
        response={"status": 200},
    )
    original = entry.compute_hash()
    entry.request = {"clientId": "tampered"}
    assert entry.compute_hash() != original


# -- EvidenceBundle -----------------------------------------------------------

def test_evidence_bundle_add_entry():
    bundle = EvidenceBundle(module_id="M1", component="verify")
    entry = bundle.add_entry("vp-request", {"clientId": "x"}, {"status": 200})
    assert entry.step == "vp-request"
    assert entry.sha256 != ""
    assert len(bundle.entries) == 1


def test_evidence_bundle_to_dict():
    bundle = EvidenceBundle(module_id="M1", component="verify")
    bundle.add_entry("vp-request", {"a": 1}, {"b": 2})
    d = bundle.to_dict()
    assert d["moduleId"] == "M1"
    assert d["component"] == "verify"
    assert d["entryCount"] == 1
    assert d["entries"][0]["step"] == "vp-request"


def test_evidence_bundle_verify_hashes():
    bundle = EvidenceBundle(module_id="M1", component="verify")
    bundle.add_entry("step1", {}, {})
    # Tamper with stored hash
    bundle.entries[0].sha256 = "deadbeef"
    bad = bundle.verify_hashes()
    assert bad == ["step1"]


# -- EvidenceRecorder ---------------------------------------------------------

def test_evidence_recorder_write_all(tmp_path):
    ev_dir = tmp_path / "evidence"
    recorder = EvidenceRecorder(ev_dir)
    bundle = recorder.bundle_for("M1", "verify")
    bundle.add_entry("vp-request", {}, {})
    paths = recorder.write_all()
    assert "M1" in paths
    assert Path(paths["M1"]).exists()
    data = json.loads(Path(paths["M1"]).read_text())
    assert data["moduleId"] == "M1"


def test_evidence_recorder_verify_all(tmp_path):
    ev_dir = tmp_path / "evidence"
    recorder = EvidenceRecorder(ev_dir)
    bundle = recorder.bundle_for("M1", "verify")
    bundle.add_entry("step1", {}, {})
    bundle.entries[0].sha256 = "tampered"
    recorder.write_all()
    bad = recorder.verify_all()
    assert "M1" in bad
    assert "step1" in bad["M1"]


# -- Suite version ------------------------------------------------------------

def test_check_suite_version_match():
    def fake_get(url, headers=None, timeout=None):
        class Resp:
            status_code = 200

            def json(self):
                return {"tag": "release-v5.2.4"}

        return Resp()

    with patch("icg.suite_version.httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.get = fake_get
        tag = check_suite_version("https://suite.example", "release-v5.2.4")
        assert tag == "release-v5.2.4"


def test_check_suite_version_mismatch():
    def fake_get(url, headers=None, timeout=None):
        class Resp:
            status_code = 200

            def json(self):
                return {"tag": "release-v5.1.0"}

        return Resp()

    with patch("icg.suite_version.httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.get = fake_get
        with pytest.raises(SuiteVersionMismatch) as exc:
            check_suite_version("https://suite.example", "release-v5.2.4")
        assert "release-v5.1.0" in str(exc.value)


def test_check_suite_version_endpoint_down():
    import httpx

    with patch("icg.suite_version.httpx.Client") as mock_client:
        mock_client.return_value.__enter__.side_effect = httpx.ConnectError("boom")
        tag = check_suite_version("https://suite.example", "release-v5.2.4")
        assert tag is None


def test_extract_suite_info():
    data = {
        "tag": "release-v5.2.4",
        "version": "5.2.4",
        "buildTime": "2026-01-01T00:00:00Z",
        "gitCommit": "abc123",
    }
    info = extract_suite_info(data)
    assert info["tag"] == "release-v5.2.4"
    assert info["version"] == "5.2.4"
    assert info["buildTime"] == "2026-01-01T00:00:00Z"
    assert info["gitCommit"] == "abc123"
