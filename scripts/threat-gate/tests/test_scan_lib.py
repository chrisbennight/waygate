"""Tests for the scanner utilities.

Pinned invariants:

1. When callers mark KEV enforcement as required, a network failure
   must raise rather than silently scrub KEV alerting from the run.
2. When required, a successful fetch with an unrecognised payload
   shape (missing or non-list `vulnerabilities`) must also raise — an
   upstream schema change cannot be allowed to degrade the gate to
   "no KEV hits ever".
3. Default behaviour (required=False) preserves the historical fail-open
   for both failure modes — used where KEV data is advisory only.
4. ``load_policy`` honours ``THREAT_GATE_POLICY_PATH`` first, then the
   bundled ``default-policy.json``, then the hardcoded baseline.
5. ``grype_image_ref`` qualifies bare single-name official images to
   ``docker.io/library/<name>`` so a repo name that collides with a Grype
   source scheme (``registry:``, ``docker:``, ...) cannot be misparsed and
   crash the scan.
"""

from __future__ import annotations

import json
import sys
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import scan_lib  # noqa: E402


def _raise_url_error(*_args, **_kwargs):
    raise urllib.error.URLError("simulated outage")


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *_exc) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def _patch_urlopen_with_payload(monkeypatch, payload: dict) -> None:
    body = json.dumps(payload).encode()
    monkeypatch.setattr(
        scan_lib.urllib.request, "urlopen",
        lambda *_a, **_k: _FakeResponse(body),
    )


def test_fetch_kev_fail_open_returns_empty_set_on_failure(monkeypatch):
    monkeypatch.setattr(scan_lib.urllib.request, "urlopen", _raise_url_error)
    assert scan_lib.fetch_cisa_kev() == set()


def test_fetch_kev_required_raises_on_failure(monkeypatch):
    monkeypatch.setattr(scan_lib.urllib.request, "urlopen", _raise_url_error)
    with pytest.raises(scan_lib.KEVFetchError):
        scan_lib.fetch_cisa_kev(required=True)


def test_fetch_kev_required_raises_on_missing_vulnerabilities_field(monkeypatch):
    _patch_urlopen_with_payload(monkeypatch, {"catalogVersion": "2026.01"})
    with pytest.raises(scan_lib.KEVFetchError):
        scan_lib.fetch_cisa_kev(required=True)


def test_fetch_kev_required_raises_on_non_list_vulnerabilities(monkeypatch):
    _patch_urlopen_with_payload(monkeypatch, {"vulnerabilities": {"items": []}})
    with pytest.raises(scan_lib.KEVFetchError):
        scan_lib.fetch_cisa_kev(required=True)


def test_fetch_kev_fail_open_tolerates_missing_vulnerabilities_field(monkeypatch):
    _patch_urlopen_with_payload(monkeypatch, {"catalogVersion": "2026.01"})
    assert scan_lib.fetch_cisa_kev() == set()


def test_fetch_kev_parses_well_formed_payload(monkeypatch):
    _patch_urlopen_with_payload(monkeypatch, {
        "vulnerabilities": [
            {"cveID": "CVE-2024-0001"},
            {"cveID": "CVE-2024-0002"},
            {"cveID": ""},
            {},
        ],
    })
    assert scan_lib.fetch_cisa_kev(required=True) == {
        "CVE-2024-0001", "CVE-2024-0002",
    }


def test_load_policy_uses_env_var_override(tmp_path, monkeypatch):
    """If ``THREAT_GATE_POLICY_PATH`` points at an existing file, that
    file's contents are returned in preference to the bundled default.
    """
    override = tmp_path / "custom-policy.json"
    override.write_text(json.dumps({
        "fail_on_severities": ["critical"],
        "fail_on_kev": False,
        "ignored_vulnerabilities": ["CVE-2024-9999"],
        "blocked_images": [],
        "warn_only_images": [],
    }))
    monkeypatch.setenv("THREAT_GATE_POLICY_PATH", str(override))
    policy = scan_lib.load_policy()
    assert policy["fail_on_severities"] == ["critical"]
    assert policy["fail_on_kev"] is False
    assert policy["ignored_vulnerabilities"] == ["CVE-2024-9999"]


def test_load_policy_falls_back_to_bundled_default(monkeypatch):
    """When the env var is unset (or points at a missing file), the
    action's bundled ``default-policy.json`` is loaded.
    """
    monkeypatch.delenv("THREAT_GATE_POLICY_PATH", raising=False)
    bundled = scan_lib.DEFAULT_POLICY_PATH
    assert bundled.exists(), "default-policy.json must ship with the action"
    expected = json.loads(bundled.read_text())
    assert scan_lib.load_policy() == expected


def test_load_policy_falls_back_to_hardcoded_baseline_when_default_missing(
    tmp_path, monkeypatch
):
    """If neither override nor bundled default exists, the hardcoded
    baseline is returned. Guards against a packaging regression that
    would otherwise silently produce an empty policy.
    """
    monkeypatch.delenv("THREAT_GATE_POLICY_PATH", raising=False)
    monkeypatch.setattr(
        scan_lib, "DEFAULT_POLICY_PATH", tmp_path / "missing.json"
    )
    assert scan_lib.load_policy() == scan_lib.HARDCODED_BASELINE_POLICY


@pytest.mark.parametrize(
    "ref, expected",
    [
        # The defect: the Docker Distribution image collides with Grype's
        # `registry:` source scheme, so a bare ref is misparsed as
        # registry-scheme + image `2.8.3` -> docker.io/library/2.8.3 and the
        # scan aborts UNAUTHORIZED. Qualifying it makes the leading token a host.
        (
            "registry:2.8.3@sha256:a3d8aaa",
            "docker.io/library/registry:2.8.3@sha256:a3d8aaa",
        ),
        # Other bare official (`library/`) images are qualified too — harmless,
        # they resolve identically and can never collide with a future scheme.
        ("alpine:3.20", "docker.io/library/alpine:3.20"),
        (
            "postgres:17-alpine@sha256:abc",
            "docker.io/library/postgres:17-alpine@sha256:abc",
        ),
        # Refs that already carry an org or registry host (a `/`) are untouched.
        ("linuxserver/jellyfin:10.11", "linuxserver/jellyfin:10.11"),
        (
            "lscr.io/linuxserver/radarr:6.1.1@sha256:c0a",
            "lscr.io/linuxserver/radarr:6.1.1@sha256:c0a",
        ),
        # Idempotent: an already-qualified library ref is left alone.
        ("docker.io/library/postgres:17", "docker.io/library/postgres:17"),
    ],
)
def test_grype_image_ref_qualifies_only_bare_official_images(ref, expected):
    assert scan_lib.grype_image_ref(ref) == expected


def test_grype_image_ref_avoids_registry_scheme_collision():
    """Regression contract: the qualified `registry` ref must
    resolve under `library/` so Grype scans the Distribution image rather
    than parsing `registry:` as a source scheme. Asserts the violated
    contract — the leading token is a host, not a scheme keyword."""
    out = scan_lib.grype_image_ref("registry:2.8.3@sha256:a3d8aaa")
    assert out.startswith("docker.io/library/registry:")
    assert not out.startswith("registry:")
