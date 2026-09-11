"""Scanning utilities for the container update threat gate.

The scanner runs from this repository in either Gitea or GitHub Actions.

Policy resolution order:
  1. ``THREAT_GATE_POLICY_PATH`` env var, if it points at an existing
     file. The workflow selects ``policy/container-threat-policy.json``
     when present.
  2. ``default-policy.json`` shipped alongside this module — the
     baseline used when a consumer doesn't provide its own override.
  3. A hardcoded baseline (critical/high + KEV, no ignores) as the
     last-resort fallback if neither file exists.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

MODULE_DIR = Path(__file__).resolve().parent
DEFAULT_POLICY_PATH = MODULE_DIR / "default-policy.json"
SEVERITY_ORDER = ["negligible", "low", "medium", "high", "critical"]

HARDCODED_BASELINE_POLICY: dict = {
    "fail_on_severities": ["critical", "high"],
    "fail_on_kev": True,
    "ignored_vulnerabilities": [],
    "blocked_images": [],
    "warn_only_images": [],
}


@dataclass
class Finding:
    vulnerability_id: str
    severity: str
    fix_state: str | None = None
    fix_versions: list[str] = field(default_factory=list)
    artifact_name: str | None = None
    artifact_version: str | None = None


def log(message: str) -> None:
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"[{timestamp}] {message}", flush=True)


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    log(f"Running command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, check=check, text=True, capture_output=True)
    except subprocess.CalledProcessError as exc:
        if exc.stdout:
            print(exc.stdout, file=sys.stderr, end="")
        if exc.stderr:
            print(exc.stderr, file=sys.stderr, end="")
        raise
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    return result


def load_policy() -> dict:
    """Resolve and return the active policy dict.

    Tries the env-var override, then the bundled default, then the
    hardcoded baseline. Each step is logged so operators can tell from
    the run log which policy actually applied.
    """
    override = os.environ.get("THREAT_GATE_POLICY_PATH")
    if override:
        path = Path(override)
        if path.exists():
            log(f"Loading policy from THREAT_GATE_POLICY_PATH={path}")
            return json.loads(path.read_text())
        log(f"THREAT_GATE_POLICY_PATH={path} not found; falling back")
    if DEFAULT_POLICY_PATH.exists():
        log(f"Loading bundled default policy from {DEFAULT_POLICY_PATH}")
        return json.loads(DEFAULT_POLICY_PATH.read_text())
    log("No policy file found; using hardcoded baseline")
    return dict(HARDCODED_BASELINE_POLICY)


def grype_image_ref(image_ref: str) -> str:
    """Return *image_ref* in a form Grype cannot mistake for a source scheme.

    Grype reads a leading ``name:`` as a SOURCE SCHEME (``registry:``,
    ``docker:``, ``dir:``, ``sbom:``, ``oci-dir:``, ...). A bare single-name
    official image like ``registry:2.8.3@sha256:...`` is therefore misparsed
    as scheme ``registry`` + image ``2.8.3`` -> ``docker.io/library/2.8.3``,
    which does not exist, so Grype aborts the whole scan with UNAUTHORIZED.

    Bare official images have no ``/`` in the repo path (before any
    ``@digest``); fully-qualify them to ``docker.io/library/<name>`` so the
    leading token is an unambiguous registry host that can never collide with
    a scheme. Refs that already carry a registry host or org (a ``/``) are
    left untouched, and the rewrite resolves to the same image either way.

    This takes a *container image ref* (what the scanner's extractors always
    produce), never an explicit Grype ``scheme:`` source. A no-slash ref is
    therefore unambiguously an official ``library/`` image — the function does
    not special-case a literal ``sbom:``/``dir:`` input, which the scanner
    never passes here.
    """
    if image_ref and "/" not in image_ref.split("@", 1)[0]:
        return f"docker.io/library/{image_ref}"
    return image_ref


def scan_image(image_ref: str, *, only_fixed: bool = True) -> list[Finding]:
    """Scan *image_ref* with Grype and return parsed findings.

    The threat gate passes ``only_fixed=False`` so unfixable CVEs still
    surface to the policy gate — severity and KEV are evaluated
    regardless of fix availability.
    """
    scan_ref = grype_image_ref(image_ref)
    log(f"Scanning image with Grype: {scan_ref}")
    cmd = ["grype", scan_ref, "--output", "json"]
    if only_fixed:
        cmd.append("--only-fixed")
    result = run(cmd)
    payload = json.loads(result.stdout)
    findings: list[Finding] = []
    for match in payload.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        fix = vuln.get("fix", {})
        findings.append(
            Finding(
                vulnerability_id=vuln.get("id", "unknown"),
                severity=(vuln.get("severity") or "unknown").lower(),
                fix_state=fix.get("state"),
                fix_versions=fix.get("versions") or [],
                artifact_name=artifact.get("name"),
                artifact_version=artifact.get("version"),
            )
        )
    log(f"Grype found {len(findings)} vulnerabilities for {image_ref}")
    return findings


class KEVFetchError(RuntimeError):
    """Raised when the CISA KEV feed cannot be fetched or parsed and the
    caller has marked KEV enforcement as required (policy.fail_on_kev=true).
    """


def fetch_cisa_kev(*, required: bool = False) -> set[str]:
    """Fetch the CISA Known Exploited Vulnerabilities feed.

    When `required=False` (default), a fetch or parse failure is logged
    and an empty set is returned. When `required=True`, the same failure
    raises `KEVFetchError` so a transient outage cannot silently relax
    the policy.
    """
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    log(f"Fetching CISA KEV feed from {url}")
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            payload = json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        if required:
            raise KEVFetchError(
                f"CISA KEV feed unavailable ({exc!r}); "
                "policy.fail_on_kev is true so the gate is failing closed"
            ) from exc
        log("Unable to fetch or parse CISA KEV feed; continuing without KEV matches")
        return set()
    vulns = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(vulns, list):
        if required:
            raise KEVFetchError(
                "CISA KEV feed payload missing 'vulnerabilities' list; "
                "policy.fail_on_kev is true so the gate is failing closed"
            )
        log("CISA KEV feed payload missing 'vulnerabilities' list; continuing without KEV matches")
        return set()
    kev_ids = {
        item.get("cveID", "")
        for item in vulns
        if isinstance(item, dict) and item.get("cveID")
    }
    log(f"Loaded {len(kev_ids)} KEV entries")
    return kev_ids


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity.lower())
    except ValueError:
        return -1


def finding_key(finding: Finding) -> tuple[str, str]:
    return (finding.vulnerability_id, finding.severity)


def filter_findings(
    findings: Iterable[Finding], ignored_ids: set[str]
) -> list[Finding]:
    return [
        finding for finding in findings if finding.vulnerability_id not in ignored_ids
    ]


def compare_findings(
    old_findings: list[Finding], new_findings: list[Finding]
) -> list[Finding]:
    old_keys = {finding_key(item) for item in old_findings}
    return [item for item in new_findings if finding_key(item) not in old_keys]


def summarize_findings(findings: list[Finding]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for finding in findings:
        summary[finding.severity] = summary.get(finding.severity, 0) + 1
    return summary


def render_summary_line(summary: dict[str, int]) -> str:
    parts = [
        f"{severity}={summary[severity]}"
        for severity in SEVERITY_ORDER
        if summary.get(severity)
    ]
    return ", ".join(parts) if parts else "none"


def write_step_summary(lines: list[str]) -> None:
    step_summary = os.environ.get("GITEA_STEP_SUMMARY") or os.environ.get(
        "GITHUB_STEP_SUMMARY"
    )
    if not step_summary:
        log("No step summary path available")
        return
    Path(step_summary).write_text("\n".join(lines) + "\n")
    log(f"Wrote step summary to {step_summary}")
