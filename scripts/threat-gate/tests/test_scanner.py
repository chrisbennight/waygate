"""Tests for the container-update threat gate's diff parsing.

Pinned invariants:

1. Compose `image:` bumps still produce a pair (regression guard for the
   pre-existing diff-line path).
2. Direct Dockerfile FROM bumps produce a pair.
3. Dockerfile bumps via `ARG VAR=...` interpolated into FROM resolve
   correctly and produce a pair.
4. A FROM that references an undeclared ARG (build-time only) is skipped
   with a log line rather than emitting a half-substituted ref Grype
   cannot parse.
5. A new Dockerfile (no base-side file) yields pairs with `old=None`.
6. The gate calls `scan_image(..., only_fixed=False)` so unfixable
   critical/high or KEV-listed CVEs cannot be filtered out by Grype's
   `--only-fixed` flag before policy evaluation.
7. The gate does not call `fetch_cisa_kev` when no container files
   changed — a transient KEV outage must not fail PRs that have no
   images to scan.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import scanner as tg  # noqa: E402


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, check=True,
    )
    return result.stdout


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "test")
    _git(repo, "commit", "--allow-empty", "-q", "-m", "root")
    return repo


def _commit_file(repo: Path, path: str, content: str, msg: str) -> str:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    _git(repo, "add", path)
    _git(repo, "commit", "-q", "-m", msg)
    return _git(repo, "rev-parse", "HEAD").strip()


def test_compose_image_bump_produces_pair(tmp_path, monkeypatch):
    """Regression guard for the pre-existing compose path: a literal
    `image:` line bump must still be picked up by the diff-line scanner.
    """
    repo = _init_repo(tmp_path)
    base = _commit_file(
        repo, "docker-compose.yml",
        "services:\n  app:\n    image: traefik:3.4\n",
        "base",
    )
    head = _commit_file(
        repo, "docker-compose.yml",
        "services:\n  app:\n    image: traefik:3.5\n",
        "bump",
    )
    monkeypatch.chdir(repo)
    pairs = tg.extract_pairs_for_file(base, head, "docker-compose.yml")
    assert len(pairs) == 1
    assert pairs[0].old == "traefik:3.4"
    assert pairs[0].new == "traefik:3.5"


def test_compose_interpolated_default_bump_resolves(tmp_path, monkeypatch):
    """Compose manifests can use
    `image: foo:${TAG:-default}` and Renovate bumps the default. The
    diff-line scanner captures the literal `foo:${TAG:-default}` ref,
    which Grype cannot parse. The compose extractor must substitute the
    default before pairing — matches what `docker compose pull` actually
    fetches when the env var is unset, which is the realistic scan
    target.
    """
    repo = _init_repo(tmp_path)
    base = _commit_file(
        repo, "docker-compose.yml",
        "services:\n  app:\n    image: onyxdotapp/onyx-backend:${IMAGE_TAG:-v3.1.1}\n",
        "base",
    )
    head = _commit_file(
        repo, "docker-compose.yml",
        "services:\n  app:\n    image: onyxdotapp/onyx-backend:${IMAGE_TAG:-v3.1.2}\n",
        "bump default",
    )
    monkeypatch.chdir(repo)
    pairs = tg.extract_pairs_for_file(base, head, "docker-compose.yml")
    assert len(pairs) == 1
    assert pairs[0].old == "onyxdotapp/onyx-backend:v3.1.1"
    assert pairs[0].new == "onyxdotapp/onyx-backend:v3.1.2"


def test_compose_interpolation_without_default_is_skipped(tmp_path, monkeypatch, capfd):
    """A compose image ref with `${VAR}` (no `:-default`) cannot be
    resolved at gate time — we have no env var to read. Skip with a log
    line rather than emit a partial substitution Grype cannot scan.
    """
    repo = _init_repo(tmp_path)
    base = _commit_file(
        repo, "docker-compose.yml",
        "services:\n  app:\n    image: old.example.com/img:${TAG}\n",
        "base",
    )
    head = _commit_file(
        repo, "docker-compose.yml",
        "services:\n  app:\n    image: new.example.com/img:${TAG}\n",
        "registry change, tag still unresolvable",
    )
    monkeypatch.chdir(repo)
    pairs = tg.extract_pairs_for_file(base, head, "docker-compose.yml")
    assert pairs == []
    out = capfd.readouterr().out
    assert "skipping image" in out


def test_dockerfile_literal_from_bump_produces_pair(tmp_path, monkeypatch):
    """Direct `FROM rust:1.90 -> 1.95` (no ARG indirection) must still
    produce a pair after the Dockerfile path is rewritten to use
    full-file parsing.
    """
    repo = _init_repo(tmp_path)
    base = _commit_file(
        repo, "Dockerfile",
        "FROM rust:1.90-slim-bookworm AS builder\n",
        "base",
    )
    head = _commit_file(
        repo, "Dockerfile",
        "FROM rust:1.95-slim-bookworm AS builder\n",
        "bump",
    )
    monkeypatch.chdir(repo)
    pairs = tg.extract_pairs_for_file(base, head, "Dockerfile")
    assert len(pairs) == 1
    assert pairs[0].old == "rust:1.90-slim-bookworm"
    assert pairs[0].new == "rust:1.95-slim-bookworm"


def test_dockerfile_arg_interpolated_from_bump_produces_pair(tmp_path, monkeypatch):
    """When a Dockerfile pins `ARG RUST_VERSION=1.90`
    and uses it in `FROM rust:${RUST_VERSION}-slim-bookworm`, a Renovate
    PR that only changes the ARG default must still produce a scan pair.
    Pre-fix the diff-line scanner saw no FROM change and exited success.
    """
    base_content = (
        "ARG RUST_VERSION=1.90\n"
        "FROM rust:${RUST_VERSION}-slim-bookworm AS builder\n"
    )
    head_content = (
        "ARG RUST_VERSION=1.95\n"
        "FROM rust:${RUST_VERSION}-slim-bookworm AS builder\n"
    )
    repo = _init_repo(tmp_path)
    base = _commit_file(repo, "Dockerfile", base_content, "base")
    head = _commit_file(repo, "Dockerfile", head_content, "bump arg")
    monkeypatch.chdir(repo)
    pairs = tg.extract_pairs_for_file(base, head, "Dockerfile")
    assert len(pairs) == 1
    assert pairs[0].old == "rust:1.90-slim-bookworm"
    assert pairs[0].new == "rust:1.95-slim-bookworm"


def test_dockerfile_undeclared_arg_in_from_is_skipped(tmp_path, monkeypatch, capfd):
    """If a FROM references an ARG without a default (build-time only),
    we cannot resolve the ref. Skip the pair rather than emit a partial
    substitution Grype cannot parse, and log so operators can see it.
    """
    base = (
        "ARG VERSION\n"
        "FROM example.com/img:${VERSION}\n"
    )
    head = (
        "ARG VERSION\n"
        "FROM example.com/img:${VERSION}\n"
    )
    repo = _init_repo(tmp_path)
    base_sha = _commit_file(repo, "Dockerfile", base, "base")
    # Must commit a change to the file so it's visible in the head tree;
    # an unrelated comment edit suffices.
    head_sha = _commit_file(repo, "Dockerfile", head + "# touch\n", "touch")
    monkeypatch.chdir(repo)
    pairs = tg.extract_pairs_for_file(base_sha, head_sha, "Dockerfile")
    assert pairs == []
    out = capfd.readouterr().out
    assert "skipping FROM" in out


def _write_renovate_event(tmp_path: Path, base_sha: str, head_sha: str) -> Path:
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps({
        "pull_request": {
            "head": {"ref": "renovate/foo", "sha": head_sha},
            "base": {"sha": base_sha},
            "user": {"login": "renovate"},
        }
    }))
    return event_path


def test_threat_gate_calls_scan_image_with_only_fixed_false(tmp_path, monkeypatch):
    """Policy fails on critical/high or KEV-listed CVEs regardless of
    whether a fix is available. If `scan_image` is called with the
    default `only_fixed=True`, Grype's --only-fixed flag drops unfixable
    CVEs before the gate can act.
    """
    repo = _init_repo(tmp_path)
    base = _commit_file(
        repo, "docker-compose.yml",
        "services:\n  app:\n    image: traefik:3.4\n",
        "base",
    )
    head = _commit_file(
        repo, "docker-compose.yml",
        "services:\n  app:\n    image: traefik:3.5\n",
        "bump",
    )
    captured: list[dict] = []

    def fake_scan(image_ref, *, only_fixed=True):
        captured.append({"image": image_ref, "only_fixed": only_fixed})
        return []

    monkeypatch.setattr(tg, "scan_image", fake_scan)
    monkeypatch.setattr(tg, "fetch_cisa_kev", lambda **_kw: set())
    event = _write_renovate_event(tmp_path, base, head)
    monkeypatch.setenv("GITEA_EVENT_PATH", str(event))
    monkeypatch.chdir(repo)

    rc = tg.main()
    assert rc == 0
    assert captured, "scan_image was never called"
    for call in captured:
        assert call["only_fixed"] is False, (
            f"scan_image called with only_fixed={call['only_fixed']!r} for {call['image']}"
        )


def test_threat_gate_skips_kev_fetch_when_no_container_changes(tmp_path, monkeypatch):
    """Renovate PRs that don't touch container files (e.g. Python deps,
    shell scripts, docs) must not trigger the KEV fetch. With
    `policy.fail_on_kev=true` the fetch raises on transient outage, and
    that should not fail a PR that has no images to scan.
    """
    repo = _init_repo(tmp_path)
    base = _commit_file(repo, "README.md", "before\n", "base")
    head = _commit_file(repo, "README.md", "after\n", "doc tweak")

    def fail_kev(**_kw):
        raise AssertionError(
            "fetch_cisa_kev must not be called when no container files changed"
        )

    def fail_scan(*_a, **_k):
        raise AssertionError(
            "scan_image must not be called when no container files changed"
        )

    monkeypatch.setattr(tg, "fetch_cisa_kev", fail_kev)
    monkeypatch.setattr(tg, "scan_image", fail_scan)
    event = _write_renovate_event(tmp_path, base, head)
    monkeypatch.setenv("GITEA_EVENT_PATH", str(event))
    monkeypatch.chdir(repo)

    rc = tg.main()
    assert rc == 0


def test_threat_gate_dedups_same_image_across_files(tmp_path, monkeypatch):
    """A bump that touches multiple compose files with the same image
    pin (e.g. vllm's docker-compose.yml + docker-compose-desktop.yml)
    must invoke Grype once per unique (old, new), not once per file.
    Each Grype scan of a large image can take minutes, so duplicate
    references must share their scan.
    """
    repo = _init_repo(tmp_path)
    base = _commit_file(
        repo, "vllm/docker-compose.yml",
        "services:\n  vllm:\n    image: vllm/vllm-openai:v0.19.1\n",
        "base main compose",
    )
    base = _commit_file(
        repo, "vllm/docker-compose-desktop.yml",
        "services:\n  vllm:\n    image: vllm/vllm-openai:v0.19.1\n",
        "base desktop compose",
    )
    _commit_file(
        repo, "vllm/docker-compose.yml",
        "services:\n  vllm:\n    image: vllm/vllm-openai:v0.20.0\n",
        "bump main",
    )
    head = _commit_file(
        repo, "vllm/docker-compose-desktop.yml",
        "services:\n  vllm:\n    image: vllm/vllm-openai:v0.20.0\n",
        "bump desktop",
    )
    captured: list[str] = []

    def fake_scan(image_ref, *, only_fixed=True):
        captured.append(image_ref)
        return []

    monkeypatch.setattr(tg, "scan_image", fake_scan)
    monkeypatch.setattr(tg, "fetch_cisa_kev", lambda **_kw: set())
    event = _write_renovate_event(tmp_path, base, head)
    monkeypatch.setenv("GITEA_EVENT_PATH", str(event))
    monkeypatch.chdir(repo)

    rc = tg.main()
    assert rc == 0
    assert sorted(captured) == [
        "vllm/vllm-openai:v0.19.1",
        "vllm/vllm-openai:v0.20.0",
    ], f"expected one scan per unique image, got {captured!r}"


def test_dockerfile_added_in_pr_yields_old_none(tmp_path, monkeypatch):
    """A Dockerfile created in this PR has no base-side content. The
    scanner should still emit pairs for its FROM lines with `old=None`
    so Grype scans the new image (the runner skips old scanning when
    pair.old is None).
    """
    repo = _init_repo(tmp_path)
    base = _git(repo, "rev-parse", "HEAD").strip()
    head = _commit_file(
        repo, "Dockerfile",
        "FROM alpine:3.20\n",
        "add dockerfile",
    )
    monkeypatch.chdir(repo)
    pairs = tg.extract_pairs_for_file(base, head, "Dockerfile")
    assert len(pairs) == 1
    assert pairs[0].old is None
    assert pairs[0].new == "alpine:3.20"
