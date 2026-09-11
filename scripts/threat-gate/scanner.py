#!/usr/bin/env python3
"""Scan Renovate container image changes against the repository threat policy.

Reads the PR event from GITEA_EVENT_PATH or GITHUB_EVENT_PATH. The optional
THREAT_GATE_POLICY_PATH selects a policy; otherwise the bundled baseline applies.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from itertools import zip_longest
from pathlib import Path

from scan_lib import (
    Finding,
    compare_findings,
    fetch_cisa_kev,
    filter_findings,
    load_policy,
    log,
    render_summary_line,
    run,
    scan_image,
    summarize_findings,
    write_step_summary,
)

IMAGE_LINE_RE = re.compile(r"^\+\s*image:\s*[\"']?([^\s\"']+)[\"']?\s*$")
FROM_LINE_RE = re.compile(r"^\+\s*FROM\s+([^\s]+)", re.IGNORECASE)
OLD_IMAGE_LINE_RE = re.compile(r"^-\s*image:\s*[\"']?([^\s\"']+)[\"']?\s*$")
OLD_FROM_LINE_RE = re.compile(r"^-\s*FROM\s+([^\s]+)", re.IGNORECASE)
COMPOSE_NAME_RE = re.compile(r"(^|/)(docker-)?compose[^/]*\.ya?ml$")

# Dockerfile parser regexes for ARG resolution. Renovate's `dockerfile`
# manager bumps `ARG NAME=value` defaults when those values are
# interpolated into FROM lines, so a PR may change ONLY the ARG line and
# leave the FROM line literally identical. Without resolving the
# interpolation here, the diff-line scanner sees no FROM change and
# silently passes the gate. Resolve defaults before comparing image inputs.
DOCKERFILE_ARG_RE = re.compile(
    r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$"
)
DOCKERFILE_FROM_RE = re.compile(r"^\s*FROM\s+(\S+)", re.IGNORECASE)
# Matches ${VAR}, ${VAR:-default}, and $VAR. The default-form clause is
# parsed but ignored; we only need the var name to look up the ARG
# value the Dockerfile itself declared.
ARG_REF_RE = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}|\$([A-Za-z_][A-Za-z0-9_]*)"
)

# Compose interpolation. Matches ${VAR:-default} (captures default),
# ${VAR} (no default — unresolvable), and $VAR (no default — unresolvable).
# Used by `resolve_compose_ref` to turn `image: foo:${TAG:-1.2.3}` into
# `foo:1.2.3` before handing the ref to Grype. Renovate bumps the
# default value, so resolving to it scans the same image a `docker
# compose` invocation would pull when the env var is unset.
COMPOSE_INTERP_RE = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)"
)


class ImagePair:
    __slots__ = ("path", "old", "new")

    def __init__(self, path: str, old: str | None, new: str) -> None:
        self.path = path
        self.old = old
        self.new = new


def load_event() -> dict:
    event_path = os.environ.get("GITEA_EVENT_PATH") or os.environ.get(
        "GITHUB_EVENT_PATH"
    )
    if not event_path:
        log("No event payload path found in environment")
        return {}
    log(f"Loading event payload from {event_path}")
    return json.loads(Path(event_path).read_text())


def is_renovate_pr(event: dict) -> bool:
    pr = event.get("pull_request") or {}
    head = ((pr.get("head") or {}).get("ref") or "").lower()
    user = (((pr.get("user") or {}).get("login")) or "").lower()
    return head.startswith("renovate/") or user.startswith("renovate")


def get_shas(event: dict) -> tuple[str, str]:
    pr = event.get("pull_request") or {}
    base_sha = ((pr.get("base") or {}).get("sha")) or ""
    head_sha = ((pr.get("head") or {}).get("sha")) or ""
    if not base_sha or not head_sha:
        raise RuntimeError(
            "pull request base/head SHAs were not found in the event payload"
        )
    return base_sha, head_sha


def changed_files(base_sha: str, head_sha: str) -> list[str]:
    result = run(["git", "diff", "--name-only", f"{base_sha}...{head_sha}"])
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def is_container_file(path: str) -> bool:
    return bool(
        COMPOSE_NAME_RE.search(path) or Path(path).name.startswith("Dockerfile")
    )


def normalize_image_ref(value: str) -> str:
    return value.strip().strip('"').strip("'")


def read_file_at_ref(sha: str, path: str) -> str | None:
    """Return the file's content at `sha`, or None if it does not exist
    at that ref. Used by the Dockerfile path so we can resolve ARG
    interpolation against the full file rather than just the diff hunk.
    """
    result = subprocess.run(
        ["git", "show", f"{sha}:{path}"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout


def parse_dockerfile(content: str) -> tuple[dict[str, str], list[str]]:
    """Parse Dockerfile content into (arg_defaults, from_image_refs).

    Only ARG declarations with a default value (`ARG NAME=value`) are
    tracked. ARGs without defaults must be supplied via `--build-arg` at
    build time; we have no visibility into those, so resolving a FROM
    that depends on them is impossible — we deliberately skip such
    FROMs in `extract_dockerfile_pairs`.

    The returned FROM list preserves source order so callers can pair
    old vs new positionally; Renovate edits never reorder FROM stages.
    """
    args: dict[str, str] = {}
    froms: list[str] = []
    for raw in content.splitlines():
        # Strip end-of-line comments. Dockerfiles also support full-line
        # `# comment` lines; the regex below ignores them naturally.
        line = raw.split("#", 1)[0]
        arg_match = DOCKERFILE_ARG_RE.match(line)
        if arg_match:
            value = arg_match.group(2).strip().strip('"').strip("'")
            args[arg_match.group(1)] = value
            continue
        from_match = DOCKERFILE_FROM_RE.match(line)
        if from_match:
            froms.append(from_match.group(1))
    return args, froms


def resolve_dockerfile_ref(ref: str, args: dict[str, str]) -> str | None:
    """Substitute ${VAR} and $VAR in a Dockerfile FROM ref using `args`.

    Returns None if the ref references any ARG that the Dockerfile did
    not declare with a default — emitting a partial substitution would
    produce a string Grype cannot parse. The caller logs the skip so
    operators can tell the gate is intentionally not scanning that ref.
    """
    missing = False

    def repl(match: re.Match) -> str:
        nonlocal missing
        name = match.group(1) or match.group(2)
        if name not in args:
            missing = True
            return match.group(0)
        return args[name]

    resolved = ARG_REF_RE.sub(repl, ref)
    return None if missing else resolved


def extract_dockerfile_pairs(
    base_sha: str, head_sha: str, path: str
) -> list[ImagePair]:
    """Extract image-update pairs from a Dockerfile by parsing the full
    old + new file content and resolving `${ARG}` interpolation against
    each side's ARG defaults. Pairs FROM lines positionally because FROM
    stage order is stable across Renovate bumps.
    """
    new_text = read_file_at_ref(head_sha, path)
    if new_text is None:
        # File deleted in this PR — nothing to scan on the new side.
        return []
    new_args, new_froms = parse_dockerfile(new_text)

    old_text = read_file_at_ref(base_sha, path)
    if old_text is None:
        old_args: dict[str, str] = {}
        old_froms: list[str] = []
    else:
        old_args, old_froms = parse_dockerfile(old_text)

    pairs: list[ImagePair] = []
    for old_ref, new_ref in zip_longest(old_froms, new_froms):
        if not new_ref:
            continue
        new_resolved = resolve_dockerfile_ref(new_ref, new_args)
        if new_resolved is None:
            log(
                f"{path}: skipping FROM {new_ref!r} — references undeclared ARG; "
                "build-time --build-arg values are not visible to the threat gate"
            )
            continue
        old_resolved = (
            resolve_dockerfile_ref(old_ref, old_args) if old_ref else None
        )
        if old_resolved == new_resolved:
            continue
        pairs.append(ImagePair(path=path, old=old_resolved, new=new_resolved))
    return pairs


def resolve_compose_ref(ref: str) -> str | None:
    """Substitute `${VAR:-default}` interpolations in a compose image
    ref with their default value. Returns None if any interpolation has
    no default — without one we have no way to know what the runtime
    env supplies, and handing Grype an unresolved `${...}` string makes
    it fail rather than scan.

    Example: `image: onyxdotapp/onyx-backend:${IMAGE_TAG:-v3.1.1}` is
    captured as `onyxdotapp/onyx-backend:${IMAGE_TAG:-v3.1.1}` by the
    diff-line scanner, then resolved here to
    `onyxdotapp/onyx-backend:v3.1.1`. Renovate bumps the default value,
    which is what a `docker compose pull` with the env var unset would
    actually fetch.
    """
    missing = False

    def repl(match: re.Match) -> str:
        nonlocal missing
        # Group 1 = ${VAR(:-default)?} var name
        # Group 2 = the default after `:-` (may be empty string)
        # Group 3 = $VAR (no braces, no default form)
        if match.group(1) is not None:
            default = match.group(2)
            if default is None:
                missing = True
                return match.group(0)
            return default
        # bare $VAR — no default, unresolvable.
        missing = True
        return match.group(0)

    resolved = COMPOSE_INTERP_RE.sub(repl, ref)
    return None if missing else resolved


def extract_compose_pairs(
    base_sha: str, head_sha: str, path: str
) -> list[ImagePair]:
    """Diff-based image extraction for compose files.

    The historical `--unified=0` diff-line approach captures the literal
    rhs of `image:`. Many composes interpolate the tag via
    `${VAR:-default}`, so a Renovate bump of the default value gives us
    a captured ref like `foo:${TAG:-1.2.3}` that Grype cannot parse.
    `resolve_compose_ref` substitutes the default before pairing; refs
    with bare `${VAR}` (no default) are skipped with a log line since we
    have no value to substitute.
    """
    result = run(["git", "diff", "--unified=0", f"{base_sha}...{head_sha}", "--", path])
    old_refs: list[str] = []
    new_refs: list[str] = []
    for line in result.stdout.splitlines():
        old_match = OLD_IMAGE_LINE_RE.match(line) or OLD_FROM_LINE_RE.match(line)
        if old_match:
            old_refs.append(normalize_image_ref(old_match.group(1)))
            continue
        new_match = IMAGE_LINE_RE.match(line) or FROM_LINE_RE.match(line)
        if new_match:
            new_refs.append(normalize_image_ref(new_match.group(1)))
    pairs: list[ImagePair] = []
    for old_ref, new_ref in zip_longest(old_refs, new_refs):
        if not new_ref:
            continue
        new_resolved = resolve_compose_ref(new_ref)
        if new_resolved is None:
            log(
                f"{path}: skipping image {new_ref!r} — interpolation "
                "without a default cannot be resolved at gate time"
            )
            continue
        old_resolved = resolve_compose_ref(old_ref) if old_ref else None
        if old_resolved == new_resolved:
            continue
        pairs.append(ImagePair(path=path, old=old_resolved, new=new_resolved))
    return pairs


def extract_pairs_for_file(base_sha: str, head_sha: str, path: str) -> list[ImagePair]:
    """Dispatch to the Dockerfile or compose extractor based on filename.

    Dockerfiles need full-file parsing so ARG-interpolated FROM tags
    resolve correctly; compose files use the simpler diff-line path.
    """
    if Path(path).name.startswith("Dockerfile"):
        return extract_dockerfile_pairs(base_sha, head_sha, path)
    return extract_compose_pairs(base_sha, head_sha, path)


def main() -> int:
    event = load_event()
    if not is_renovate_pr(event):
        log("Not a Renovate PR; skipping threat gate")
        return 0

    policy = load_policy()
    fail_on_severities = {item.lower() for item in policy.get("fail_on_severities", [])}
    ignored_ids = set(policy.get("ignored_vulnerabilities", []))
    blocked_images = set(policy.get("blocked_images", []))
    warn_only_images = set(policy.get("warn_only_images", []))
    fail_on_kev = bool(policy.get("fail_on_kev", True))

    base_sha, head_sha = get_shas(event)
    log(f"Evaluating Renovate PR diff from {base_sha} to {head_sha}")
    pairs: list[ImagePair] = []
    files = changed_files(base_sha, head_sha)
    log(f"Changed files: {', '.join(files) if files else 'none'}")
    for path in files:
        if is_container_file(path):
            pairs.extend(extract_pairs_for_file(base_sha, head_sha, path))

    if not pairs:
        log("No container image updates detected in this Renovate PR")
        return 0

    # Defer KEV fetch until we know there are container pairs to scan.
    # When fail_on_kev is true, a KEV-fetch failure must abort the gate
    # (fail-closed). Returning an empty set on failure — the previous
    # behaviour — silently relaxed enforcement: every PR appeared to
    # match zero KEV CVEs regardless of actual risk. Keeping the fetch
    # behind the no-pairs early-return means linked Renovate PRs that
    # touch no container files (e.g. shell or Python deps) are not
    # blocked by a transient KEV outage they cannot interact with.
    kev_ids = fetch_cisa_kev(required=fail_on_kev) if fail_on_kev else set()

    # Collapse pairs by (old, new) so a bump that touches multiple files
    # (e.g. vllm's docker-compose.yml + docker-compose-desktop.yml both
    # pinning the same image) only invokes Grype once per unique image
    # rather than once per file. Each scan of a large image takes minutes,
    # so an N-file bump with the previous loop ran 2N scans against N
    # unique image refs.
    grouped: dict[tuple[str | None, str], list[str]] = {}
    for pair in pairs:
        grouped.setdefault((pair.old, pair.new), []).append(pair.path)

    log(
        "Image updates detected: "
        + "; ".join(
            f"{', '.join(paths)}: {old or 'n/a'} -> {new}"
            for (old, new), paths in grouped.items()
        )
    )

    summary_lines = [
        "# Renovate threat gate",
        "",
        "| Files | Current | Candidate | New high/critical | KEV |",
        "| --- | --- | --- | --- | --- |",
    ]
    blocking_reasons: list[str] = []

    for (old, new), paths in grouped.items():
        paths_label = ", ".join(paths)
        log(
            f"Processing image update for {paths_label}: {old or 'n/a'} -> {new}"
        )
        # Pass only_fixed=False: the policy fails on critical/high or
        # KEV-listed CVEs regardless of whether an upstream fix is yet
        # available. Letting Grype's --only-fixed filter run first would
        # silently scrub unfixable-but-policy-violating CVEs before the
        # severity and KEV gate evaluate them.
        new_findings = filter_findings(scan_image(new, only_fixed=False), ignored_ids)
        old_findings = (
            filter_findings(scan_image(old, only_fixed=False), ignored_ids)
            if old
            else []
        )
        introduced = compare_findings(old_findings, new_findings)
        introduced_bad = [
            finding for finding in introduced if finding.severity in fail_on_severities
        ]
        kev_hits = sorted(
            {
                finding.vulnerability_id
                for finding in introduced
                if finding.vulnerability_id in kev_ids
            }
        )

        new_summary = render_summary_line(summarize_findings(new_findings))
        introduced_summary = render_summary_line(summarize_findings(introduced_bad))
        kev_summary = ", ".join(kev_hits[:5]) if kev_hits else "none"
        paths_cell = ", ".join(f"`{p}`" for p in paths)
        summary_lines.append(
            f"| {paths_cell} | `{old or 'n/a'}` | `{new}` | {introduced_summary} | {kev_summary} |"
        )
        summary_lines.append("")
        summary_lines.append(f"- Candidate summary for `{new}`: {new_summary}")
        log(
            f"Candidate summary for {new}: current={render_summary_line(summarize_findings(old_findings))}, new={new_summary}, introduced={introduced_summary}, kev={kev_summary}"
        )

        if new in blocked_images:
            blocking_reasons.append(
                f"{new}: manually blocked by policy.blocked_images"
            )
        elif new in warn_only_images:
            summary_lines.append(f"- Warning only for `{new}` per policy file")
        else:
            if introduced_bad:
                top_ids = ", ".join(
                    sorted({finding.vulnerability_id for finding in introduced_bad})[:8]
                )
                blocking_reasons.append(
                    f"{new}: introduced {introduced_summary} ({top_ids})"
                )
            if kev_hits:
                blocking_reasons.append(
                    f"{new}: introduced KEV-listed vulnerabilities ({', '.join(kev_hits[:8])})"
                )

    write_step_summary(summary_lines)

    if blocking_reasons:
        print("Threat gate blocked the PR:", file=sys.stderr)
        for reason in blocking_reasons:
            print(f"- {reason}", file=sys.stderr)
        return 1

    log("Threat gate passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
