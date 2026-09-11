"""Publish a smoke-tested local image from the serialized GitHub publish job.

CI is the sole registry writer. The workflow's publication concurrency group
covers the registry reads and writes; GHCR does not offer conditional tag writes.
"""
import json
import os
from pathlib import Path
import re
import subprocess

from release_policy import image_plan, parse_version, require_merged, run, workspace_version

RELEASE_LABEL = 'io.waygate.release.version'


def remote_image(reference):
    result = subprocess.run(
        ['docker', 'buildx', 'imagetools', 'inspect', reference, '--format', '{{json .}}'],
        text=True, capture_output=True,
    )
    if result.returncode:
        # Only a registry's explicit missing-manifest response means absence.
        # Authentication, transport, and parser failures must stop publication.
        if re.search(r'(?:manifest unknown|: not found)\s*$', result.stderr.strip(), re.I):
            return None
        raise RuntimeError(f'cannot inspect registry image {reference}; publication stopped')
    data = json.loads(result.stdout)
    digest = data['manifest']['digest']
    if not re.fullmatch('sha256:[0-9a-f]{64}', digest):
        raise ValueError('registry returned an invalid digest')
    return digest, data['image']['config'].get('Labels', {}) or {}


def advance_latest(version, current):
    candidate, prerelease = parse_version(version)
    if prerelease:
        return False
    if current is None:
        return True
    previous = current[1].get(RELEASE_LABEL)
    # Images from the former main/latest workflow carry no release label.
    if previous is None:
        return True
    old, old_prerelease = parse_version(previous)
    if old_prerelease:
        raise ValueError('latest unexpectedly points to a prerelease')
    return candidate > old


def push_tag(local, target):
    run('docker', 'tag', local, target)
    run('docker', 'push', target)
    published = remote_image(target)
    if published is None:
        raise RuntimeError('pushed image cannot be read back')
    return published[0]


def publish():
    sha = run('git', 'rev-parse', 'HEAD')
    kind, version = image_plan(os.environ['GITHUB_EVENT_NAME'], os.environ['GITHUB_REF'], sha, workspace_version())
    if kind == 'verify':
        raise ValueError('build-only events cannot publish')
    require_merged(os.environ['GITHUB_SHA'])
    repository = 'ghcr.io/' + os.environ['GITHUB_REPOSITORY'].lower()
    if not re.fullmatch(r'ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+', repository):
        raise ValueError('invalid GHCR repository')
    local = repository + ':sha-' + sha
    if os.environ['GATEWAY_IMAGE_PINNED'] != local:
        raise ValueError('smoked image name does not match the source commit')
    labels = json.loads(run('docker', 'image', 'inspect', local, '--format', '{{json .Config.Labels}}')) or {}
    if labels.get('org.opencontainers.image.revision') != sha or labels.get(RELEASE_LABEL, '') != version:
        raise ValueError('local image provenance does not match the event')
    if kind == 'main':
        digest = push_tag(local, local)
        # A delayed main run must not roll edge back after a newer run published.
        current = remote_image(repository + ':edge')
        if current:
            previous = current[1].get('org.opencontainers.image.revision', '')
            if not re.fullmatch('[0-9a-f]{40}', previous):
                raise ValueError('edge has no valid source revision')
            result = subprocess.run(['git', 'merge-base', '--is-ancestor', previous, sha])
            if result.returncode == 1:
                print('Published source image; edge already points to newer or divergent history.')
                return
            result.check_returncode()
        if push_tag(local, repository + ':edge') != digest:
            raise RuntimeError('edge digest differs from verified source image')
    else:
        target = repository + ':' + version
        if remote_image(target) is not None:
            raise ValueError('version image already exists; reconcile its digest and release notes instead of rebuilding it')
        previous_latest = remote_image(repository + ':latest')
        latest = advance_latest(version, previous_latest)
        digest = push_tag(local, target)
        if latest and push_tag(local, repository + ':latest') != digest:
            raise RuntimeError('latest digest differs from verified release image')
        observed_latest = remote_image(repository + ':latest')
        with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a') as handle:
            before = previous_latest[0] if previous_latest else 'absent'
            after = observed_latest[0] if observed_latest else 'absent'
            handle.write(f'Latest image before publication: `{before}`\n\nLatest image after publication: `{after}`\n')
        if not latest and observed_latest != previous_latest:
            raise RuntimeError('latest changed during a prerelease or backport publication')
        notes = Path('gateway-release-notes.txt')
        notes.write_text(f'Waygate {version}\n\nSource commit: `{sha}`\n\nVerified image: `{repository}@{digest}`\n\nDeploy by digest. Source publication does not deploy.\n')
        args = ['gh', 'release', 'create', 'v' + version, '--verify-tag', '--title', 'Waygate ' + version,
                '--notes-file', str(notes), '--latest=' + str(latest).lower()]
        if parse_version(version)[1]:
            args.append('--prerelease')
        run(*args)
    with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a') as handle:
        handle.write(f'Published verified image: `{repository}@{digest}`\n')


if __name__ == '__main__':
    publish()
