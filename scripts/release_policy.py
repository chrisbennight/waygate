"""Release identity checks shared by source-repository workflows."""
import os
from pathlib import Path
import re
import subprocess
import tomllib


# Container tags cannot represent SemVer build metadata without changing it.
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?")


def parse_version(value):
    match = VERSION.fullmatch(value)
    if not match or len(value) > 120:
        raise ValueError("expected MAJOR.MINOR.PATCH with optional prerelease and no build metadata")
    prerelease = match[4]
    if prerelease and any(part.isdigit() and len(part) > 1 and part[0] == '0'
                          for part in prerelease.split('.')):
        raise ValueError("numeric prerelease identifiers cannot have leading zeros")
    return tuple(int(match[i]) for i in (1, 2, 3)), prerelease


def run(*args):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE).stdout.strip()


def workspace_version():
    with open('Cargo.toml', 'rb') as handle:
        value = tomllib.load(handle)['workspace']['package']['version']
    parse_version(value)
    return value


def release_version(ref, prefix, expected):
    if not ref.startswith('refs/tags/' + prefix):
        raise ValueError('unexpected release tag namespace')
    value = ref.removeprefix('refs/tags/' + prefix)
    parse_version(value)
    if value != expected:
        raise ValueError('release tag does not match the workspace version')
    return value


def require_merged(sha):
    if not re.fullmatch('[0-9a-f]{40}', sha):
        raise ValueError('expected a full source commit SHA')
    if run('git', 'rev-parse', 'HEAD') != sha:
        raise ValueError('checkout does not match the event commit')
    # Full-history checkout supplies origin/main, including in private repos
    # whose read-only checkout deliberately removes persisted credentials.
    run('git', 'merge-base', '--is-ancestor', sha, 'origin/main')


def image_plan(event, ref, sha, version):
    parse_version(version)
    if event in ('pull_request', 'workflow_dispatch'):
        return 'verify', ''
    if event != 'push':
        raise ValueError('unsupported image event')
    if ref == 'refs/heads/main':
        return 'main', ''
    return 'release', release_version(ref, 'v', version)


def main():
    version = workspace_version()
    sha = run('git', 'rev-parse', 'HEAD')
    kind, release = image_plan(os.environ['GITHUB_EVENT_NAME'], os.environ['GITHUB_REF'], sha, version)
    if kind == 'release':
        require_merged(os.environ['GITHUB_SHA'])
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as handle:
        handle.write(f'kind={kind}\nversion={release}\n')
    with Path(os.environ['GITHUB_ENV']).open('a') as handle:
        handle.write(f'GATEWAY_RELEASE_VERSION={release}\n')


if __name__ == '__main__':
    main()
