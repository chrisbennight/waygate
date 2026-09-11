"""Validate the shared helper version and explicit release tag before building."""
import os
from pathlib import Path

from release_policy import release_version, require_merged, workspace_version


def resolve(event, ref, expected, recorded, requested=''):
    if recorded != expected:
        raise ValueError('release/mcp-files.version must match workspace.package.version')
    if requested and requested != expected:
        raise ValueError('manual verification version must match workspace.package.version')
    if event == 'push':
        return release_version(ref, 'mcp-files-v', expected)
    if event not in ('pull_request', 'workflow_dispatch'):
        raise ValueError('unsupported helper event')
    return expected


def main():
    event = os.environ['GITHUB_EVENT_NAME']
    version = resolve(event, os.environ['GITHUB_REF'], workspace_version(),
                      Path('release/mcp-files.version').read_text().strip(),
                      os.environ.get('INPUT_VERSION', ''))
    if event != 'pull_request':
        require_merged(os.environ['GITHUB_SHA'])
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as handle:
        handle.write(f'version={version}\n')


if __name__ == '__main__':
    main()
