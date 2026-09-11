"""Helper publication starts only from explicit tags with consistent versions."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from helper_release import resolve

SCRIPT = Path(__file__).resolve().with_name('helper_release.py')


class HelperReleaseTests(unittest.TestCase):
    def test_supported_events_and_version_agreement(self):
        for event, ref in [('push', 'refs/tags/mcp-files-v1.2.3'),
                           ('pull_request', 'refs/pull/1/merge'),
                           ('workflow_dispatch', 'refs/heads/main')]:
            self.assertEqual(resolve(event, ref, '1.2.3', '1.2.3'), '1.2.3')
        for event, ref, recorded, requested in [
            ('push', 'refs/heads/main', '1.2.3', ''),
            ('push', 'refs/tags/v1.2.3', '1.2.3', ''),
            ('push', 'refs/tags/mcp-files-v2.0.0', '1.2.3', ''),
            ('pull_request', 'refs/pull/1/merge', '1.2.2', ''),
            ('workflow_dispatch', 'refs/heads/main', '1.2.3', '2.0.0'),
            ('workflow_dispatch', 'refs/heads/main', '1.2.3', '$(id)'),
            ('release', 'refs/tags/mcp-files-v1.2.3', '1.2.3', ''),
        ]:
            with self.subTest(event=event, ref=ref), self.assertRaises(ValueError):
                resolve(event, ref, '1.2.3', recorded, requested)

    def test_script_validates_real_checkout_before_emitting_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(['git', '-C', directory, *args], text=True).strip()
            git('init', '-q', '-b', 'main')
            git('config', 'user.name', 'Release test')
            git('config', 'user.email', 'test@example.com')
            (root / 'Cargo.toml').write_text('[workspace.package]\nversion = "1.2.3-rc.1"\n')
            (root / 'release').mkdir()
            (root / 'release/mcp-files.version').write_text('1.2.3-rc.1\n')
            git('add', 'Cargo.toml', 'release')
            git('commit', '-q', '-m', 'release')
            sha = git('rev-parse', 'HEAD')
            git('update-ref', 'refs/remotes/origin/main', sha)
            output = root / 'output'
            env = {**os.environ, 'GITHUB_EVENT_NAME': 'push',
                   'GITHUB_REF': 'refs/tags/mcp-files-v1.2.3-rc.1',
                   'GITHUB_SHA': sha, 'GITHUB_OUTPUT': str(output), 'INPUT_VERSION': ''}
            def invoke():
                return subprocess.run(['python3', str(SCRIPT)], cwd=root, env=env,
                                      capture_output=True, text=True)
            self.assertEqual(invoke().returncode, 0)
            self.assertEqual(output.read_text(), 'version=1.2.3-rc.1\n')
            output.unlink()
            git('checkout', '-q', '-b', 'unmerged')
            git('commit', '-q', '--allow-empty', '-m', 'unmerged')
            env['GITHUB_SHA'] = git('rev-parse', 'HEAD')
            self.assertNotEqual(invoke().returncode, 0)
            self.assertFalse(output.exists())
            env['GITHUB_EVENT_NAME'] = 'pull_request'
            self.assertEqual(invoke().returncode, 0)


if __name__ == '__main__':
    unittest.main()
