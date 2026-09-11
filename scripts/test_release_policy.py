"""Release identity and publication contracts, without registry or forge access."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from release_policy import image_plan, parse_version, release_version, require_merged

spec = importlib.util.spec_from_file_location('publisher', Path(__file__).with_name('publish-gateway-image.py'))
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
SHA = 'a' * 40
DIGEST = 'sha256:' + 'b' * 64
REPO = 'ghcr.io/test/waygate'


class IdentityTests(unittest.TestCase):
    def test_event_publication_matrix(self):
        cases = [
            ('pull_request', 'refs/pull/1/merge', 'verify', ''),
            ('workflow_dispatch', 'refs/tags/v1.2.3', 'verify', ''),
            ('push', 'refs/heads/main', 'main', ''),
            ('push', 'refs/tags/v1.2.3', 'release', '1.2.3'),
        ]
        for event, ref, kind, version in cases:
            with self.subTest(event=event, ref=ref):
                self.assertEqual(image_plan(event, ref, SHA, '1.2.3'), (kind, version))
        for event, ref in [('push', 'refs/heads/topic'), ('push', 'refs/tags/mcp-files-v1.2.3'),
                           ('release', 'refs/tags/v1.2.3'), ('push', 'refs/tags/v2.0.0')]:
            with self.subTest(event=event, ref=ref), self.assertRaises(ValueError):
                image_plan(event, ref, SHA, '1.2.3')

    def test_version_validation(self):
        for version in ['0.1.0', '1.2.3-rc.1', '2.0.0-alpha-beta.0']:
            parse_version(version)
        for version in ['01.2.3', '1.2', '1.2.3-01', '1.2.3+build', '1.2.3\n',
                        '1.2.3-rc..1', '$(id)', '1.2.3/' , '1.2.3-' + 'a' * 120]:
            with self.subTest(version=version), self.assertRaises(ValueError):
                parse_version(version)

    def test_helper_namespace_and_version_agreement(self):
        self.assertEqual(release_version('refs/tags/mcp-files-v1.2.3', 'mcp-files-v', '1.2.3'), '1.2.3')
        with self.assertRaises(ValueError):
            release_version('refs/tags/v1.2.3', 'mcp-files-v', '1.2.3')

    def test_ancestry_uses_real_git_and_rejects_unmerged_or_wrong_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            def git(*args):
                return subprocess.check_output(['git', '-C', directory, *args], text=True).strip()
            git('init', '-q', '-b', 'main')
            git('config', 'user.name', 'Release test')
            git('config', 'user.email', 'test@example.com')
            git('commit', '-q', '--allow-empty', '-m', 'main')
            merged = git('rev-parse', 'HEAD')
            git('update-ref', 'refs/remotes/origin/main', merged)
            previous = Path.cwd()
            try:
                os.chdir(directory)
                require_merged(merged)
                git('checkout', '-q', '-b', 'topic')
                git('commit', '-q', '--allow-empty', '-m', 'unmerged')
                with self.assertRaises(subprocess.CalledProcessError):
                    require_merged(git('rev-parse', 'HEAD'))
                with self.assertRaises(ValueError):
                    require_merged(merged)
            finally:
                os.chdir(previous)


class PublishTests(unittest.TestCase):
    def test_stable_channel_selection(self):
        def current(version):
            return DIGEST, {publisher.RELEASE_LABEL: version}
        for version, previous, expected in [
            ('1.2.3-rc.1', None, False), ('1.2.3', None, True),
            ('1.2.3', (DIGEST, {}), True),
            ('1.2.3', current('1.2.2'), True), ('1.2.3', current('1.2.3'), False),
            ('1.2.3', current('1.3.0'), False), ('1.10.0', current('1.9.0'), True),
            ('0.2.0', current('0.1.9'), True),
        ]:
            with self.subTest(version=version, previous=previous):
                self.assertEqual(publisher.advance_latest(version, previous), expected)
        with self.assertRaises(ValueError):
            publisher.advance_latest('1.2.3', current('1.2.3-rc.1'))

    def test_inspection_failures_do_not_become_absence(self):
        for error in ['unauthorized', 'connection refused', 'unexpected response 500', 'parse error']:
            result = subprocess.CompletedProcess([], 1, '', error)
            with patch.object(publisher.subprocess, 'run', return_value=result), self.assertRaises(RuntimeError):
                publisher.remote_image(REPO + ':1.2.3')
        for error in ['ERROR: ghcr.io/test/waygate:1.2.3: not found', 'manifest unknown']:
            result = subprocess.CompletedProcess([], 1, '', error)
            with patch.object(publisher.subprocess, 'run', return_value=result):
                self.assertIsNone(publisher.remote_image(REPO + ':1.2.3'))
        result = subprocess.CompletedProcess([], 0, json.dumps({'manifest': {'digest': DIGEST}, 'image': {'config': {'Labels': {'revision': SHA}}}}), '')
        with patch.object(publisher.subprocess, 'run', return_value=result):
            self.assertEqual(publisher.remote_image(REPO), (DIGEST, {'revision': SHA}))

    def exercise_publish(self, version, existing=False, latest_version=None, event='push'):
        commands, images = [], {}
        if existing:
            images[REPO + ':' + version] = DIGEST, {}
        if latest_version:
            images[REPO + ':latest'] = DIGEST, {publisher.RELEASE_LABEL: latest_version}
        labels = {'org.opencontainers.image.revision': SHA, publisher.RELEASE_LABEL: version}
        def command(*args):
            commands.append(args)
            if args == ('git', 'rev-parse', 'HEAD'):
                return SHA
            if args[:3] == ('docker', 'image', 'inspect'):
                return json.dumps(labels)
            if args[:2] == ('docker', 'push'):
                images[args[2]] = DIGEST, labels
            return ''
        with tempfile.TemporaryDirectory() as directory:
            previous = Path.cwd()
            try:
                os.chdir(directory)
                env = {'GITHUB_EVENT_NAME': event, 'GITHUB_REF': 'refs/tags/v' + version,
                       'GITHUB_SHA': SHA, 'GITHUB_REPOSITORY': 'Test/Waygate',
                       'GATEWAY_IMAGE_PINNED': REPO + ':sha-' + SHA,
                       'GITHUB_STEP_SUMMARY': str(Path(directory) / 'summary')}
                with patch.dict(os.environ, env), patch.object(publisher, 'run', side_effect=command), \
                     patch.object(publisher, 'workspace_version', return_value=version), \
                     patch.object(publisher, 'require_merged'), \
                     patch.object(publisher, 'remote_image', side_effect=lambda ref: images.get(ref)):
                    if existing or event == 'workflow_dispatch':
                        with self.assertRaises(ValueError):
                            publisher.publish()
                        self.assertFalse(any(c[:2] in [('docker', 'push'), ('gh', 'release')] for c in commands))
                    else:
                        publisher.publish()
                        self.assertIn(DIGEST, Path('gateway-release-notes.txt').read_text())
            finally:
                os.chdir(previous)
        return commands

    def test_stable_publish_and_release_notes(self):
        commands = self.exercise_publish('1.2.3')
        self.assertIn(('docker', 'push', REPO + ':latest'), commands)
        self.assertTrue(any(c[:3] == ('gh', 'release', 'create') and '--latest=true' in c for c in commands))

    def test_prerelease_and_backport_do_not_advance_latest(self):
        for version, latest in [('1.2.3-rc.1', None), ('1.2.3', '2.0.0')]:
            commands = self.exercise_publish(version, latest_version=latest)
            self.assertNotIn(('docker', 'push', REPO + ':latest'), commands)
            release = next(c for c in commands if c[:3] == ('gh', 'release', 'create'))
            self.assertIn('--latest=false', release)
            self.assertEqual('--prerelease' in release, '-' in version)

    def test_main_publishes_edge_but_not_latest_or_a_release(self):
        commands = []
        labels = {'org.opencontainers.image.revision': SHA, publisher.RELEASE_LABEL: ''}
        def command(*args):
            commands.append(args)
            if args == ('git', 'rev-parse', 'HEAD'):
                return SHA
            if args[:3] == ('docker', 'image', 'inspect'):
                return json.dumps(labels)
            return ''
        with tempfile.TemporaryDirectory() as directory:
            env = {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REF': 'refs/heads/main',
                   'GITHUB_SHA': SHA, 'GITHUB_REPOSITORY': 'Test/Waygate',
                   'GATEWAY_IMAGE_PINNED': REPO + ':sha-' + SHA,
                   'GITHUB_STEP_SUMMARY': str(Path(directory) / 'summary')}
            for newer_edge in (False, True):
                commands.clear()
                def remote(ref):
                    if ref.endswith(':edge'):
                        return DIGEST, {'org.opencontainers.image.revision': 'c' * 40}
                    return DIGEST, labels
                with patch.dict(os.environ, env), patch.object(publisher, 'run', side_effect=command), \
                     patch.object(publisher, 'workspace_version', return_value='1.2.3'), \
                     patch.object(publisher, 'require_merged'), \
                     patch.object(publisher, 'remote_image', side_effect=remote), \
                     patch.object(publisher.subprocess, 'run', return_value=subprocess.CompletedProcess([], int(newer_edge))):
                    publisher.publish()
                self.assertIn(('docker', 'push', REPO + ':sha-' + SHA), commands)
                self.assertEqual(('docker', 'push', REPO + ':edge') in commands, not newer_edge)
                self.assertNotIn(('docker', 'push', REPO + ':latest'), commands)
                self.assertFalse(any(c[:2] == ('gh', 'release') for c in commands))

    def test_existing_version_and_manual_run_never_publish(self):
        self.exercise_publish('1.2.3', existing=True)
        self.exercise_publish('1.2.3', event='workflow_dispatch')


if __name__ == '__main__':
    unittest.main()
