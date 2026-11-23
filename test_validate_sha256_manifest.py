import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name('scripts') / 'validate_sha256_manifest.py'


class ValidateSha256ManifestTests(unittest.TestCase):
    def make_repo(self, root):
        (root / '.github/workflows').mkdir(parents=True)
        (root / '.github/workflows/ci.yml').write_text('workflow\n', encoding='utf-8')
        (root / 'uv.lock').write_text('lock\n', encoding='utf-8')

    def run_validator(self, root):
        return subprocess.run(
            [sys.executable, str(SCRIPT), '--root', str(root)],
            capture_output=True, text=True, check=False,
        )

    def test_valid_manifest_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_repo(root)
            content = b'payload\n'
            (root / 'payload.txt').write_bytes(content)
            entries = [
                {'path': 'payload.txt', 'sha256': hashlib.sha256(content).hexdigest(),
                 'bytes': len(content)},
                {'path': 'uv.lock', 'sha256': hashlib.sha256(b'lock\n').hexdigest(),
                 'bytes': 5},
                {'path': '.github/workflows/ci.yml',
                 'sha256': hashlib.sha256(b'workflow\n').hexdigest(), 'bytes': 9},
            ]
            (root / 'SHA256_MANIFEST.json').write_text(
                json.dumps({'files': entries}), encoding='utf-8')

            result = self.run_validator(root)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('SHA256 manifest PASS (3 files)', result.stdout)

    def test_reports_every_digest_and_size_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_repo(root)
            (root / 'first.txt').write_text('current first\n', encoding='utf-8')
            (root / 'second.txt').write_text('current second\n', encoding='utf-8')
            entries = [
                {'path': 'first.txt', 'sha256': '0' * 64, 'bytes': 0},
                {'path': 'second.txt', 'sha256': '0' * 64, 'bytes': 0},
                {'path': 'uv.lock', 'sha256': hashlib.sha256(b'lock\n').hexdigest(),
                 'bytes': 5},
                {'path': '.github/workflows/ci.yml',
                 'sha256': hashlib.sha256(b'workflow\n').hexdigest(), 'bytes': 9},
            ]
            (root / 'SHA256_MANIFEST.json').write_text(
                json.dumps({'files': entries}), encoding='utf-8')

            result = self.run_validator(root)

            self.assertNotEqual(result.returncode, 0)
            for path in ('first.txt', 'second.txt'):
                self.assertIn(f'SHA-256 mismatch: {path}', result.stderr)
                self.assertIn(f'size mismatch: {path}', result.stderr)


if __name__ == '__main__':
    unittest.main()
