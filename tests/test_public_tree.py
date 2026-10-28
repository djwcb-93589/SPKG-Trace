import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('public_checks', ROOT / 'scripts/check_public_tree.py')
CHECKS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKS)


class PublicTreeTests(unittest.TestCase):
    def test_source_boundary(self):
        report = CHECKS.scan(ROOT)
        self.assertTrue(report['passed'], report['findings'])

    def test_detects_secret_without_echoing_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secret = 'synthetic-' + 'credential-value'
            (root / 'README.md').write_text(secret, encoding='utf-8')
            report = CHECKS.scan(root, [secret])
            self.assertFalse(report['passed'])
            self.assertNotIn(secret, str(report))

    def test_rejects_frontend_and_environment_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'app.html').write_text('sample', encoding='utf-8')
            (root / '.env.local').write_text('sample', encoding='utf-8')
            self.assertEqual(len(CHECKS.scan(root)['findings']), 2)
