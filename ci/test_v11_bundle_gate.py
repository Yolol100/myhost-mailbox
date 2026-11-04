"""Offline safety checks for the GitHub-hosted V11 release verifier."""
import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from v11_bundle_gate import safe_extract, validate_release_url, run_zip_tests


class BundleGateTests(unittest.TestCase):
    def test_allow_only_owner_release(self):
        ok='https://github.com/Yolol100/myhost-mailbox/releases/download/v11/source.zip'
        self.assertEqual(validate_release_url(ok), ok)
        for value in ['http://github.com/Yolol100/myhost-mailbox/releases/download/x/a.zip',
                      'https://evil.invalid/source.zip',
                      'https://github.com/Yolol100/myhost-mailbox/releases/download/../bad.zip',
                      'https://github.com/Yolol100/Leadscanner/releases/download/x/a.zip']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_release_url(value)

    def test_reject_zip_slip(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'bad.zip'
            with zipfile.ZipFile(path,'w') as z:
                z.writestr('../outside.txt','bad')
            with self.assertRaises(ValueError):
                safe_extract(path,Path(d)/'dest')
            self.assertFalse((Path(d)/'outside.txt').exists())

    def test_reject_missing_app(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'incomplete.zip'
            with zipfile.ZipFile(path,'w') as z:
                z.writestr('not-the-app.txt','hello')
            with self.assertRaises(ValueError):
                safe_extract(path,Path(d)/'dest')

    def test_reject_incorrect_hash_before_running_source(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'fake.zip'
            with zipfile.ZipFile(path,'w') as z:
                z.writestr('MyApp/MijnHostConcepten.pyw','invalid')
                z.writestr('MyApp/concept_core.py','invalid')
            with self.assertRaisesRegex(ValueError,'SHA256'):
                run_zip_tests(path, '0'*64)


if __name__ == '__main__':
    unittest.main()
