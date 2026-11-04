"""Offline safety checks for the GitHub-hosted V11 release verifier."""
import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from v11_bundle_gate import (safe_extract, validate_release_url, run_zip_tests,
                             MANDATORY_BUNDLE_FILES)


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

    def _synthetic_archive(self, root, *, corrupt=False):
        root = Path(root)
        archive = root / 'almost_v11.zip'
        test_stub = ("import unittest\n"
                     "class TestStub(unittest.TestCase):\n"
                     "    def test_fake(self): self.assertTrue(True)\n")
        files = {name: test_stub if name.startswith('test_') else '# fake\n'
                 for name in MANDATORY_BUNDLE_FILES if name != 'SHA256SUMS.txt'}
        manifest = ''.join(hashlib.sha256(value.encode()).hexdigest() + '  ' + name + '\n'
                           for name, value in sorted(files.items()))
        if corrupt:
            manifest = manifest.replace(next(iter(files)), 'different_file.py', 1)
        with zipfile.ZipFile(archive, 'w') as z:
            for name, content in files.items():
                z.writestr('Fake_V11/' + name, content)
            z.writestr('Fake_V11/SHA256SUMS.txt', manifest)
        return archive

    def test_reject_trivial_test_suite_even_when_all_files_present(self):
        with tempfile.TemporaryDirectory() as d:
            archive = self._synthetic_archive(d)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            with self.assertRaisesRegex(RuntimeError, 'Insufficient V11 tests'):
                run_zip_tests(archive, digest)

    def test_reject_tampered_sha256_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            archive = self._synthetic_archive(d, corrupt=True)
            with self.assertRaisesRegex(ValueError, 'manifest'):
                safe_extract(archive, Path(d) / 'extracted')

    def test_reject_duplicate_zip_entries(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'duplicated.zip'
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                with zipfile.ZipFile(path,'w') as z:
                    z.writestr('App/x.py','first')
                    z.writestr('App/x.py','second')
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                safe_extract(path, Path(d)/'out')

    def _synthetic_archive(self, folder, *, corrupt=False):
        folder = Path(folder)
        archive = folder / 'almost_v11.zip'
        test_stub = ("import unittest\n"
                     "class TestStub(unittest.TestCase):\n"
                     "    def test_fake(self): self.assertTrue(True)\n")
        from v11_bundle_gate import MANDATORY_BUNDLE_FILES
        files = {name: test_stub if name.startswith('test_') else '# fake\n'
                 for name in MANDATORY_BUNDLE_FILES if name != 'SHA256SUMS.txt'}
        manifest = ''.join(hashlib.sha256(content.encode()).hexdigest() + '  ' + name + '\n'
                           for name, content in sorted(files.items()))
        if corrupt:
            manifest = manifest.replace(next(iter(files)), 'different_file.py', 1)
        with zipfile.ZipFile(archive, 'w') as z:
            for name, content in files.items():
                z.writestr('Fake_V11/' + name, content)
            z.writestr('Fake_V11/SHA256SUMS.txt', manifest)
        return archive

    def test_reject_trivial_test_suite_even_with_expected_files(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = self._synthetic_archive(temp)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            with self.assertRaisesRegex(RuntimeError, 'Insufficient V11 tests'):
                run_zip_tests(archive, digest)

    def test_reject_manifest_tampering(self):
        with tempfile.TemporaryDirectory() as temp:
            archive = self._synthetic_archive(temp, corrupt=True)
            with self.assertRaisesRegex(ValueError, 'manifest'):
                safe_extract(archive, Path(temp) / 'extract')

    def test_reject_duplicate_zip_entries(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'duplicated.zip'
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                with zipfile.ZipFile(path, 'w') as z:
                    z.writestr('App/x.py', 'first')
                    z.writestr('App/x.py', 'second')
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                safe_extract(path, Path(temp) / 'extract')

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
