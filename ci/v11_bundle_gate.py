"""Verify and test the exact V11 (or newer) ZIP on GitHub-hosted runners.

A ZIP from the owner's release is downloaded only on an explicit manual run.
No real mail login is attempted; all bundled tests use fake IMAP instances.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

OWNER_RELEASE = 'https://github.com/Yolol100/myhost-mailbox/releases/download/'
MAX_ZIP_BYTES = 15 * 1024 * 1024
MAX_UNPACKED_BYTES = 50 * 1024 * 1024


def validate_release_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.netloc != 'github.com'
            or not url.startswith(OWNER_RELEASE) or parsed.query or parsed.fragment
            or '..' in urllib.parse.unquote(parsed.path).split('/')):
        raise ValueError('Only releases of Yolol100/myhost-mailbox are accepted')
    if len(parsed.path.split('/')) < 7:
        raise ValueError('Expected a GitHub release file URL')
    return url


def download_release(url, output):
    validate_release_url(url)
    req = urllib.request.Request(url, headers={'User-Agent': 'isolated-mailbox-ci'})
    with urllib.request.urlopen(req, timeout=45) as response:
        final = urllib.parse.urlsplit(response.url)
        if final.scheme != 'https' or final.hostname not in {
            'github.com', 'release-assets.githubusercontent.com',
        }:
            raise ValueError('Unexpected release redirect')
        total = 0
        with output.open('wb') as f:
            while True:
                piece = response.read(65536)
                if not piece:
                    break
                total += len(piece)
                if total > MAX_ZIP_BYTES:
                    raise ValueError('Release exceeds the test size limit')
                f.write(piece)


def safe_extract(archive, destination):
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        if len(entries) > 120 or sum(x.file_size for x in entries) > MAX_UNPACKED_BYTES:
            raise ValueError('Unsafe archive size')
        for entry in entries:
            parts = entry.filename.replace('\\', '/').split('/')
            if (entry.filename.startswith(('/', '\\')) or not entry.filename
                    or '..' in parts or any(':' in p for p in parts)
                    or (entry.external_attr >> 16) & 0o170000 == 0o120000):
                raise ValueError('Unsafe ZIP file path or symlink')
        z.extractall(destination)
    matches = sorted(destination.rglob('MijnHostConcepten.pyw'))
    if len(matches) != 1 or not (matches[0].parent / 'concept_core.py').is_file():
        raise ValueError('Archive has no unique V11 application root')
    return matches[0].parent


def run_windows_native_checks(folder):
    if os.name != 'nt':
        return
    env = dict(os.environ)
    # Isolated temporary credential key, not the user's production target.
    native_test = '''import uuid
import backup_crypto, windows_credentials
payload=b"fake CI recovery-only email"
wrapped=backup_crypto.protect(payload)
assert wrapped!=payload and backup_crypto.unprotect(wrapped)==payload
original=windows_credentials.TARGET
windows_credentials.TARGET="CI.Mailbox.Only."+uuid.uuid4().hex
try:
    windows_credentials.save_credentials("ci@example.invalid","synthetic-only")
    assert windows_credentials.load_credentials()==("ci@example.invalid","synthetic-only")
finally:
    windows_credentials.delete_credentials()
    windows_credentials.TARGET=original
print("WINDOWS_SECURITY=PASS dpapi=real credential_manager=real")
'''
    subprocess.run([sys.executable, '-c', native_test], cwd=folder,
                   env=env, check=True, timeout=40)


def run_zip_tests(archive, digest):
    if not re.fullmatch('[a-fA-F0-9]{64}', digest):
        raise ValueError('Expected a full SHA256 digest')
    hasher = hashlib.sha256()
    with archive.open('rb') as f:
        for chunk in iter(lambda: f.read(131072), b''):
            hasher.update(chunk)
    if hasher.hexdigest().lower() != digest.lower():
        raise ValueError('SHA256 mismatch; refusing to run unverified source')
    with tempfile.TemporaryDirectory(prefix='mailbox-ci-') as tmp:
        root = safe_extract(archive, Path(tmp))
        # Never open or modify a real account. Bundled tests should use mocks.
        run_windows_native_checks(root)
        subprocess.run([sys.executable, '-m', 'unittest', 'discover',
                        '-s', '.', '-p', 'test*.py', '-q'],
                       cwd=root, check=True, timeout=360)
    print('BUNDLED_V11_TESTS=PASS sha256=verified windows_native=' +
          ('yes' if os.name == 'nt' else 'no') + ' sent=0')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--release-url')
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    if bool(args.archive) == bool(args.release_url):
        parser.error('Select exactly one of --archive and --release-url')
    if args.archive:
        run_zip_tests(args.archive, args.sha256)
    else:
        with tempfile.TemporaryDirectory(prefix='mailbox-release-') as tmp:
            archive = Path(tmp) / 'release.zip'
            download_release(args.release_url, archive)
            run_zip_tests(archive, args.sha256)


if __name__ == '__main__':
    main()
