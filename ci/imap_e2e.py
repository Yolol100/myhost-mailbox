"""Black-box IMAPS test against a short-lived, isolated Dovecot test account.

Never point this at a production host: the safety guard is deliberately strict.
No real credentials, customers, SMTP, or permanent mailbox data are used.
"""
from __future__ import annotations

import base64
import os
import socket
import ssl
import sys
import time
from email import policy
from email.parser import BytesParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import myhost_mailbox as mailbox  # noqa: E402

HOST = 'localhost'
PORT = 19993
ACCOUNT = 'ci-fake@example.invalid'
PASSWORD = 'synthetic-ci-password-only'


def require_isolation():
    if os.environ.get('MAILBOX_CI_ISOLATED') != 'yes':
        raise RuntimeError('Isolated mailbox test guard is missing')
    expected = {
        'OUTREACH_IMAP_HOST': HOST,
        'OUTREACH_IMAP_PORT': str(PORT),
        'OUTREACH_MAIL_USER': ACCOUNT,
        'OUTREACH_MAIL_PASSWORD': PASSWORD,
    }
    for name, value in expected.items():
        if os.environ.get(name) != value:
            raise RuntimeError('Blocked: unexpected IMAP configuration: ' + name)
    cert = Path(os.environ.get('SSL_CERT_FILE', ''))
    if not cert.is_file():
        raise RuntimeError('Blocked: no trusted isolated CA certificate')
    return cert


def wait_until_ready(timeout=75):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with socket.create_connection(('127.0.0.1', PORT), timeout=1):
                return
        except OSError:
            time.sleep(.75)
    raise RuntimeError('Isolated Dovecot did not start')


def test_tls_and_login(cert):
    context = ssl.create_default_context(cafile=str(cert))
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    with socket.create_connection(('127.0.0.1', PORT), timeout=5) as tcp:
        with context.wrap_socket(tcp, server_hostname=HOST) as connection:
            assert connection.version() in ('TLSv1.2', 'TLSv1.3')
    try:
        with socket.create_connection(('127.0.0.1', PORT), timeout=5) as tcp:
            with context.wrap_socket(tcp, server_hostname='wrong-host.example.invalid'):
                pass
    except ssl.SSLCertVerificationError:
        pass
    else:
        raise AssertionError('TLS accepted an invalid server hostname')
    import imaplib
    client = imaplib.IMAP4_SSL(HOST, port=PORT, ssl_context=context, timeout=15)
    try:
        try:
            client.login(ACCOUNT, 'deliberately-wrong-password')
        except imaplib.IMAP4.error:
            pass
        else:
            raise AssertionError('IMAP accepted an incorrect password')
    finally:
        try:
            client.logout()
        except Exception:
            pass


def attachment_bytes(msg):
    return [(part.get_filename(), part.get_payload(decode=True))
            for part in msg.walk() if part.get_content_disposition() == 'attachment']


def test_draft_lifecycle():
    client = mailbox.connect_imap()
    try:
        caps = mailbox.capabilities(client)
        if 'UIDPLUS' not in caps:
            raise AssertionError('Dovecot test image unexpectedly lacks UIDPLUS')
        for folder in ('Drafts', 'Trash'):
            status, _ = client.create(folder)
            if status not in ('OK', 'NO'):
                raise AssertionError('Unable to prepare test folder')
        payload = {
            'to': 'first-recipient@example.invalid',
            'cc': 'copy-recipient@example.invalid',
            'subject': 'E2E original subject',
            'body_text': 'E2E original body with unicode: cafe\u0301',
            'attachments': [{
                'filename': 'synthetic.txt',
                'content_type': 'text/plain',
                'content_base64': base64.b64encode(b'synthetic attachment').decode(),
            }],
        }
        first_uid = mailbox.append_draft(client, 'Drafts', payload)
        untouched_uid = mailbox.append_draft(client, 'Drafts', {
            'to': 'second-recipient@example.invalid',
            'subject': 'Keep unchanged', 'body_text': 'Do not edit this draft',
        })
        before = mailbox.fetch_message(client, 'Drafts', first_uid)
        assert str(before['Subject']) == payload['subject']
        assert attachment_bytes(before) == [('synthetic.txt', b'synthetic attachment')]
        assert str(before['To']) == payload['to']
        assert str(before['Cc']) == payload['cc']
        changed = dict(payload, subject='E2E updated subject', body_text='E2E updated body')
        new_uid = mailbox.replace_draft(client, 'Drafts', first_uid, changed)
        uids = set(mailbox.list_message_uids(client, 'Drafts', limit=20))
        assert first_uid not in uids
        assert new_uid in uids and untouched_uid in uids
        updated = mailbox.fetch_message(client, 'Drafts', new_uid)
        assert str(updated['Subject']) == changed['subject']
        assert updated.get_body(preferencelist=('plain',)).get_content().strip() == changed['body_text']
        assert str(updated['To']) == payload['to']
        assert str(updated['Cc']) == payload['cc']
        assert attachment_bytes(updated) == [('synthetic.txt', b'synthetic attachment')]
        untouched = mailbox.fetch_message(client, 'Drafts', untouched_uid)
        assert str(untouched['Subject']) == 'Keep unchanged'
        mailbox.delete_message(client, 'Drafts', untouched_uid)
        after_delete = set(mailbox.list_message_uids(client, 'Drafts', limit=20))
        assert untouched_uid not in after_delete and new_uid in after_delete
        print('ISOLATED_IMAPS_E2E=PASS tls=verified auth=verified create=2 '
              'replace=1 delete=1 attachments=preserved other_messages=preserved sent=0')
    finally:
        try:
            client.logout()
        except Exception:
            pass


def main():
    cert = require_isolation()
    wait_until_ready()
    test_tls_and_login(cert)
    test_draft_lifecycle()


if __name__ == '__main__':
    main()
