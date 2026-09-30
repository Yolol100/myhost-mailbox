from __future__ import annotations

import base64
import os
import unittest
from email.message import EmailMessage
from unittest.mock import patch

import myhost_mailbox as m


class FakeIMAP:
    def __init__(self, caps=b"IMAP4rev1 UIDPLUS MOVE"):
        self.caps = caps
        self.uid_calls = []
        self.appended = []
        self.search_result = b"7"
        self.messages = {"7": self._raw("hello", "Body")}

    @staticmethod
    def _raw(subject, body):
        msg = EmailMessage()
        msg["From"] = "sender@example.test"
        msg["To"] = "me@example.test"
        msg["Subject"] = subject
        msg["Message-ID"] = "<m1@example.test>"
        msg.set_content(body)
        return msg.as_bytes()

    def capability(self):
        return "OK", [self.caps]

    def list(self):
        return "OK", [b'(\\HasNoChildren) "/" "INBOX"', b'(\\HasNoChildren \\Drafts) "/" "Drafts"']

    def select(self, folder, readonly=True):
        return "OK", [b"1"]

    def uid(self, command, *args):
        self.uid_calls.append((command.lower(), args))
        command = command.lower()
        if command == "search":
            return "OK", [self.search_result]
        if command == "fetch":
            return "OK", [(b"7 (RFC822)", self.messages[str(args[0])])]
        return "OK", [b""]

    def create(self, folder):
        return "OK", [b""]

    def rename(self, old, new):
        return "OK", [b""]

    def delete(self, folder):
        return "OK", [b""]

    def append(self, folder, flags, date_time, raw):
        self.appended.append((folder, flags, raw))
        return "OK", [b""]

    def logout(self):
        return "BYE", [b""]


class FakeSMTP:
    def __init__(self, refused=None):
        self.sent = []
        self.refused = refused or {}

    def send_message(self, msg):
        self.sent.append(msg)
        return self.refused

    def quit(self):
        pass


class MailboxTests(unittest.TestCase):
    def test_list_search_read(self):
        client = FakeIMAP()
        self.assertEqual(m.list_folders(client), ["INBOX", "Drafts"])
        self.assertEqual(m.list_message_uids(client, "INBOX"), ["7"])
        self.assertEqual(m.search_messages(client, "INBOX", subject_text="hello"), ["7"])
        msg = m.fetch_message(client, "INBOX", "7")
        self.assertEqual(m.serialize_message(msg)["body_text"], "Body")

    def test_safe_delete_requires_uidplus(self):
        client = FakeIMAP(caps=b"IMAP4rev1")
        with self.assertRaises(RuntimeError):
            m.delete_message(client, "INBOX", "7")
        self.assertFalse(any(call[0] == "store" for call in client.uid_calls))

    def test_safe_delete_uses_uid_expunge(self):
        client = FakeIMAP()
        m.delete_message(client, "INBOX", "7")
        commands = [call[0] for call in client.uid_calls]
        self.assertEqual(commands[-2:], ["store", "expunge"])

    def test_move_prefers_move_capability(self):
        client = FakeIMAP()
        m.move_message(client, "INBOX", "7", "Archive")
        self.assertEqual(client.uid_calls[-1][0], "move")

    def test_append_draft_has_exact_readback(self):
        client = FakeIMAP()
        uid = m.append_draft(client, "Drafts", {"to": "person@example.test", "subject": "Test", "body_text": "Hello"})
        self.assertEqual(uid, "7")
        self.assertIn(b"X-Webactueel-Mailbox-Operation-ID:", client.appended[0][2])

    def test_append_draft_unknown_outcome_when_not_unique(self):
        client = FakeIMAP()
        client.search_result = b"7 8"
        with self.assertRaises(m.UnknownOutcomeError):
            m.append_draft(client, "Drafts", {"to": "person@example.test", "subject": "Test", "body_text": "Hello"})

    def test_attachment_limits_on_write(self):
        too_many = [{"filename": "a.bin", "content_base64": ""}] * 21
        with self.assertRaises(ValueError):
            m.build_message({"to": "person@example.test", "subject": "Test", "body_text": "Hello", "attachments": too_many})

    def test_attachment_metadata_without_content(self):
        msg = m.build_message({
            "to": "person@example.test",
            "subject": "Test",
            "body_text": "Hello",
            "attachments": [{
                "filename": "a.txt",
                "content_type": "text/plain",
                "content_base64": base64.b64encode(b"hi").decode(),
            }],
        })
        data = m.serialize_message(msg, include_attachment_content=False)
        self.assertEqual(data["attachments"][0]["size"], 2)
        self.assertNotIn("content_base64", data["attachments"][0])

    def test_reply_all_excludes_own_address_and_duplicates(self):
        source = EmailMessage()
        source["From"] = "sender@example.test"
        source["To"] = "me@example.test, other@example.test"
        source["Cc"] = "other@example.test, third@example.test"
        source["Subject"] = "Question"
        source["Message-ID"] = "<x@example.test>"
        source.set_content("Original")
        with patch.dict(os.environ, {"OUTREACH_MAIL_USER": "me@example.test", "OUTREACH_SENDER_EMAIL": "me@example.test"}, clear=False):
            reply = m.reply_payload(source, "Answer", reply_all=True)
        self.assertEqual(reply["to"], ["sender@example.test"])
        self.assertEqual(reply["cc"], ["other@example.test", "third@example.test"])

    def test_send_requires_double_gate(self):
        payload = {"to": "person@example.test", "subject": "Test", "body_text": "Hello"}
        with patch.dict(os.environ, {m.SEND_ENABLE_ENV: "false"}, clear=False):
            with self.assertRaises(RuntimeError):
                m.send_message(payload, confirm_send=True, smtp_factory=lambda: FakeSMTP())
        with patch.dict(os.environ, {m.SEND_ENABLE_ENV: "true"}, clear=False):
            with self.assertRaises(RuntimeError):
                m.send_message(payload, confirm_send=False, smtp_factory=lambda: FakeSMTP())

    def test_send_explicit_success(self):
        payload = {"to": "person@example.test", "subject": "Test", "body_text": "Hello"}
        smtp = FakeSMTP()
        with patch.dict(os.environ, {m.SEND_ENABLE_ENV: "true"}, clear=False):
            result = m.send_message(payload, confirm_send=True, smtp_factory=lambda: smtp)
        self.assertTrue(result["sent"])
        self.assertEqual(len(smtp.sent), 1)

    def test_rejects_invalid_uid_before_mutation(self):
        client = FakeIMAP()
        with self.assertRaises(ValueError):
            m.delete_message(client, "INBOX", "7:9")
        self.assertEqual(client.uid_calls, [])


if __name__ == "__main__":
    unittest.main()
