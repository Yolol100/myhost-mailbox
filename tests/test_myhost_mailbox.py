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
        self.messages = {"7": self._raw("hello", "Body", "<m1@example.test>")}

    @staticmethod
    def _raw(subject, body, message_id, *, in_reply_to=None):
        msg = EmailMessage()
        msg["From"] = "sender@example.test"
        msg["To"] = "me@example.test"
        msg["Subject"] = subject
        msg["Message-ID"] = message_id
        if in_reply_to:
            msg["In-Reply-To"] = in_reply_to
        msg.set_content(body)
        return msg.as_bytes()

    def capability(self):
        return "OK", [self.caps]

    def list(self):
        return "OK", [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\HasNoChildren \\Drafts) "/" "Drafts"',
            b'(\\HasNoChildren \\Sent) "/" "Sent"',
            b'(\\HasNoChildren \\Archive) "/" "Archive"',
            b'(\\HasNoChildren \\Trash) "/" "Trash"',
        ]

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
    def test_special_folder_detection(self):
        client = FakeIMAP()
        self.assertEqual(m.find_special_folder(client, "drafts"), "Drafts")
        self.assertEqual(m.find_special_folder(client, "sent"), "Sent")
        self.assertEqual(m.find_special_folder(client, "archive"), "Archive")

    def test_list_search_read(self):
        client = FakeIMAP()
        self.assertEqual(m.list_message_uids(client, "INBOX"), ["7"])
        self.assertEqual(m.search_message_uids(client, "INBOX", subject_text="hello"), ["7"])
        msg = m.fetch_message(client, "INBOX", "7")
        self.assertEqual(m.serialize_message(msg)["body_text"], "Body")

    def test_list_summaries(self):
        rows = m.list_message_summaries(FakeIMAP(), "INBOX")
        self.assertEqual(rows[0]["uid"], "7")
        self.assertEqual(rows[0]["subject"], "hello")

    def test_safe_delete_requires_uidplus(self):
        client = FakeIMAP(caps=b"IMAP4rev1")
        with self.assertRaises(RuntimeError):
            m.delete_message(client, "INBOX", "7")
        self.assertFalse(any(call[0] == "store" for call in client.uid_calls))

    def test_safe_delete_uses_uid_expunge(self):
        client = FakeIMAP()
        m.delete_message(client, "INBOX", "7")
        self.assertEqual([call[0] for call in client.uid_calls][-2:], ["store", "expunge"])

    def test_move_prefers_move_capability(self):
        client = FakeIMAP()
        m.move_message(client, "INBOX", "7", "Archive")
        self.assertEqual(client.uid_calls[-1][0], "move")

    def test_append_draft_has_exact_readback(self):
        client = FakeIMAP()
        uid = m.append_draft(client, "Drafts", {
            "to": "person@example.test",
            "subject": "Test",
            "body_text": "Hello",
        })
        self.assertEqual(uid, "7")
        self.assertIn(b"X-Webactueel-Mailbox-Operation-ID:", client.appended[0][2])

    def test_append_draft_unknown_outcome_when_not_unique(self):
        client = FakeIMAP()
        client.search_result = b"7 8"
        with self.assertRaises(m.UnknownOutcomeError):
            m.append_draft(client, "Drafts", {
                "to": "person@example.test",
                "subject": "Test",
                "body_text": "Hello",
            })

    def test_attachment_limits_on_write(self):
        with self.assertRaises(ValueError):
            m.build_message({
                "to": "person@example.test",
                "subject": "Test",
                "body_text": "Hello",
                "attachments": [{"filename": "a.bin", "content_base64": ""}] * 21,
            })

    def test_attachment_read_by_index(self):
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
        client = FakeIMAP()
        client.messages["7"] = msg.as_bytes()
        item = m.read_attachment(client, "INBOX", "7", 0)
        self.assertEqual(item["filename"], "a.txt")
        self.assertEqual(base64.b64decode(item["content_base64"]), b"hi")

    def test_attachment_chunk_is_bounded_and_resumable(self):
        payload = b"x" * (m.MAX_CHUNK_BYTES + 10)
        msg = m.build_message({
            "to": "person@example.test",
            "subject": "Chunked",
            "body_text": "Hello",
            "attachments": [{
                "filename": "big.bin",
                "content_type": "application/octet-stream",
                "content_base64": base64.b64encode(payload).decode(),
            }],
        })
        client = FakeIMAP()
        client.messages["7"] = msg.as_bytes()
        first = m.read_attachment_chunk(client, "INBOX", "7", 0)
        self.assertEqual(first["chunk_size"], m.MAX_CHUNK_BYTES)
        self.assertFalse(first["eof"])
        second = m.read_attachment_chunk(client, "INBOX", "7", 0, offset=first["next_offset"])
        self.assertTrue(second["eof"])
        self.assertEqual(
            base64.b64decode(first["content_base64"]) + base64.b64decode(second["content_base64"]),
            payload,
        )

    def test_body_chunk_roundtrip(self):
        body = "á" * (m.MAX_CHUNK_BYTES // 2 + 10)
        msg = EmailMessage()
        msg["From"] = "sender@example.test"
        msg["To"] = "me@example.test"
        msg["Subject"] = "Large body"
        msg["Message-ID"] = "<body@example.test>"
        msg.set_content(body)
        client = FakeIMAP()
        client.messages["7"] = msg.as_bytes()
        first = m.read_body_chunk(client, "INBOX", "7", max_bytes=4096)
        self.assertEqual(first["chunk_size"], 4096)
        self.assertFalse(first["eof"])

    def test_read_defaults_to_attachment_metadata_only(self):
        msg = m.build_message({
            "to": "person@example.test",
            "subject": "Metadata",
            "body_text": "Hello",
            "attachments": [{
                "filename": "a.txt",
                "content_type": "text/plain",
                "content_base64": base64.b64encode(b"hi").decode(),
            }],
        })
        client = FakeIMAP()
        client.messages["7"] = msg.as_bytes()
        with patch.object(m, "connect_imap", return_value=client):
            data = m.execute({"action": "read", "folder": "INBOX", "uid": "7"})
        self.assertNotIn("content_base64", data["message"]["attachments"][0])

    def test_reply_all_excludes_own_and_duplicates(self):
        source = EmailMessage()
        source["From"] = "sender@example.test"
        source["To"] = "me@example.test, other@example.test"
        source["Cc"] = "other@example.test, third@example.test"
        source["Subject"] = "Question"
        source["Message-ID"] = "<x@example.test>"
        source.set_content("Original")
        with patch.dict(os.environ, {
            "OUTREACH_MAIL_USER": "me@example.test",
            "OUTREACH_SENDER_EMAIL": "me@example.test",
        }, clear=False):
            reply = m.reply_payload(source, "Answer", reply_all=True)
        self.assertEqual(reply["to"], ["sender@example.test"])
        self.assertEqual(reply["cc"], ["other@example.test", "third@example.test"])

    def test_forward_preserves_attachment(self):
        source = m.build_message({
            "to": "me@example.test",
            "subject": "Question",
            "body_text": "Original",
            "attachments": [{
                "filename": "a.txt",
                "content_type": "text/plain",
                "content_base64": base64.b64encode(b"hi").decode(),
            }],
        })
        source.replace_header("From", "sender@example.test")
        payload = m.forward_payload(source, "other@example.test", "FYI")
        self.assertEqual(payload["attachments"][0]["filename"], "a.txt")

    def test_send_requires_double_gate(self):
        payload = {"to": "person@example.test", "subject": "Test", "body_text": "Hello"}
        with patch.dict(os.environ, {m.SEND_ENABLE_ENV: "false"}, clear=False):
            with self.assertRaises(RuntimeError):
                m.send_message(
                    payload,
                    confirm_send=True,
                    smtp_factory=lambda: FakeSMTP(),
                    imap_factory=lambda: FakeIMAP(),
                )
        with patch.dict(os.environ, {m.SEND_ENABLE_ENV: "true"}, clear=False):
            with self.assertRaises(RuntimeError):
                m.send_message(
                    payload,
                    confirm_send=False,
                    smtp_factory=lambda: FakeSMTP(),
                    imap_factory=lambda: FakeIMAP(),
                )

    def test_send_saves_sent_copy(self):
        payload = {"to": "person@example.test", "subject": "Test", "body_text": "Hello"}
        smtp = FakeSMTP()
        imap = FakeIMAP()
        with patch.dict(os.environ, {m.SEND_ENABLE_ENV: "true"}, clear=False):
            result = m.send_message(
                payload,
                confirm_send=True,
                smtp_factory=lambda: smtp,
                imap_factory=lambda: imap,
            )
        self.assertTrue(result["sent"])
        self.assertTrue(result["sent_copy"])
        self.assertEqual(len(smtp.sent), 1)
        self.assertEqual(imap.appended[0][0], "Sent")

    def test_thread_finds_parent_and_child(self):
        client = FakeIMAP()
        client.messages = {
            "5": client._raw("Thread", "Parent", "<p@example.test>"),
            "7": client._raw("Thread", "Root", "<r@example.test>", in_reply_to="<p@example.test>"),
            "9": client._raw("Thread", "Child", "<c@example.test>", in_reply_to="<r@example.test>"),
        }

        def uid(command, *args):
            client.uid_calls.append((command.lower(), args))
            command = command.lower()
            if command == "fetch":
                return "OK", [(b"x", client.messages[str(args[0])])]
            if command == "search":
                joined = " ".join(str(x) for x in args)
                if "Message-ID" in joined and "p@example.test" in joined:
                    return "OK", [b"5"]
                if "In-Reply-To" in joined and "r@example.test" in joined:
                    return "OK", [b"9"]
                return "OK", [b""]
            return "OK", [b""]

        client.uid = uid
        rows = m.thread_messages(client, "INBOX", "7")
        self.assertEqual({row["uid"] for row in rows}, {"5", "7", "9"})

    def test_rejects_invalid_uid_before_mutation(self):
        client = FakeIMAP()
        with self.assertRaises(ValueError):
            m.delete_message(client, "INBOX", "7:9")
        self.assertEqual(client.uid_calls, [])


if __name__ == "__main__":
    unittest.main()
