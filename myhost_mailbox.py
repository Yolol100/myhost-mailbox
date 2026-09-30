from __future__ import annotations

import base64
import imaplib
import json
import os
import re
import smtplib
import ssl
import time
import uuid
from email.message import EmailMessage
from email.parser import BytesParser
from email.policy import default
from email.utils import formatdate, getaddresses, make_msgid
from pathlib import Path

SEND_ENABLE_ENV = "OUTREACH_SMTP_SEND_ENABLED"
MAX_ATTACHMENTS = 20
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024
MAX_MESSAGE_BYTES = 50 * 1024 * 1024
UID_RE = re.compile(r"^[1-9][0-9]*$")


class UnknownOutcomeError(RuntimeError):
    """The provider may have applied a write, but exact readback was not possible."""


def normalize_text(value: object) -> str:
    return str(value or "").replace("\r\n", "\n").replace("\r", "\n").strip()


def _required_text(value: object, name: str) -> str:
    text = normalize_text(value)
    if not text:
        raise ValueError(f"{name} is required")
    if "\n" in text or "\r" in text:
        raise ValueError(f"{name} must not contain line breaks")
    return text


def _uid_text(value: object) -> str:
    uid = normalize_text(value)
    if not UID_RE.fullmatch(uid):
        raise ValueError("uid must be a positive numeric IMAP UID")
    return uid


def connect_imap():
    host = os.getenv("OUTREACH_IMAP_HOST", "mail.andrewbaeten.nl").strip()
    port = int(os.getenv("OUTREACH_IMAP_PORT", "993"))
    user = os.getenv("OUTREACH_MAIL_USER", "info@andrewbaeten.nl").strip()
    password = os.getenv("OUTREACH_MAIL_PASSWORD", "")
    if not password:
        raise RuntimeError("OUTREACH_MAIL_PASSWORD is required")
    client = imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context())
    client.login(user, password)
    return client


def connect_smtp():
    host = os.getenv("OUTREACH_SMTP_HOST", os.getenv("OUTREACH_IMAP_HOST", "mail.andrewbaeten.nl")).strip()
    mode = os.getenv("OUTREACH_SMTP_MODE", "starttls").strip().casefold()
    port = int(os.getenv("OUTREACH_SMTP_PORT", "465" if mode == "ssl" else "587"))
    user = os.getenv("OUTREACH_MAIL_USER", "info@andrewbaeten.nl").strip()
    password = os.getenv("OUTREACH_SMTP_PASSWORD", os.getenv("OUTREACH_MAIL_PASSWORD", ""))
    if not password:
        raise RuntimeError("OUTREACH_SMTP_PASSWORD or OUTREACH_MAIL_PASSWORD is required")
    context = ssl.create_default_context()
    if mode == "ssl":
        client = smtplib.SMTP_SSL(host, port, context=context, timeout=30)
    elif mode == "starttls":
        client = smtplib.SMTP(host, port, timeout=30)
        client.ehlo()
        client.starttls(context=context)
        client.ehlo()
    else:
        raise RuntimeError("OUTREACH_SMTP_MODE must be starttls or ssl")
    client.login(user, password)
    return client


def capabilities(client) -> set[str]:
    status, data = client.capability()
    if status != "OK":
        raise RuntimeError("Could not read IMAP capabilities")
    text = b" ".join(data or []).decode("ascii", errors="ignore").upper()
    return set(text.split())


def decode_folder(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="replace")
    if '"' in text:
        end = text.rfind('"')
        start = text.rfind('"', 0, end)
        if start >= 0:
            return text[start + 1 : end].replace('\\"', '"')
    return text.split()[-1].strip('"')


def list_folders(client) -> list[str]:
    status, rows = client.list()
    if status != "OK":
        raise RuntimeError("Could not list IMAP folders")
    return [decode_folder(row) for row in (rows or [])]


def select_folder(client, folder: str, *, readonly: bool = True) -> int:
    folder = _required_text(folder, "folder")
    escaped = folder.replace("\\", "\\\\").replace('"', '\\"')
    status, data = client.select(f'"{escaped}"', readonly=readonly)
    if status != "OK":
        raise RuntimeError(f"Could not open folder: {folder}")
    try:
        return int((data or [b"0"])[0] or 0)
    except (TypeError, ValueError):
        return 0


def _uid(client, command: str, *args):
    status, data = client.uid(command, *args)
    if status != "OK":
        raise RuntimeError(f"IMAP UID {command} failed")
    return data


def list_message_uids(client, folder: str, *, unread_only: bool = False, limit: int = 50) -> list[str]:
    if limit < 1 or limit > 500:
        raise ValueError("limit must be 1-500")
    select_folder(client, folder, readonly=True)
    data = _uid(client, "search", None, "UNSEEN" if unread_only else "ALL")
    uids = (data[0] if data else b"").split()
    return [uid.decode("ascii") for uid in uids[-limit:]][::-1]


def fetch_message(client, folder: str, uid: str, *, readonly: bool = True) -> EmailMessage:
    uid = _uid_text(uid)
    select_folder(client, folder, readonly=readonly)
    data = _uid(client, "fetch", uid, "(RFC822)")
    for item in data or []:
        if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], (bytes, bytearray)):
            raw = bytes(item[1])
            if len(raw) > MAX_MESSAGE_BYTES:
                raise ValueError("message exceeds 50 MiB")
            return BytesParser(policy=default).parsebytes(raw)
    raise RuntimeError(f"No message bytes returned for UID {uid}")


def _body_parts(msg: EmailMessage) -> tuple[str, str | None]:
    plain = ""
    html = None
    if msg.is_multipart():
        plain_part = msg.get_body(preferencelist=("plain",))
        html_part = msg.get_body(preferencelist=("html",))
        if plain_part:
            plain = normalize_text(plain_part.get_content())
        if html_part:
            html = normalize_text(html_part.get_content())
    else:
        content = msg.get_content()
        if msg.get_content_type() == "text/html":
            html = normalize_text(content)
        else:
            plain = normalize_text(content)
    return plain, html


def serialize_message(
    msg: EmailMessage,
    *,
    include_attachments: bool = True,
    include_attachment_content: bool = True,
) -> dict:
    plain, html = _body_parts(msg)
    attachments = []
    total_bytes = 0
    if include_attachments:
        parts = list(msg.iter_attachments())
        if len(parts) > MAX_ATTACHMENTS:
            raise ValueError("message has more than 20 attachments")
        for part in parts:
            payload = part.get_payload(decode=True) or b""
            total_bytes += len(payload)
            if total_bytes > MAX_ATTACHMENT_BYTES:
                raise ValueError("message attachments exceed 25 MiB")
            item = {
                "filename": part.get_filename(),
                "content_type": part.get_content_type(),
                "size": len(payload),
            }
            if include_attachment_content:
                item["content_base64"] = base64.b64encode(payload).decode("ascii")
            attachments.append(item)
    return {
        "message_id": normalize_text(msg.get("Message-ID", "")) or None,
        "from": normalize_text(msg.get("From", "")),
        "to": normalize_text(msg.get("To", "")),
        "cc": normalize_text(msg.get("Cc", "")) or None,
        "bcc": normalize_text(msg.get("Bcc", "")) or None,
        "subject": normalize_text(msg.get("Subject", "")),
        "date": normalize_text(msg.get("Date", "")) or None,
        "in_reply_to": normalize_text(msg.get("In-Reply-To", "")) or None,
        "references": normalize_text(msg.get("References", "")) or None,
        "body_text": plain,
        "body_html": html,
        "attachments": attachments,
    }


def _search_value(value: object) -> str:
    text = normalize_text(value)
    if "\n" in text or "\r" in text:
        raise ValueError("search terms must not contain line breaks")
    return text.replace('"', "")


def search_messages(
    client,
    folder: str,
    *,
    from_text: str | None = None,
    to_text: str | None = None,
    subject_text: str | None = None,
    body_text: str | None = None,
    unread_only: bool = False,
    limit: int = 50,
) -> list[str]:
    if limit < 1 or limit > 500:
        raise ValueError("limit must be 1-500")
    select_folder(client, folder, readonly=True)
    criteria: list[str] = []
    if unread_only:
        criteria.append("UNSEEN")
    for key, value in (("FROM", from_text), ("TO", to_text), ("SUBJECT", subject_text), ("BODY", body_text)):
        value = _search_value(value)
        if value:
            criteria.extend([key, f'"{value}"'])
    if not criteria:
        criteria = ["ALL"]
    data = _uid(client, "search", None, *criteria)
    uids = (data[0] if data else b"").split()
    return [uid.decode("ascii") for uid in uids[-limit:]][::-1]


def create_folder(client, folder: str) -> None:
    folder = _required_text(folder, "folder")
    status, _ = client.create(folder)
    if status != "OK":
        raise RuntimeError(f"Could not create folder: {folder}")


def rename_folder(client, old_folder: str, new_folder: str) -> None:
    old_folder = _required_text(old_folder, "folder")
    new_folder = _required_text(new_folder, "destination")
    status, _ = client.rename(old_folder, new_folder)
    if status != "OK":
        raise RuntimeError(f"Could not rename folder: {old_folder}")


def delete_folder(client, folder: str) -> None:
    folder = _required_text(folder, "folder")
    status, _ = client.delete(folder)
    if status != "OK":
        raise RuntimeError(f"Could not delete folder: {folder}")


def set_flag(client, folder: str, uid: str, flag: str, *, enabled: bool) -> None:
    uid = _uid_text(uid)
    select_folder(client, folder, readonly=False)
    _uid(client, "store", uid, "+FLAGS.SILENT" if enabled else "-FLAGS.SILENT", f"({flag})")


def copy_message(client, source_folder: str, uid: str, destination_folder: str) -> None:
    uid = _uid_text(uid)
    destination_folder = _required_text(destination_folder, "destination")
    select_folder(client, source_folder, readonly=False)
    _uid(client, "copy", uid, destination_folder)


def delete_message(client, folder: str, uid: str) -> None:
    uid = _uid_text(uid)
    if "UIDPLUS" not in capabilities(client):
        raise RuntimeError("Safe delete requires IMAP UIDPLUS support")
    select_folder(client, folder, readonly=False)
    _uid(client, "store", uid, "+FLAGS.SILENT", "(\\Deleted)")
    _uid(client, "expunge", uid)


def move_message(client, source_folder: str, uid: str, destination_folder: str) -> None:
    uid = _uid_text(uid)
    destination_folder = _required_text(destination_folder, "destination")
    caps = capabilities(client)
    select_folder(client, source_folder, readonly=False)
    if "MOVE" in caps:
        _uid(client, "move", uid, destination_folder)
        return
    if "UIDPLUS" not in caps:
        raise RuntimeError("Safe move requires IMAP MOVE or UIDPLUS support")
    _uid(client, "copy", uid, destination_folder)
    _uid(client, "store", uid, "+FLAGS.SILENT", "(\\Deleted)")
    _uid(client, "expunge", uid)


def _addresses(value: object) -> str:
    if isinstance(value, list):
        return ", ".join(normalize_text(x) for x in value if normalize_text(x))
    return normalize_text(value)


def _attachment_payloads(payload: dict) -> list[tuple[bytes, str, str | None]]:
    attachments = payload.get("attachments") or []
    if len(attachments) > MAX_ATTACHMENTS:
        raise ValueError("at most 20 attachments are allowed")
    total_attachment_bytes = 0
    result = []
    for attachment in attachments:
        raw = base64.b64decode(str(attachment.get("content_base64") or ""), validate=True)
        total_attachment_bytes += len(raw)
        if total_attachment_bytes > MAX_ATTACHMENT_BYTES:
            raise ValueError("attachments exceed 25 MiB")
        content_type = normalize_text(attachment.get("content_type")) or "application/octet-stream"
        filename = normalize_text(attachment.get("filename")) or None
        result.append((raw, content_type, filename))
    return result


def build_message(payload: dict, *, include_bcc: bool = True, operation_id: str | None = None) -> EmailMessage:
    sender_name = os.getenv("OUTREACH_SENDER_NAME", "Andrew Baeten").strip()
    sender_email = os.getenv("OUTREACH_SENDER_EMAIL", os.getenv("OUTREACH_MAIL_USER", "info@andrewbaeten.nl")).strip()
    to = _addresses(payload.get("to"))
    subject = normalize_text(payload.get("subject"))
    body_text = normalize_text(payload.get("body_text"))
    body_html = normalize_text(payload.get("body_html"))
    if not to or not subject or (not body_text and not body_html):
        raise ValueError("to, subject and body_text or body_html are required")

    msg = EmailMessage(policy=default)
    msg["From"] = f"{sender_name} <{sender_email}>"
    msg["To"] = to
    cc = _addresses(payload.get("cc"))
    bcc = _addresses(payload.get("bcc"))
    if cc:
        msg["Cc"] = cc
    if include_bcc and bcc:
        msg["Bcc"] = bcc
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=sender_email.split("@")[-1] if "@" in sender_email else None)
    if operation_id:
        msg["X-Webactueel-Mailbox-Operation-ID"] = operation_id
    if normalize_text(payload.get("in_reply_to")):
        msg["In-Reply-To"] = normalize_text(payload["in_reply_to"])
    if normalize_text(payload.get("references")):
        msg["References"] = normalize_text(payload["references"])

    if body_html:
        msg.set_content(body_text or "HTML email")
        msg.add_alternative(body_html, subtype="html")
    else:
        msg.set_content(body_text)

    for raw, content_type, filename in _attachment_payloads(payload):
        maintype, _, subtype = content_type.partition("/")
        if not subtype:
            maintype, subtype = "application", "octet-stream"
        msg.add_attachment(raw, maintype=maintype, subtype=subtype, filename=filename)
    return msg


def _verify_appended_message(client, folder: str, operation_id: str) -> str:
    select_folder(client, folder, readonly=True)
    data = _uid(client, "search", None, "HEADER", "X-Webactueel-Mailbox-Operation-ID", f'"{operation_id}"')
    uids = (data[0] if data else b"").split()
    if len(uids) != 1:
        raise UnknownOutcomeError("draft append succeeded but exact readback could not identify one message")
    return uids[0].decode("ascii")


def append_draft(client, folder: str, payload: dict) -> str:
    folder = _required_text(folder, "folder")
    operation_id = uuid.uuid4().hex
    msg = build_message(payload, operation_id=operation_id)
    status, _ = client.append(folder, "(\\Draft)", imaplib.Time2Internaldate(time.time()), msg.as_bytes(policy=default))
    if status != "OK":
        raise RuntimeError("IMAP APPEND failed")
    return _verify_appended_message(client, folder, operation_id)


def replace_draft(client, folder: str, uid: str, payload: dict) -> str:
    old_uid = _uid_text(uid)
    new_uid = append_draft(client, folder, payload)
    try:
        delete_message(client, folder, old_uid)
    except Exception as exc:
        raise UnknownOutcomeError(f"replacement draft {new_uid} was verified, but old draft deletion failed") from exc
    return new_uid


def send_message(payload: dict, *, confirm_send: bool = False, smtp_factory=connect_smtp) -> dict:
    enabled = os.getenv(SEND_ENABLE_ENV, "").strip().casefold() in {"1", "true", "yes", "on"}
    if not confirm_send or not enabled:
        raise RuntimeError("Sending requires confirm_send=true and OUTREACH_SMTP_SEND_ENABLED=true")
    msg = build_message(payload, include_bcc=True)
    smtp = smtp_factory()
    try:
        refused = smtp.send_message(msg)
        if refused:
            raise RuntimeError(f"SMTP refused {len(refused)} recipient(s)")
    finally:
        try:
            smtp.quit()
        except Exception:
            pass
    return {
        "message_id": normalize_text(msg.get("Message-ID", "")),
        "to": normalize_text(msg.get("To", "")),
        "subject": normalize_text(msg.get("Subject", "")),
        "sent": True,
    }


def _mailboxes_from_headers(values: list[str]) -> list[str]:
    return [address for _, address in getaddresses(values) if address]


def _own_addresses() -> set[str]:
    values = {
        os.getenv("OUTREACH_MAIL_USER", "info@andrewbaeten.nl").strip().casefold(),
        os.getenv("OUTREACH_SENDER_EMAIL", "info@andrewbaeten.nl").strip().casefold(),
    }
    return {value for value in values if value}


def reply_payload(source: EmailMessage, body_text: str, *, reply_all: bool = False) -> dict:
    reply_header = normalize_text(source.get("Reply-To", "")) or normalize_text(source.get("From", ""))
    reply_addresses = _mailboxes_from_headers([reply_header])
    if not reply_addresses:
        raise ValueError("source message has no reply address")
    primary = reply_addresses[0]
    subject = normalize_text(source.get("Subject", ""))
    if not subject.casefold().startswith("re:"):
        subject = f"Re: {subject}"

    cc: list[str] = []
    if reply_all:
        own = _own_addresses()
        seen = {primary.casefold()}
        for address in _mailboxes_from_headers([normalize_text(source.get("To", "")), normalize_text(source.get("Cc", ""))]):
            key = address.casefold()
            if key in own or key in seen:
                continue
            seen.add(key)
            cc.append(address)

    refs = normalize_text(source.get("References", ""))
    source_id = normalize_text(source.get("Message-ID", ""))
    references = " ".join(x for x in (refs, source_id) if x)
    return {
        "to": [primary],
        "cc": cc,
        "subject": subject,
        "body_text": normalize_text(body_text),
        "in_reply_to": source_id or None,
        "references": references or None,
    }


def forward_payload(source: EmailMessage, to: object, note: str = "") -> dict:
    original = serialize_message(source, include_attachments=True, include_attachment_content=True)
    subject = original["subject"]
    if not subject.casefold().startswith("fwd:"):
        subject = f"Fwd: {subject}"
    body = normalize_text(note)
    forwarded = (f"{body}\n\n" if body else "") + (
        "---------- Forwarded message ----------\n"
        f"From: {original['from']}\nTo: {original['to']}\n"
        f"Subject: {original['subject']}\nDate: {original['date'] or ''}\n\n"
        f"{original['body_text']}"
    )
    return {"to": to, "subject": subject, "body_text": forwarded, "attachments": original["attachments"]}


def execute(request: dict) -> dict:
    action = normalize_text(request.get("action"))
    if action == "send":
        return send_message(request.get("message") or {}, confirm_send=bool(request.get("confirm_send")))

    client = connect_imap()
    try:
        if action == "list_folders":
            return {"folders": list_folders(client)}
        if action == "create_folder":
            create_folder(client, request.get("folder"))
            return {"ok": True}
        if action == "rename_folder":
            rename_folder(client, request.get("folder"), request.get("destination"))
            return {"ok": True}
        if action == "delete_folder":
            if not request.get("confirm"):
                raise RuntimeError("delete_folder requires confirm=true")
            delete_folder(client, request.get("folder"))
            return {"ok": True}
        if action == "list_messages":
            return {"uids": list_message_uids(client, request.get("folder"), unread_only=bool(request.get("unread_only")), limit=int(request.get("limit") or 50))}
        if action == "search":
            return {"uids": search_messages(client, request.get("folder"), from_text=request.get("from"), to_text=request.get("to"), subject_text=request.get("subject"), body_text=request.get("body"), unread_only=bool(request.get("unread_only")), limit=int(request.get("limit") or 50))}
        if action == "read":
            msg = fetch_message(client, request.get("folder"), request.get("uid"))
            return {"message": serialize_message(msg, include_attachments=bool(request.get("include_attachments", True)), include_attachment_content=bool(request.get("include_attachment_content", True)))}
        if action == "mark_read":
            set_flag(client, request.get("folder"), request.get("uid"), "\\Seen", enabled=True)
            return {"ok": True}
        if action == "mark_unread":
            set_flag(client, request.get("folder"), request.get("uid"), "\\Seen", enabled=False)
            return {"ok": True}
        if action == "flag":
            set_flag(client, request.get("folder"), request.get("uid"), "\\Flagged", enabled=True)
            return {"ok": True}
        if action == "unflag":
            set_flag(client, request.get("folder"), request.get("uid"), "\\Flagged", enabled=False)
            return {"ok": True}
        if action == "copy":
            copy_message(client, request.get("folder"), request.get("uid"), request.get("destination"))
            return {"ok": True}
        if action == "move":
            move_message(client, request.get("folder"), request.get("uid"), request.get("destination"))
            return {"ok": True}
        if action == "delete":
            if not request.get("confirm"):
                raise RuntimeError("delete requires confirm=true")
            delete_message(client, request.get("folder"), request.get("uid"))
            return {"ok": True}
        if action == "create_draft":
            return {"uid": append_draft(client, request.get("folder"), request.get("message") or {})}
        if action == "replace_draft":
            if not request.get("confirm"):
                raise RuntimeError("replace_draft requires confirm=true")
            return {"uid": replace_draft(client, request.get("folder"), request.get("uid"), request.get("message") or {})}
        raise ValueError(f"Unknown action: {action}")
    finally:
        try:
            client.logout()
        except Exception:
            pass


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    request = json.loads(Path(args.request).read_text(encoding="utf-8"))
    result = execute(request)
    Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"MYHOST_MAILBOX=green action={normalize_text(request.get('action'))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
