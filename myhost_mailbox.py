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
from email.utils import formatdate, getaddresses, make_msgid, parsedate_to_datetime
from pathlib import Path

SEND_ENABLE_ENV = "OUTREACH_SMTP_SEND_ENABLED"
MAX_ATTACHMENTS = 20
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024
MAX_MESSAGE_BYTES = 50 * 1024 * 1024
MAX_THREAD_MESSAGES = 100
MAX_CHUNK_BYTES = 512 * 1024
UID_RE = re.compile(r"^[1-9][0-9]*$")
SPECIAL_FLAGS = {
    "drafts": "\\DRAFTS",
    "sent": "\\SENT",
    "trash": "\\TRASH",
    "junk": "\\JUNK",
    "archive": "\\ARCHIVE",
}
SPECIAL_NAMES = {
    "drafts": ("draft", "concept"),
    "sent": ("sent", "verzonden"),
    "trash": ("trash", "deleted", "prullenbak"),
    "junk": ("junk", "spam", "ongewenst"),
    "archive": ("archive", "archief"),
}


class UnknownOutcomeError(RuntimeError):
    """A provider write may have succeeded, but exact readback is unavailable."""


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


def parse_folder_row(raw: bytes) -> dict:
    text = raw.decode("utf-8", errors="replace")
    match = re.match(r'^\(([^)]*)\)\s+(?:"(?:\\.|[^"])*"|NIL)\s+(.+)$', text)
    if not match:
        raise ValueError("Malformed IMAP LIST response")

    flags = [item.upper() for item in match.group(1).split()]
    mailbox = match.group(2).strip()
    if mailbox.startswith('"') and mailbox.endswith('"'):
        name = mailbox[1:-1].replace('\\"', '"').replace('\\\\', '\\')
    else:
        name = mailbox
    if not name:
        raise ValueError("IMAP LIST response has empty mailbox name")
    return {"name": name, "flags": flags}

def list_folder_info(client) -> list[dict]:
    status, rows = client.list()
    if status != "OK":
        raise RuntimeError("Could not list IMAP folders")
    return [parse_folder_row(row) for row in (rows or [])]


def list_folders(client) -> list[str]:
    return [item["name"] for item in list_folder_info(client)]


def find_special_folder(client, kind: str) -> str:
    kind = normalize_text(kind).casefold()
    if kind not in SPECIAL_FLAGS:
        raise ValueError(f"unknown special folder kind: {kind}")
    info = list_folder_info(client)
    expected_flag = SPECIAL_FLAGS[kind]
    for item in info:
        if expected_flag in item["flags"]:
            return item["name"]
    for item in info:
        low = item["name"].casefold()
        if any(token in low for token in SPECIAL_NAMES[kind]):
            return item["name"]
    raise RuntimeError(f"Could not find {kind} folder")


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


def _search_header(client, folder: str, header: str, value: str) -> list[str]:
    select_folder(client, folder, readonly=True)
    clean = _required_text(value, "header value").replace('"', "")
    data = _uid(client, "search", None, "HEADER", header, f'"{clean}"')
    return [item.decode("ascii") for item in (data[0] if data else b"").split()]


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


def message_summary(msg: EmailMessage, uid: str) -> dict:
    return {
        "uid": _uid_text(uid),
        "message_id": normalize_text(msg.get("Message-ID", "")) or None,
        "from": normalize_text(msg.get("From", "")),
        "to": normalize_text(msg.get("To", "")),
        "cc": normalize_text(msg.get("Cc", "")) or None,
        "subject": normalize_text(msg.get("Subject", "")),
        "date": normalize_text(msg.get("Date", "")) or None,
        "in_reply_to": normalize_text(msg.get("In-Reply-To", "")) or None,
        "webactueel_lead_id": normalize_text(msg.get("X-Webactueel-Lead-ID", "")) or None,
        "webactueel_review_required": normalize_text(msg.get("X-Webactueel-Review-Required", "")) or None,
        "has_attachments": any(True for _ in msg.iter_attachments()),
    }


def serialize_message(msg: EmailMessage, *, uid: str | None = None, include_attachments: bool = True, include_attachment_content: bool = True) -> dict:
    plain, html = _body_parts(msg)
    attachments = []
    total_bytes = 0
    if include_attachments:
        parts = list(msg.iter_attachments())
        if len(parts) > MAX_ATTACHMENTS:
            raise ValueError("message has more than 20 attachments")
        for index, part in enumerate(parts):
            payload = part.get_payload(decode=True) or b""
            total_bytes += len(payload)
            if total_bytes > MAX_ATTACHMENT_BYTES:
                raise ValueError("message attachments exceed 25 MiB")
            item = {"index": index, "filename": part.get_filename(), "content_type": part.get_content_type(), "size": len(payload)}
            if include_attachment_content:
                item["content_base64"] = base64.b64encode(payload).decode("ascii")
            attachments.append(item)
    result = {
        "message_id": normalize_text(msg.get("Message-ID", "")) or None,
        "from": normalize_text(msg.get("From", "")),
        "to": normalize_text(msg.get("To", "")),
        "cc": normalize_text(msg.get("Cc", "")) or None,
        "bcc": normalize_text(msg.get("Bcc", "")) or None,
        "subject": normalize_text(msg.get("Subject", "")),
        "date": normalize_text(msg.get("Date", "")) or None,
        "in_reply_to": normalize_text(msg.get("In-Reply-To", "")) or None,
        "references": normalize_text(msg.get("References", "")) or None,
        "webactueel_lead_id": normalize_text(msg.get("X-Webactueel-Lead-ID", "")) or None,
        "webactueel_review_required": normalize_text(msg.get("X-Webactueel-Review-Required", "")) or None,
        "body_text": plain,
        "body_html": html,
        "attachments": attachments,
    }
    if uid is not None:
        result["uid"] = _uid_text(uid)
    return result


def read_attachment(client, folder: str, uid: str, index: int) -> dict:
    msg = fetch_message(client, folder, uid)
    parts = list(msg.iter_attachments())
    if index < 0 or index >= len(parts):
        raise ValueError("attachment index is out of range")
    part = parts[index]
    payload = part.get_payload(decode=True) or b""
    if len(payload) > MAX_ATTACHMENT_BYTES:
        raise ValueError("attachment exceeds 25 MiB")
    return {"index": index, "filename": part.get_filename(), "content_type": part.get_content_type(), "size": len(payload), "content_base64": base64.b64encode(payload).decode("ascii")}


def _byte_chunk(payload: bytes, *, offset: int = 0, max_bytes: int = MAX_CHUNK_BYTES) -> dict:
    if offset < 0:
        raise ValueError("offset must be >= 0")
    if max_bytes < 1 or max_bytes > MAX_CHUNK_BYTES:
        raise ValueError(f"max_bytes must be 1-{MAX_CHUNK_BYTES}")
    total = len(payload)
    if offset > total:
        raise ValueError("offset exceeds payload size")
    end = min(total, offset + max_bytes)
    chunk = payload[offset:end]
    return {
        "offset": offset,
        "next_offset": end if end < total else None,
        "eof": end >= total,
        "total_size": total,
        "chunk_size": len(chunk),
        "content_base64": base64.b64encode(chunk).decode("ascii"),
    }


def read_attachment_chunk(client, folder: str, uid: str, index: int, *, offset: int = 0, max_bytes: int = MAX_CHUNK_BYTES) -> dict:
    msg = fetch_message(client, folder, uid)
    parts = list(msg.iter_attachments())
    if index < 0 or index >= len(parts):
        raise ValueError("attachment index is out of range")
    part = parts[index]
    payload = part.get_payload(decode=True) or b""
    if len(payload) > MAX_ATTACHMENT_BYTES:
        raise ValueError("attachment exceeds 25 MiB")
    result = _byte_chunk(payload, offset=offset, max_bytes=max_bytes)
    result.update({"index": index, "filename": part.get_filename(), "content_type": part.get_content_type()})
    return result


def read_body_chunk(client, folder: str, uid: str, *, kind: str = "text", offset: int = 0, max_bytes: int = MAX_CHUNK_BYTES) -> dict:
    msg = fetch_message(client, folder, uid)
    plain, html = _body_parts(msg)
    kind = normalize_text(kind).casefold() or "text"
    if kind not in {"text", "html"}:
        raise ValueError("kind must be text or html")
    body = plain if kind == "text" else (html or "")
    result = _byte_chunk(body.encode("utf-8"), offset=offset, max_bytes=max_bytes)
    result.update({"kind": kind, "encoding": "utf-8"})
    return result


def list_message_summaries(client, folder: str, *, unread_only: bool = False, limit: int = 50) -> list[dict]:
    uids = list_message_uids(client, folder, unread_only=unread_only, limit=limit)
    return [message_summary(fetch_message(client, folder, uid), uid) for uid in uids]


def _search_value(value: object) -> str:
    text = normalize_text(value)
    if "\n" in text or "\r" in text:
        raise ValueError("search terms must not contain line breaks")
    return text.replace('"', "")


def search_message_uids(client, folder: str, *, from_text: str | None = None, to_text: str | None = None, subject_text: str | None = None, body_text: str | None = None, unread_only: bool = False, flagged_only: bool = False, limit: int = 50) -> list[str]:
    if limit < 1 or limit > 500:
        raise ValueError("limit must be 1-500")
    select_folder(client, folder, readonly=True)
    criteria: list[str] = []
    if unread_only:
        criteria.append("UNSEEN")
    if flagged_only:
        criteria.append("FLAGGED")
    for key, value in (("FROM", from_text), ("TO", to_text), ("SUBJECT", subject_text), ("BODY", body_text)):
        value = _search_value(value)
        if value:
            criteria.extend([key, f'"{value}"'])
    if not criteria:
        criteria = ["ALL"]
    data = _uid(client, "search", None, *criteria)
    uids = (data[0] if data else b"").split()
    return [uid.decode("ascii") for uid in uids[-limit:]][::-1]


def search_message_summaries(client, folder: str, **kwargs) -> list[dict]:
    uids = search_message_uids(client, folder, **kwargs)
    return [message_summary(fetch_message(client, folder, uid), uid) for uid in uids]


def thread_messages(client, folder: str, uid: str) -> list[dict]:
    root_uid = _uid_text(uid)
    found: dict[str, EmailMessage] = {root_uid: fetch_message(client, folder, root_uid)}
    seen_ids: set[str] = set()

    current = found[root_uid]
    for _ in range(MAX_THREAD_MESSAGES):
        parent_id = normalize_text(current.get("In-Reply-To", ""))
        if not parent_id or parent_id in seen_ids:
            break
        seen_ids.add(parent_id)
        parent_uids = _search_header(client, folder, "Message-ID", parent_id)
        if not parent_uids:
            break
        parent_uid = parent_uids[0]
        if parent_uid in found:
            break
        current = fetch_message(client, folder, parent_uid)
        found[parent_uid] = current

    queue = [normalize_text(msg.get("Message-ID", "")) for msg in found.values()]
    queue = [item for item in queue if item]
    processed: set[str] = set()
    while queue and len(found) < MAX_THREAD_MESSAGES:
        message_id = queue.pop(0)
        if message_id in processed:
            continue
        processed.add(message_id)
        for child_uid in _search_header(client, folder, "In-Reply-To", message_id):
            if child_uid in found:
                continue
            child = fetch_message(client, folder, child_uid)
            found[child_uid] = child
            child_id = normalize_text(child.get("Message-ID", ""))
            if child_id:
                queue.append(child_id)
            if len(found) >= MAX_THREAD_MESSAGES:
                break

    def sort_key(item: tuple[str, EmailMessage]):
        date = normalize_text(item[1].get("Date", ""))
        try:
            return parsedate_to_datetime(date).timestamp() if date else 0.0
        except Exception:
            return 0.0

    return [serialize_message(msg, uid=message_uid, include_attachments=False, include_attachment_content=False) for message_uid, msg in sorted(found.items(), key=sort_key)]


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


def _verify_by_header(client, folder: str, header: str, value: str) -> str:
    uids = _search_header(client, folder, header, value)
    if len(uids) != 1:
        raise UnknownOutcomeError(f"write succeeded but exact readback found {len(uids)} matching messages")
    return uids[0]


def append_draft(client, folder: str, payload: dict) -> str:
    folder = _required_text(folder, "folder")
    operation_id = uuid.uuid4().hex
    msg = build_message(payload, operation_id=operation_id)
    status, _ = client.append(folder, "(\\Draft)", imaplib.Time2Internaldate(time.time()), msg.as_bytes(policy=default))
    if status != "OK":
        raise RuntimeError("IMAP APPEND failed")
    return _verify_by_header(client, folder, "X-Webactueel-Mailbox-Operation-ID", operation_id)


def replace_draft(client, folder: str, uid: str, payload: dict) -> str:
    old_uid = _uid_text(uid)
    new_uid = append_draft(client, folder, payload)
    try:
        delete_message(client, folder, old_uid)
    except Exception as exc:
        raise UnknownOutcomeError(f"replacement draft {new_uid} was verified, but old draft deletion failed") from exc
    return new_uid


def _payload_from_message(msg: EmailMessage) -> dict:
    data = serialize_message(msg, include_attachments=True, include_attachment_content=True)
    return {
        "to": data["to"],
        "cc": data["cc"],
        "bcc": data["bcc"],
        "subject": data["subject"],
        "body_text": data["body_text"],
        "body_html": data["body_html"],
        "attachments": data["attachments"],
        "in_reply_to": data["in_reply_to"],
        "references": data["references"],
    }


def send_message(payload: dict, *, confirm_send: bool = False, save_sent_copy: bool = True, smtp_factory=connect_smtp, imap_factory=connect_imap) -> dict:
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

    result = {"message_id": normalize_text(msg.get("Message-ID", "")), "to": normalize_text(msg.get("To", "")), "subject": normalize_text(msg.get("Subject", "")), "sent": True, "sent_copy": False}
    if not save_sent_copy:
        return result

    client = None
    try:
        client = imap_factory()
        sent_folder = find_special_folder(client, "sent")
        copy = BytesParser(policy=default).parsebytes(msg.as_bytes(policy=default))
        if "Bcc" in copy:
            del copy["Bcc"]
        status, _ = client.append(sent_folder, "(\\Seen)", imaplib.Time2Internaldate(time.time()), copy.as_bytes(policy=default))
        if status != "OK":
            result["sent_copy_warning"] = "message sent, but IMAP Sent append failed"
            return result
        try:
            result["sent_uid"] = _verify_by_header(client, sent_folder, "Message-ID", result["message_id"])
            result["sent_copy"] = True
        except UnknownOutcomeError:
            result["sent_copy_warning"] = "message sent and Sent append returned OK, but exact Sent readback was ambiguous"
        return result
    except Exception:
        result["sent_copy_warning"] = "message sent, but Sent-folder readback was unavailable"
        return result
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:
                pass


def _mailboxes_from_headers(values: list[str]) -> list[str]:
    return [address for _, address in getaddresses(values) if address]


def _own_addresses() -> set[str]:
    values = {os.getenv("OUTREACH_MAIL_USER", "info@andrewbaeten.nl").strip().casefold(), os.getenv("OUTREACH_SENDER_EMAIL", "info@andrewbaeten.nl").strip().casefold()}
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
    return {"to": [primary], "cc": cc, "subject": subject, "body_text": normalize_text(body_text), "in_reply_to": source_id or None, "references": references or None}


def forward_payload(source: EmailMessage, to: object, note: str = "") -> dict:
    original = serialize_message(source, include_attachments=True, include_attachment_content=True)
    subject = original["subject"]
    if not subject.casefold().startswith("fwd:"):
        subject = f"Fwd: {subject}"
    body = normalize_text(note)
    forwarded = (f"{body}\n\n" if body else "") + ("---------- Forwarded message ----------\n" f"From: {original['from']}\nTo: {original['to']}\n" f"Subject: {original['subject']}\nDate: {original['date'] or ''}\n\n" f"{original['body_text']}")
    return {"to": to, "subject": subject, "body_text": forwarded, "attachments": original["attachments"]}


def execute(request: dict) -> dict:
    action = normalize_text(request.get("action"))
    if action == "send":
        return send_message(request.get("message") or {}, confirm_send=bool(request.get("confirm_send")), save_sent_copy=bool(request.get("save_sent_copy", True)))

    client = connect_imap()
    try:
        if action == "list_folders":
            return {"folders": list_folder_info(client)}
        if action == "create_folder":
            create_folder(client, request.get("folder")); return {"ok": True}
        if action == "rename_folder":
            rename_folder(client, request.get("folder"), request.get("destination")); return {"ok": True}
        if action == "delete_folder":
            if not request.get("confirm"): raise RuntimeError("delete_folder requires confirm=true")
            delete_folder(client, request.get("folder")); return {"ok": True}
        if action == "list_messages":
            return {"messages": list_message_summaries(client, request.get("folder"), unread_only=bool(request.get("unread_only")), limit=int(request.get("limit") or 50))}
        if action == "search":
            return {"messages": search_message_summaries(client, request.get("folder"), from_text=request.get("from"), to_text=request.get("to"), subject_text=request.get("subject"), body_text=request.get("body"), unread_only=bool(request.get("unread_only")), flagged_only=bool(request.get("flagged_only")), limit=int(request.get("limit") or 50))}
        if action == "read":
            msg = fetch_message(client, request.get("folder"), request.get("uid"))
            return {"message": serialize_message(msg, uid=request.get("uid"), include_attachments=bool(request.get("include_attachments", True)), include_attachment_content=bool(request.get("include_attachment_content", False)))}
        if action == "read_attachment":
            return {"attachment": read_attachment(client, request.get("folder"), request.get("uid"), int(request.get("index", 0)))}
        if action == "read_attachment_chunk":
            return {"attachment": read_attachment_chunk(client, request.get("folder"), request.get("uid"), int(request.get("index", 0)), offset=int(request.get("offset", 0)), max_bytes=int(request.get("max_bytes", MAX_CHUNK_BYTES)))}
        if action == "read_body_chunk":
            return {"body": read_body_chunk(client, request.get("folder"), request.get("uid"), kind=request.get("kind", "text"), offset=int(request.get("offset", 0)), max_bytes=int(request.get("max_bytes", MAX_CHUNK_BYTES)))}
        if action == "thread":
            return {"messages": thread_messages(client, request.get("folder"), request.get("uid"))}
        if action == "mark_read":
            set_flag(client, request.get("folder"), request.get("uid"), "\\Seen", enabled=True); return {"ok": True}
        if action == "mark_unread":
            set_flag(client, request.get("folder"), request.get("uid"), "\\Seen", enabled=False); return {"ok": True}
        if action == "flag":
            set_flag(client, request.get("folder"), request.get("uid"), "\\Flagged", enabled=True); return {"ok": True}
        if action == "unflag":
            set_flag(client, request.get("folder"), request.get("uid"), "\\Flagged", enabled=False); return {"ok": True}
        if action == "copy":
            copy_message(client, request.get("folder"), request.get("uid"), request.get("destination")); return {"ok": True}
        if action in {"move", "archive", "trash", "junk"}:
            destination = request.get("destination") if action == "move" else find_special_folder(client, action)
            move_message(client, request.get("folder"), request.get("uid"), destination); return {"ok": True, "destination": destination}
        if action == "delete":
            if not request.get("confirm"): raise RuntimeError("delete requires confirm=true")
            delete_message(client, request.get("folder"), request.get("uid")); return {"ok": True}
        if action == "create_draft":
            folder = request.get("folder") or find_special_folder(client, "drafts")
            return {"uid": append_draft(client, folder, request.get("message") or {}), "folder": folder}
        if action == "replace_draft":
            if not request.get("confirm"): raise RuntimeError("replace_draft requires confirm=true")
            folder = request.get("folder") or find_special_folder(client, "drafts")
            return {"uid": replace_draft(client, folder, request.get("uid"), request.get("message") or {}), "folder": folder}
        if action in {"reply", "reply_all", "forward", "send_draft"}:
            folder = request.get("folder")
            uid = request.get("uid")
            source = fetch_message(client, folder, uid)
            if action == "reply":
                payload = reply_payload(source, request.get("body_text"), reply_all=False)
            elif action == "reply_all":
                payload = reply_payload(source, request.get("body_text"), reply_all=True)
            elif action == "forward":
                payload = forward_payload(source, request.get("to"), request.get("note", ""))
            else:
                payload = _payload_from_message(source)
            try: client.logout()
            except Exception: pass
            result = send_message(payload, confirm_send=bool(request.get("confirm_send")), save_sent_copy=bool(request.get("save_sent_copy", True)))
            if action == "send_draft" and result.get("sent"):
                cleanup = connect_imap()
                try:
                    delete_message(cleanup, folder, uid)
                    result["draft_deleted"] = True
                except Exception:
                    result["draft_deleted"] = False
                    result["draft_delete_warning"] = "message was sent, but the original draft could not be safely deleted"
                finally:
                    try: cleanup.logout()
                    except Exception: pass
            return result
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
