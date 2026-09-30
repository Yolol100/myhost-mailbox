# myhost-mailbox

Generic mijn.host IMAP/SMTP mailbox runtime for controlled automation.

## Scope

This repository contains reusable mailbox code and tests for:
- listing folders;
- listing, reading and searching messages;
- flags/read state;
- copying, moving and deleting messages;
- creating and replacing drafts;
- attachments;
- reply/reply-all and forwarding payloads;
- SMTP submission behind an explicit double confirmation gate.

## Security boundary

The repository may be public, but mailbox credentials and mailbox content are not repository data.

- Credentials belong in GitHub Actions Secrets or another secret store.
- Do not commit passwords, tokens, message bodies, recipients or attachments.
- Do not print mailbox content into public workflow logs.
- Do not upload mailbox content as public workflow artifacts.
- Sending requires both an explicit request confirmation and `OUTREACH_SMTP_SEND_ENABLED=true`.
- Destructive actions require explicit confirmation.
- The lead-generation project remains review-first and does not inherit automatic sending.

Source code being public does not make the mailbox public; runtime data must remain outside repository-visible output.
