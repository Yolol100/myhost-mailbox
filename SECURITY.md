# Security

This repository may be public. Source code is not mailbox data.

## Never commit

- mailbox passwords, tokens or application passwords;
- message bodies, recipients, attachments or raw MIME from a real mailbox;
- generated request/result payloads containing personal or business correspondence;
- debug logs containing authentication or mailbox data.

## Runtime rules

- Store credentials only in a secret manager or GitHub Actions Secrets.
- Keep GitHub token permissions at least privilege.
- Do not enable Actions debug logging for live mailbox runs.
- Do not upload mailbox results as artifacts in a public repository.
- Do not write mailbox results to issues, pull requests, commits, job summaries or workflow logs.
- SMTP sending requires both an explicit per-request confirmation and `OUTREACH_SMTP_SEND_ENABLED=true`.
- Delete and draft-replace operations require exact target identity and readback.
- If a write may have succeeded but readback is ambiguous, treat it as an unknown outcome and do not retry blindly.

## Reporting

Do not open a public issue containing credentials or real mailbox content.
