# Security — research-only archive boundary

This public repository contains no active mailbox, draft or message-delivery runtime. The previous implementation was removed from `main` on 10 November 2026 and retained only on `archive/pre-myhost-mail-cleanup-2026-11-10`.

## Rules

- Never commit credentials, secrets, historical correspondence, personal data or mailbox content.
- No active mail integrations, send/draft commands, or scheduler may be restored from this repository.
- Archived access, code or documentation never grants permission for mailbox operations.
- Preserve historical opt-outs, bounce records, dedupe/suppressions and restoration evidence; do not destroy or reset them as part of repository cleanup.
- A future restoration requires a separate explicit change request, technical and legal review, rollback and readback.
