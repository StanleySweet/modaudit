# 0011 — Auditor role and scoped API key

Status: accepted

## Context

The CLI needs queue access, artifact download, audit submission, draft creation
and signature submission. It must not be able to post comments, manage users, or
hold the mod.io token.

## Decision

Add an `auditor` role and hashed, revocable API keys scoped to: read queue,
download artifact, submit audit record, create comment draft, submit signature.
Approving/posting comments and uploading modfiles stay with `mod_signer`/admin
sessions in the manager.

## Consequences

- Least privilege on signer machines; a stolen key cannot publish or post.
- Manager endpoints, scopes and audit-log entries must be added together, in the
  existing `../modio-manager` repo.
- Approval has an API primitive and an admin-UI path; both are audit-logged.
- Key rotation is a manager action; the CLI fails closed on revoked keys.
- Signature verification uses a per-alpha public-key trust store owned by admins.
