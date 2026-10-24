# 0001 — Manager is control plane, CLI is data plane

Status: accepted

## Context

The mod.io OAuth token already lives on the hosted manager. The signer machine
runs the audit and holds the signing key. Either could do everything.

## Decision

The manager owns queue, artifacts, audit records, comment drafts, signature
records, mod.io upload and audit logs. The Go CLI fetches, audits, repackages
and signs, authenticating with a revocable manager API key, and never talks to
mod.io directly.

## Consequences

- Token exposure is limited to the server; a compromised signer machine leaks
  only its own API key, which is revocable.
- The manager must grow queue/download/submit/comment endpoints and an
  `auditor` role.
- Offline audit still works on local files; submission needs the manager.
- Two components to deploy and version-check (`GET /api/version`).
