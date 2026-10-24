# 0009 — Comments are queued drafts, human-approved

Status: accepted

## Context

Refusal comments are public and effectively irreversible. Automated posting on a
deterministic blocker is tempting but risks posting on a false positive or a
mislabelled mod.

## Decision

Every comment is created as a draft in the manager. A signer or admin approves
it in the manager UI; the manager posts through the mod.io token and records the
comment id. Drafts are built from rule code templates, not LLM prose.

## Consequences

- No public comment without human action.
- Posting is idempotent: one open draft per mod/version.
- Comment wording is consistent and costs no tokens.
- Refusals need someone to work the queue; the manager queue makes that visible.
- Repackage comments disclose that WFG rebuilt and signed the artifact.
