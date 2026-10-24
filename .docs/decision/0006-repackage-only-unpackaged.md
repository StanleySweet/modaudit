# 0006 — Repackage only validated-but-unpackaged mods

Status: accepted

## Context

Many pending mods fail only because they were not run through
`-archivebuild-compress`, or ship a bad archive layout. Others are unsafe,
broken, or try to bypass compatibility checks.

## Decision

Repackaging is allowed only for `REPACKAGE`: the audit found no safety, quality
or compatibility blocker, but packaging is wrong. Unsafe, broken and
compatibility-violating mods get a queued refusal comment and nothing else.

Repackaging requires: human yes, patch bump of `mod.json` `version`, extraction
with traversal protection, junk removal, archivebuild, reproducible rebuild,
full re-audit, manifest comparison, human confirmation, signature over the
rebuilt zip, manager upload, and a comment stating the mod was repackaged.

## Consequences

- The signature guarantee becomes "WFG audited and produced these exact bytes".
- New modfile upload is required (mod.io cannot edit an existing file's blob).
- The original upload is never signed.
- Any unexpected file change aborts and falls back to a human decision.
- Author rights: the signer's game-admin account performs the upload; the
  changelog discloses the repackage.
