# 0007 — archivebuild-compress on every repackage

Status: accepted

## Context

Repacking could be structural only (fix layout, strip junk) or go through
pyrogenesis to produce compiled assets. Mixed packages are the compatibility
problem being fixed.

## Decision

Every repackage runs pyrogenesis `-archivebuild-compress` using the engine
version matching the signing key. Packaging detection before repackaging is
static: layout faults, or source assets without their compiled counterpart
(notably `.xml` without `.xmb`).

## Consequences

- Rebuilt zips are internally consistent and match the engine expectations.
- Repackage is slower and needs the matching pyrogenesis build locally.
- pyrogenesis runs only after the deterministic audit passes, never on
  untrusted content that already failed.
- If pyrogenesis is missing or its version differs from the key alpha, abort.
- `archivebuild` output is not guaranteed byte-identical across engine versions;
  the manifest diff, not the hash, is the safety proof.
