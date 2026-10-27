# 0010 — `dependencies` from key alpha, not mod.json

Status: superseded by [0013](0013-blob-per-alpha-signatures.md)

## Context

The signature blob is
`{"dependencies":["0ad=<version>"],"minisigs":[...]}`. The existing
`minisign.py` derives the version from the key filename. Community-mod and the
wiki show `mod.json` dependencies instead, which are *mod* dependencies.

## Decision

The blob's `dependencies` entry is `0ad=<engine alpha>` taken from the selected
signing key (`minisign-0.28.0.pem` → `0ad=0.28.0`). `mod.json` `dependencies`
describe mods, are recorded as metadata, and are never used in the blob.

## Consequences

- The blob cannot lie about which engine the signature targets.
- Key filename is the authority for the alpha; the CLI cross-checks it against
  the target version in the queue record and refuses on mismatch.
- Manager verifies signatures against the per-alpha trust store.
- Mod dependency metadata is still visible to the signer and stored in records.
