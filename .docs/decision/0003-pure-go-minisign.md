# 0003 — Pure-Go minisign, no cgo or external binary

Status: accepted

## Context

Signing needs encrypted-key decryption, streaming over large zips, and
verification. The C `minisign` binary is a CLI, not a library; linking it means
cgo, libsodium and per-OS toolchains.

## Decision

Use `aead.dev/minisign` (MIT): `DecryptKey`, `NewReader` + `SignWithComments`,
`Verify`, `Signature.MarshalText`. Verify locally after signing. Keep the
official C binary in CI only, as a cross-check.

## Consequences

- Static cross-compilation stays simple; no external runtime dependency.
- Library is pre-1.0: pin the version, vendor if practical.
- CI must verify both directions: Go signature accepted by C minisign and C
  signature accepted by Go.
- Key files stay password-encrypted `.pem`; format compatibility is tested, not
  assumed.
