# 0012 — Signing on macOS, Linux and Windows

Status: accepted

## Context

Signing may move beyond the current Mac. Approval must be genuinely interactive
on each platform, and key material must not be written to disk in plaintext.

## Decision

- Approval: Go `x/term`; `/dev/tty` on Unix, `CONIN$` on Windows. Refuse when no
  terminal. Exact-token confirmation, no bypass flag.
- Keys: the same encrypted `.pem` files everywhere, distributed through OneDrive
  or KeePassXC; decrypted in memory only.
- Signing: `aead.dev/minisign` streams the file; no temp key file, no FIFO.
- Binaries: cross-compiled static builds for darwin arm64/amd64, linux
  arm64/amd64, windows amd64.

## Consequences

- One code path for signing across all three platforms.
- Windows approval needs a real-hardware smoke test before it is claimed.
- OneDrive sync conflicts are possible; read-only signing and an offline backup
  keep that low.
- Audit-only use needs no key path and works anywhere.
