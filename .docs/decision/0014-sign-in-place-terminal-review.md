# 0014 — Sign in place; one terminal review per mod

Status: accepted. Amends design §13 (publish) and ADR 0009 (comment approval).

## Context

Design §13 assumed mod.io Edit Modfile accepts only `changelog`, `version` and
`active`, so a signature meant re-uploading the zip. The mod.io OpenAPI spec
(`https://api.mod.io/v1/swagger`, `PUT /games/{game-id}/mods/{mod-id}/files/{file-id}`)
also accepts `metadata_blob`. For a `SIGN` verdict the distributed bytes do not
change, so there is nothing to upload.

The signer wants one approval per mod, not a terminal step plus a web step.

## Decision

- `SIGN`: `modaudit review` downloads the modfile, checks it against the audited
  SHA-256, shows the summary and asks for the first 12 hex of the SHA-256. It then
  signs and sends only the `metadata_blob` to the manager
  (`POST /api/v1/reviews/{task}/publish`). The manager streams the modfile from
  mod.io itself, checks the SHA-256 against the audit record, verifies every
  minisig against its per-alpha trust store, and only then `PUT`s the blob on the
  existing modfile.
- `REFUSE`: the same review shows the rule-based draft; `c` posts it through the
  manager (`/comment`), `d` dismisses, the default skips.
- Typing the token or `c` on the terminal is the human approval; ADR 0009's web
  approval is not required for comments posted this way.
- A new zip upload (`POST /files`) is reserved for `REPACKAGE`, where the bytes
  change.

## Consequences

- No 800 MB uploads from the signer machine; the manager re-hashes from mod.io.
- The key password is decrypted once per review session and stays in memory only.
- A failed write shows up again in the next review with its error.
- The manager UI is a history (audit log), not an approval step.
