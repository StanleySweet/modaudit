# 0013 — Blob holds one signature per alpha; `dependencies` from mod.json

Status: accepted. Supersedes [0010](0010-metadata-dependencies.md).

## Context

0010 assumed `mod.json` carries no engine tag and that a blob holds one
signature. Both are false:

- Engine `source/ps/ModIo.cpp` `ParseSignature` walks `minisigs`, skips entries
  whose key number differs from the running alpha's public key, and accepts the
  first matching `ED` (prehashed) entry. Any malformed entry met before the
  match (fewer than 4 lines, bad prefix, bad base64) fails the whole mod.
- Blob `dependencies` is only displayed in the in-game mod.io list
  (`gui/modio/modio.js`); load-time compatibility comes from the downloaded
  `mod.json`. The wiki and the community-mod upload script copy `mod.json`
  `dependencies` into the blob. `mod.json` may contain `0ad` or `0ad=0.0.23`.
- Real cross-alpha mods (e.g. linux-libertine) ship one blob with signatures
  from the a23b, a24, a25, a26 and a27 keys over the same bytes, and
  `dependencies: ["0ad"]`.
- Per-alpha mod public keys are public: `modio.public_key` in
  `binaries/data/config/default.cfg` at each release tag.

## Decision

- Blob `dependencies` is the `mod.json` `dependencies` array, verbatim.
- The alpha a signature serves is bound by its key number, checked against a
  committed trust store of per-alpha public keys taken from engine release tags.
- Default signing produces a blob with the single signature for `target_alpha`.
- Cross-alpha signing merges into an existing blob: the entry with the same key
  number is replaced; other entries are kept only if they verify against the
  exact bytes being signed with a trust-store key, otherwise the merge refuses.
- Every entry of an output blob is validated in engine order (structure, `ED`,
  key in trust store, verifies against the bytes).
- After decrypting, the signing key's public half must equal the trust-store key
  for `target_alpha`; a key file named for one alpha but holding another refuses.
- The audit flags a `mod.json` `0ad` dependency that does not admit
  `target_alpha`: the engine would refuse to load it.

## Consequences

- One blob can serve several alphas without losing older signatures.
- Matches what the wiki, community-mod and existing published blobs do;
  differs from `minisign.py`, which writes `0ad=<key alpha>`.
- The trust store must be updated when a new alpha key is released.
- New bytes (new modfile) never inherit old signatures: they no longer verify.
