# Decision log

One file per decision. Newest decisions get the next number. Never rewrite an
accepted decision; supersede it with a new one and link both ways.

| ADR | Decision |
|---|---|
| [0001](0001-manager-control-plane.md) | Manager is control plane, Go CLI is data plane |
| [0002](0002-go.md) | Tool written in Go |
| [0003](0003-pure-go-minisign.md) | Pure-Go minisign library, no cgo or external binary |
| [0004](0004-verdict-model.md) | Four verdicts; deterministic blockers win |
| [0005](0005-llm-scope.md) | Client-side LLM, capped bundle, no comment prose |
| [0006](0006-repackage-only-unpackaged.md) | Repackage only validated-but-unpackaged mods |
| [0007](0007-archivebuild-always.md) | archivebuild-compress on every repackage |
| [0008](0008-key-custody.md) | Encrypted keys stay off the server |
| [0009](0009-queued-comments.md) | Comments are queued drafts, human-approved |
| [0010](0010-metadata-dependencies.md) | `dependencies` from key alpha, not mod.json |
| [0011](0011-manager-api.md) | Auditor role and scoped API key |
| [0012](0012-multi-machine-signing.md) | Signing on macOS, Linux and Windows |
