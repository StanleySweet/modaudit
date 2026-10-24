# 0005 — Client-side LLM, capped bundle, no comment prose

Status: accepted

## Context

Mod code is untrusted and may be sensitive; adding an LLM key to the OVH host
expands the attack surface. Large mods can exceed any fixed token budget.

## Decision

Judgement runs on the signer machine through the OpenCode skill, over a compact
bundle: findings, `mod.json`, added/changed executable files, manifest diff.
Caps: 60k input tokens or 50 files. Unchanged content inherits approval by hash.
Exceeding a cap yields `NEEDS_HUMAN`. Public comments use templates, not LLM
text.

## Consequences

- No LLM credentials on the server.
- Token cost per mod is dominated by changed executable files.
- Big total conversions frequently land on `NEEDS_HUMAN`; acceptable.
- Bundle must be schema-versioned so the skill and CLI agree.
