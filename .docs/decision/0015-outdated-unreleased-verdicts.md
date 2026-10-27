# 0015 — OUTDATED and UNRELEASED verdicts

Status: accepted. Amends [0004](0004-verdict-model.md).

## Context

Keys before A26 have lost passwords, and only `target_alpha` (0.28.0) is signed.
Mods whose `mod.json` pins another engine (`0ad=0.0.23`, `0ad<=0.0.27`,
`0ad>=0.29.0`) can never be signed today, yet they sat in review forever, and
refusing them with a public comment would be noise. `EngineAdmits` also OR-ed the
`0ad` constraints, so `["0ad>=0.0.26","0ad<=0.0.27"]` passed for 0.28.

## Decision

- Every `0ad` constraint must admit `target_alpha` (AND).
- If an upper bound excludes it, the audit adds `ENGINE_OUTDATED` and the verdict
  is `OUTDATED`; if a lower bound is above it, `ENGINE_UNRELEASED` and
  `UNRELEASED`. These win over blockers: no comment is drafted or posted.
- Exit codes: `5` OUTDATED, `6` UNRELEASED.
- The manager hides both from `modaudit review`; the Audits page shows them.
- Only `target_alpha` is signed; earlier alphas are not signed even when a key exists.

## Consequences

- A newer modfile that admits `target_alpha` is a new version and is queued normally.
- When `target_alpha` moves to a new release, re-queue OUTDATED/UNRELEASED tasks.
