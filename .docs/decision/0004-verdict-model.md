# 0004 — Four verdicts; deterministic blockers win

Status: accepted

## Context

The audit combines rules and an LLM. A model must not be able to wave through a
structural or policy violation, and humans need a single unambiguous outcome.

## Decision

Verdicts: `SIGN`, `REPACKAGE`, `REFUSE`, `NEEDS_HUMAN`.

Deterministic blockers force `REFUSE` and cannot be cleared by the LLM. The LLM
may only add suspicion. Budget overrun or conflicting signals yield
`NEEDS_HUMAN`, never `SIGN`.

## Consequences

- Rule codes are the unit of truth; the report lists them with severity.
- Comment bullets map from rule codes.
- Any byte change invalidates the verdict and forces re-audit.
- The LLM schema must include only allowed verdicts and cited file paths.
