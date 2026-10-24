# 0008 — Encrypted keys stay off the server

Status: accepted

## Context

Signing keys are currently password-encrypted `.pem` files in OneDrive. Server
vaults (OpenBao, Infisical) were considered for convenience.

## Decision

Keep the encrypted `.pem` files local/OneDrive, optionally inside KeePassXC.
Never store a signing key on the OVH manager. Password is typed at signing time
or fetched through `--password-cmd` (for example `keepassxc-cli show -a`), never
from the environment and never printed.

## Consequences

- A manager compromise cannot produce signatures.
- Signing always needs a human at a terminal.
- Key files are still readable by the agent, but useless without the password.
- Server secrets remain root-owned `.env`; adopt SOPS+age only if env files
  start going through Git.
- Residual risk: a compromised interactive session with the password can sign.
