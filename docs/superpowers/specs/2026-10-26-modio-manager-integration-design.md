# Lot 3: modio-manager Integration Design

## Intent and Why

Connect the Go CLI (`modaudit`) to the Fastify backend (`modio-manager`) for an end-to-end queue-to-submission pipeline. The Control Plane (Fastify on OVH) holds queues, OAuth tokens, and audit records. The Data Plane (Go CLI on secure signer machine) pulls tasks, downloads mods, runs audits, handles interactive Minisign key decryption, and pushes results back.

## Goals

1. **Fastify Backend**: Two new endpoints under `/api/v1`:
   - `GET /api/v1/queue/next` — Claim next pending mod audit/sign task (Manager API Key bearer token)
   - `POST /api/v1/mods/:modId/submissions` — Receive CLI execution results (JSON payload + multipart/form-data for repackaged mod zip)

2. **Go CLI**: New `process-queue` command that:
   - Polls the queue endpoint
   - Downloads mod zip from mod.io
   - Runs audit engine
   - Prompts interactively for Minisign passphrase (no `--yes` flag)
   - Signs against final distribution bytes
   - Submits verdict, audit report, signature blob, and optionally repackaged zip

## Non-Goals

- Building the mod.io OAuth flow (already exists in modio-manager)
- Frontend/UI for queue monitoring
- Automatic retry/backoff logic beyond basic HTTP retry
- Multi-signer coordination (single signer for now)

## Anti-Goals

- Storing signing keys on the Control Plane
- Running binary execution on the Control Plane
- Bypassing interactive passphrase prompt

## Constraints

- **Security**: Minisign private key passphrase MUST be entered interactively via TTY. No `--yes` flag, no env var, no config file.
- **Signature integrity**: Signatures must be generated against the final distribution bytes (the exact zip that will be uploaded to mod.io).
- **Authentication**: Queue endpoints use Manager API Key (Bearer token), not user JWT.
- **Database**: SQLite via Knex (existing setup in modio-manager).

## Approaches Considered

### 1. Queue Table Design
**Option A**: Single `queue_tasks` table with status enum (`pending`, `claimed`, `completed`, `failed`)
- Pros: Simple, single source of truth
- Cons: Claiming requires transaction with row locking

**Option B**: Separate `queue_pending` and `queue_completed` tables
- Pros: No locking contention, natural partitioning
- Cons: More complex migrations, duplication

**Decision**: Option A with `SELECT ... FOR UPDATE SKIP LOCKED` equivalent in SQLite (using `UPDATE ... SET status='claimed' WHERE id=(SELECT id FROM queue_tasks WHERE status='pending' ORDER BY created_at LIMIT 1) RETURNING *`). SQLite doesn't support `FOR UPDATE SKIP LOCKED` but the UPDATE-with-subquery pattern works atomically.

### 2. API Key vs JWT for Queue Endpoints
**Option A**: Reuse JWT auth middleware
- Pros: Consistent auth
- Cons: Queue workers are machines, not users; JWT expires; different threat model

**Option B**: Separate API Key middleware (Bearer token from `MANAGER_API_KEY` env)
- Pros: Long-lived, machine-to-machine, simple rotation
- Cons: Another auth mechanism

**Decision**: Option B. Add `api_keys` table, new middleware `authenticateApiKey`.

### 3. Submission Payload Format
**Option A**: Single multipart/form-data with JSON part + file part
- Pros: Single request, handles large files
- Cons: More complex parsing

**Option B**: Two-step: POST JSON first, then PUT file if needed
- Pros: Simpler JSON handling
- Cons: Two requests, eventual consistency

**Decision**: Option A. Fastify handles multipart natively. JSON fields: `verdict`, `report`, `signature_blob`, `comment_draft`. File field: `repackaged_zip` (optional).

### 4. Go CLI Queue Loop
**Option A**: Long-polling with configurable interval
- Pros: Simple, works everywhere
- Cons: Latency up to poll interval

**Option B**: WebSocket/SSE for push notifications
- Pros: Instant notification
- Cons: More complex, connection management

**Decision**: Option A. Poll every 30s (configurable). Simplicity wins for v1.

## Design Details

### Database Migration (modio-manager)

New migration: `20251213000008_add_queue_tasks_and_api_keys.ts`

```sql
-- API keys for machine-to-machine auth
CREATE TABLE api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,  -- Argon2 hash
  role TEXT NOT NULL DEFAULT 'queue_worker', -- 'queue_worker', 'admin'
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_used_at TIMESTAMP NULL,
  revoked_at TIMESTAMP NULL
);

-- Queue tasks for mod audit/sign
CREATE TABLE queue_tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mod_id INTEGER NOT NULL REFERENCES mods(id) ON DELETE CASCADE,
  mod_version_id INTEGER NOT NULL REFERENCES mod_versions(id) ON DELETE CASCADE,
  task_type TEXT NOT NULL CHECK (task_type IN ('audit', 'sign', 'audit_and_sign')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'claimed', 'completed', 'failed')),
  priority INTEGER NOT NULL DEFAULT 0,
  payload JSON,  -- Additional context (e.g., mod.io file URL, target alpha)
  result JSON,   -- Submission result (verdict, report, signatures, etc.)
  error TEXT,    -- Error message if failed
  claimed_at TIMESTAMP NULL,
  claimed_by INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
  completed_at TIMESTAMP NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_queue_tasks_status ON queue_tasks(status);
CREATE INDEX idx_queue_tasks_mod_version ON queue_tasks(mod_version_id);
```

### Fastify Endpoints

#### `GET /api/v1/queue/next`
- **Auth**: Manager API Key (Bearer token via `authenticateApiKey` middleware)
- **Behavior**: Atomically claim oldest pending task, return task details + mod.io download URL
- **Response**: `{ task: { id, mod_id, mod_version_id, task_type, payload }, mod: { name, mod_io_url, version, download_url, filesize, checksum_hash } }`
- **404**: No pending tasks
- **401**: Invalid/missing API key

#### `POST /api/v1/mods/:modId/submissions`
- **Auth**: Manager API Key
- **Content-Type**: `multipart/form-data` (or `application/json` for JSON-only)
- **Fields**:
  - `task_id` (string, required) — Queue task ID being completed
  - `verdict` (string, required) — One of: `SIGN`, `REPACKAGE`, `REFUSE`, `NEEDS_HUMAN`
  - `report` (string, required) — JSON audit report (serialized `report.Report`)
  - `signature_blob` (string, optional) — JSON blob with minisigs
  - `comment_draft` (string, optional) — Draft comment for mod.io
  - `repackaged_zip` (file, optional) — New zip if verdict=REPACKAGE
- **Behavior**: Validate task exists and is claimed, store result, update mod_version (is_signed, signature, checksum), mark task completed
- **Response**: `{ success: true, task_id }`

### Go CLI: `process-queue` Command

**Command**: `modaudit process-queue [flags]`

**Flags**:
- `--config` — Config file path (default: `$MOD_AUDIT_CONFIG`, then `./config.toml`)
- `--interval` — Poll interval in seconds (default: 30)
- `--once` — Process one task and exit (for testing)
- `--verbose` — Verbose logging

**Flow**:
1. Load config (manager_url, api_key_file/api_key_cmd, vault_cmd, key_dir, target_alpha)
2. Resolve API key (read file or run command)
3. Loop:
   a. `GET /api/v1/queue/next` with Bearer token
   b. If 404, sleep interval, continue
   c. Download mod zip from `mod.download_url` (stream to temp file)
   d. Verify checksum matches `mod.checksum_hash`
   e. Run `audit.Run()` on zip
   f. If verdict == SIGN:
      - Interactive TTY prompt for Minisign passphrase (via `approval.Password`)
      - Run `signer.Sign()` on the **exact same zip bytes**
      - Build signature blob
   g. If verdict == REPACKAGE:
      - Repackage using `archivebuild` (pyrogenesis) — out of scope for Lot 3, but CLI should support submitting the new zip
   h. `POST /api/v1/mods/:modId/submissions` with multipart form
   i. On success, delete temp files, continue loop

**Security Enforcement**:
- Passphrase prompt uses `approval.Open()` → `approval.Password()` — requires real TTY
- No `--yes` flag, no `VAULT_PASSWORD` env var support
- Signature generated via `signer.Sign()` which hashes the zip stream and verifies hash matches report

## What's Left to Builder

- Exact multipart field names and JSON schema
- Error handling and retry logic in Go CLI
- Rate limiting on queue endpoints
- Cleanup of temp files on interrupt
- Tests for both sides