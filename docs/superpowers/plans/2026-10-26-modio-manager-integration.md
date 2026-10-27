# Lot 3: modio-manager Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect Go CLI (modaudit) to Fastify backend (modio-manager) for end-to-end queue-to-submission pipeline: claim tasks, download mods, audit/sign, submit results.

**Architecture:** Two repos: Fastify backend (Control Plane, OVH) holds queue + auth; Go CLI (Data Plane, signer machine) polls queue, runs audit engine, interactive Minisign signing, submits results. SQLite via Knex for queue/tasks. Separate API Key auth for machine-to-machine queue endpoints. Multipart/form-data submissions.

**Tech Stack:** Fastify, Knex, better-sqlite3, TypeScript (backend); Go 1.26, Cobra, net/http, minisign (CLI).

**Spec:** docs/superpowers/specs/2026-10-26-modio-manager-integration-design.md

## Global Constraints

- Minisign passphrase MUST be interactive TTY prompt — no `--yes`, no env var, no config file
- Signatures generated against final distribution bytes (exact zip uploaded to mod.io)
- Queue endpoints use Manager API Key (Bearer), not user JWT
- SQLite database via existing Knex setup
- Go module: `github.com/stan/modaudit`
- Fastify module: `modio-manager-backend`

## Review Focus

1. **API Key auth bypass** — request with invalid/expired key must 401, not fall through to JWT
2. **Queue claim race** — two workers polling simultaneously must not get same task (atomic claim)
3. **Passphrase prompt on non-TTY** — must fail cleanly with "no terminal" error, not hang or echo
4. **Signature verification mismatch** — submitted signature must verify against exact zip bytes CLI downloaded
5. **Multipart submission with large zip** — must stream, not buffer entire file in memory

---

### Task 1: Database Migration — queue_tasks and api_keys tables (modio-manager)

**Files:**
- Create: `backend/src/database/migrations/20251213000008_add_queue_tasks_and_api_keys.ts`
- Test: Manual via `npm run migrate:latest`

**Interfaces:**
- Produces: Tables `api_keys`, `queue_tasks` with indexes

- [ ] **Step 1: Write migration file**

```typescript
// 20251213000008_add_queue_tasks_and_api_keys.ts
import type { Knex } from 'knex';

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable('api_keys', (table) => {
    table.increments('id').primary();
    table.string('name', 255).notNullable();
    table.string('key_hash', 255).notNullable().unique();
    table.string('role', 50).notNullable().defaultTo('queue_worker');
    table.timestamp('created_at').notNullable().defaultTo(knex.fn.now());
    table.timestamp('last_used_at').nullable();
    table.timestamp('revoked_at').nullable();
    table.index('key_hash');
    table.index('role');
  });

  await knex.schema.createTable('queue_tasks', (table) => {
    table.increments('id').primary();
    table.integer('mod_id').unsigned().notNullable().references('id').inTable('mods').onDelete('CASCADE');
    table.integer('mod_version_id').unsigned().notNullable().references('id').inTable('mod_versions').onDelete('CASCADE');
    table.enu('task_type', ['audit', 'sign', 'audit_and_sign']).notNullable();
    table.enu('status', ['pending', 'claimed', 'completed', 'failed']).notNullable().defaultTo('pending');
    table.integer('priority').notNullable().defaultTo(0);
    table.json('payload').nullable();
    table.json('result').nullable();
    table.text('error').nullable();
    table.timestamp('claimed_at').nullable();
    table.integer('claimed_by').unsigned().nullable().references('id').inTable('users').onDelete('SET NULL');
    table.timestamp('completed_at').nullable();
    table.timestamp('created_at').notNullable().defaultTo(knex.fn.now());
    table.timestamp('updated_at').notNullable().defaultTo(knex.fn.now());
    table.index('status');
    table.index('mod_version_id');
    table.index(['status', 'priority', 'created_at']);
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('queue_tasks');
  await knex.schema.dropTableIfExists('api_keys');
}
```

- [ ] **Step 2: Run migration**

Run: `cd /Users/stan/Dev/modio-manager/backend && npm run migrate:latest`
Expected: Success, tables created

- [ ] **Step 3: Verify schema**

Run: `sqlite3 data/modio.db ".schema api_keys" && sqlite3 data/modio.db ".schema queue_tasks"`
Expected: Tables with correct columns, indexes, FKs

- [ ] **Step 4: Commit**

```bash
git add backend/src/database/migrations/20251213000008_add_queue_tasks_and_api_keys.ts
git commit -m "feat(db): add api_keys and queue_tasks tables for queue worker integration"
```

---

### Task 2: API Key Authentication Middleware (modio-manager)

**Files:**
- Create: `backend/src/middleware/apiKey.ts`
- Modify: `backend/src/index.ts` (register middleware)

**Interfaces:**
- Consumes: `getDB()` from `database/db.ts`, Argon2 from `utils/password.ts`
- Produces: `authenticateApiKey(request, reply)` middleware attaching `request.apiKey = { id, role }`

- [ ] **Step 1: Write failing test** (integration style)

```typescript
// test/apiKey.test.ts (or manual curl test)
import { FastifyInstance } from 'fastify';
import { buildApp } from '../src/index';

const app = await buildApp();
const res = await app.inject({ method: 'GET', url: '/api/v1/queue/next' });
assert(res.statusCode === 401);

const res2 = await app.inject({ 
  method: 'GET', 
  url: '/api/v1/queue/next', 
  headers: { authorization: 'Bearer invalid' } 
});
assert(res2.statusCode === 401);
```

- [ ] **Step 2: Run test to verify it fails** (no middleware yet)

- [ ] **Step 3: Implement `authenticateApiKey` in `backend/src/middleware/apiKey.ts`**

```typescript
import { FastifyRequest, FastifyReply } from 'fastify';
import { getDB } from '../database/db.js';
import { verifyPassword } from '../utils/password.js';

declare module 'fastify' {
  interface FastifyRequest {
    apiKey?: { id: number; role: string };
  }
}

export async function authenticateApiKey(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<void> {
  const authHeader = request.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return reply.status(401).send({ error: 'Unauthorized', message: 'Missing or invalid API key' });
  }
  const providedKey = authHeader.substring(7);
  const db = getDB();
  const keys = await db('api_keys').whereNull('revoked_at').select('id', 'key_hash', 'role');
  for (const key of keys) {
    if (await verifyPassword(providedKey, key.key_hash)) {
      await db('api_keys').where({ id: key.id }).update({ last_used_at: new Date() });
      request.apiKey = { id: key.id, role: key.role };
      return;
    }
  }
  return reply.status(401).send({ error: 'Unauthorized', message: 'Invalid API key' });
}
```

- [ ] **Step 4: Register middleware in `backend/src/index.ts`** (before autoLoad)

- [ ] **Step 5: Run test to verify it passes**

- [ ] **Step 6: Commit**

```bash
git add backend/src/middleware/apiKey.ts backend/src/index.ts
git commit -m "feat(auth): add API key authentication middleware for queue endpoints"
```

---

### Task 3: Queue Endpoints Plugin (modio-manager)

**Files:**
- Create: `backend/src/plugins/queue.ts`
- Modify: `backend/src/index.ts` (autoLoad already picks up plugins/)

**Interfaces:**
- Consumes: `authenticateApiKey`, `getDB()`, mod.io download URL logic
- Produces: `GET /api/v1/queue/next`, `POST /api/v1/mods/:modId/submissions`

- [ ] **Step 1: Write failing tests** (integration)

```typescript
// Test: claim task
const task = await db('queue_tasks').insert({ mod_id: 1, mod_version_id: 1, task_type: 'audit_and_sign' }).returning('*');
const res = await app.inject({ method: 'GET', url: '/api/v1/queue/next', headers: { authorization: `Bearer ${validKey}` } });
assert(res.statusCode === 200);
assert(res.json().task.id === task[0].id);

// Test: submit result
const form = new FormData();
form.append('task_id', taskId);
form.append('verdict', 'SIGN');
form.append('report', JSON.stringify(report));
const res2 = await app.inject({ method: 'POST', url: `/api/v1/mods/1/submissions`, headers: { authorization: `Bearer ${validKey}` }, payload: form });
assert(res2.statusCode === 200);
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement `backend/src/plugins/queue.ts`**

Key implementation details:
- `GET /queue/next`: Atomic claim via `UPDATE queue_tasks SET status='claimed', claimed_at=now(), claimed_by=? WHERE id=(SELECT id FROM queue_tasks WHERE status='pending' ORDER BY priority DESC, created_at ASC LIMIT 1) RETURNING *`
- Join with `mods` and `mod_versions` to return download URL, checksum, version info
- `POST /mods/:modId/submissions`: Parse multipart, validate task_id matches claimed task, store result JSON, update mod_version (is_signed, signature, checksum_hash), mark task completed/failed
- Use `@fastify/multipart` for file upload handling
- Stream file to disk (temp) for repackaged_zip, compute SHA256, verify against report

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add backend/src/plugins/queue.ts
git commit -m "feat(queue): add GET /queue/next and POST /mods/:modId/submissions endpoints"
```

---

### Task 4: API Key Management CLI/Script (modio-manager)

**Files:**
- Create: `backend/src/scripts/create-api-key.ts` (or add to existing CLI)

**Interfaces:**
- Consumes: `getDB()`, Argon2 hash
- Produces: Plaintext API key printed once, hash stored

- [ ] **Step 1: Implement script to create API key**

```typescript
// Usage: npx tsx src/scripts/create-api-key.ts "worker-1" queue_worker
import { getDB } from '../database/db.js';
import { hashPassword } from '../utils/password.js';

const [, , name, role = 'queue_worker'] = process.argv;
const plainKey = `mk_${crypto.randomBytes(32).toString('hex')}`;
const keyHash = await hashPassword(plainKey);
await getDB()('api_keys').insert({ name, key_hash: keyHash, role });
console.log(`API Key (save now, shown once): ${plainKey}`);
```

- [ ] **Step 2: Test creating a key**

- [ ] **Step 3: Commit**

```bash
git add backend/src/scripts/create-api-key.ts
git commit -m "feat(scripts): add API key creation script for queue workers"
```

---

### Task 5: Go CLI — Manager Client Package (modaudit)

**Files:**
- Create: `internal/manager/client.go`
- Create: `internal/manager/client_test.go`
- Create: `internal/manager/types.go`

**Interfaces:**
- Consumes: Config (manager_url, api_key_file, api_key_cmd)
- Produces: `ManagerClient` with methods:
  - `NextTask(ctx) (*Task, error)`
  - `SubmitResult(ctx, taskID, modID, Submission) error`
  - `DownloadMod(ctx, url, destPath, expectedSHA256) error`

- [ ] **Step 1: Define types in `internal/manager/types.go`**

```go
package manager

type Task struct {
    ID            int64
    ModID         int64
    ModVersionID  int64
    TaskType      string // "audit", "sign", "audit_and_sign"
    Payload       map[string]any
    Mod           ModInfo
}

type ModInfo struct {
    Name         string
    Version      string
    DownloadURL  string
    ChecksumSHA256 string
    FileSize     int64
}

type Submission struct {
    Verdict        string
    Report         []byte // JSON report.Report
    SignatureBlob  []byte // JSON blob.Blob (optional)
    CommentDraft   string // optional
    RepackagedZip  string // path to zip file (optional)
}
```

- [ ] **Step 2: Write failing test for `NextTask`**

```go
func TestClient_NextTask(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))
        w.WriteHeader(200)
        json.NewEncoder(w).Encode(map[string]any{
            "task": map[string]any{"id": 1, "mod_id": 1, "mod_version_id": 1, "task_type": "audit_and_sign"},
            "mod": map[string]any{"name": "test", "version": "1.0", "download_url": "http://example.com/mod.zip", "checksum_sha256": "abc", "filesize": 100},
        })
    }))
    defer ts.Close()

    c := NewClient(ts.URL, "test-key")
    task, err := c.NextTask(context.Background())
    assert.NoError(t, err)
    assert.Equal(t, int64(1), task.ID)
}
```

- [ ] **Step 3: Implement `ManagerClient` in `internal/manager/client.go`**

- HTTP client with timeout, Bearer auth
- `NextTask`: GET /api/v1/queue/next, parse response
- `DownloadMod`: Stream download with progress, verify SHA256 on the fly
- `SubmitResult`: Build multipart form, POST /api/v1/mods/:modId/submissions

- [ ] **Step 4: Run test to verify it passes**

- [ ] **Step 5: Commit**

```bash
git add internal/manager/types.go internal/manager/client.go internal/manager/client_test.go
git commit -m "feat(manager): add HTTP client for queue polling and submission"
```

---

### Task 6: Go CLI — process-queue Command (modaudit)

**Files:**
- Create: `cmd/modaudit/queue.go`
- Modify: `cmd/modaudit/main.go` (register command)

**Interfaces:**
- Consumes: `manager.Client`, `audit.Run`, `signer.Sign`, `approval.Password`, `config.Load`
- Produces: `process-queue` command

- [ ] **Step 1: Write failing test** (integration-style, uses test server)

```go
func TestProcessQueue_OneTask(t *testing.T) {
    // Setup test server with one pending task
    // Run process-queue --once
    // Verify task claimed, audit run, submission made
}
```

- [ ] **Step 2: Implement `queue.go` with `processQueue` command**

Key logic:
```go
func runProcessQueue(args []string) int {
    fs := flag.NewFlagSet("process-queue", flag.ContinueOnError)
    interval := fs.Int("interval", 30, "poll interval seconds")
    once := fs.Bool("once", false, "process one task and exit")
    verbose := fs.Bool("v", false, "verbose")
    // parse config, load API key from file or cmd
    // loop:
    //   task, err := client.NextTask(ctx)
    //   if 404: sleep, continue
    //   download zip to temp file
    //   run audit.Run()
    //   if verdict == SIGN:
    //     term, _ := approval.Open()
    //     pw, _ := approval.Password(term, vaultCmd, keyName)
    //     res, _ := signer.Sign(Request{ZipPath: zipPath, WantSHA256: report.ZipSHA256, ...})
    //     blob, _ := blob.Merge(oldBlob, deps, res.Signature, zipPath)
    //   submit via client.SubmitResult()
    //   cleanup temp files
}
```

- [ ] **Step 3: Register command in `main.go`**

Add `"process-queue"` case in `run()` switch.

- [ ] **Step 4: Run test to verify it passes**

- [ ] **Step 5: Commit**

```bash
git add cmd/modaudit/queue.go cmd/modaudit/main.go
git commit -m "feat(cli): add process-queue command for queue worker loop"
```

---

### Task 7: Config Updates for Manager Integration (modaudit)

**Files:**
- Modify: `internal/config/config.go` (add ManagerURL, APIKeyFile, APIKeyCmd if not present)
- Modify: `config.toml.example` (document new fields)

**Interfaces:**
- Consumes: Existing Config struct
- Produces: Config with manager_url, api_key_file, api_key_cmd

- [ ] **Step 1: Verify config.go already has fields** (from spec: ManagerURL, APIKeyFile, APIKeyCmd, VaultCmd — already present)

- [ ] **Step 2: Update config.toml.example with comments**

- [ ] **Step 3: Commit**

```bash
git add internal/config/config.go config.toml.example
git commit -m "docs(config): document manager integration settings"
```

---

### Task 8: End-to-End Integration Test (both repos)

**Files:**
- Create: `testdata/integration_test.sh` (or similar)

**Interfaces:**
- Consumes: Running modio-manager backend, built modaudit binary

- [ ] **Step 1: Start modio-manager backend with test DB**

- [ ] **Step 2: Create API key via script**

- [ ] **Step 3: Insert test mod + version + queue task**

- [ ] **Step 4: Run `modaudit process-queue --once` with test config**

- [ ] **Step 5: Verify task completed, mod_version updated, signature stored**

- [ ] **Step 6: Clean up**

- [ ] **Step 7: Commit**

```bash
git add testdata/integration_test.sh
git commit -m "test: add end-to-end integration test for queue pipeline"
```

---

### Task 9: Documentation and Cleanup

**Files:**
- Modify: `README.md` (both repos) — document queue worker setup
- Modify: `CLAUDE.md` if needed

**Interfaces:**
- Produces: User-facing docs

- [ ] **Step 1: Update mod-signing-bench README** with `process-queue` usage

- [ ] **Step 2: Update modio-manager README** with queue endpoint docs, API key creation

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add queue worker setup and usage documentation"
```