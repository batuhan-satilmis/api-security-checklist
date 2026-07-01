# Logging

> Code-first reference for the logging & monitoring checklist items. See also: [OWASP SaaS Hardening Guide — A09 Logging & Monitoring](https://github.com/batuhan-satilmis/owasp-saas-hardening-guide/blob/main/chapters/09-logging-monitoring.md).

Logs are two products, glued together in most codebases and paying for it. The **operational** log answers "why did this request 500 at 03:14 UTC" — high volume, mostly ephemeral, allowed to be lossy. The **audit** log answers "who changed this customer's plan on Tuesday" — low volume, append-only, must survive a disk failure and a subpoena. Treat them as one and you either drown the SIEM in JSON or lose the one event that mattered.

This chapter is the pattern I ship on every Node.js + Express + Postgres API: a structured operational logger with redaction at the boundary, a separate audit log with cryptographic tamper-evidence, and the four alerting signals that catch real attacks cheaply.

## Structured logs (JSON, not strings)

Every log line is a JSON object with a stable schema. `console.log("user " + userId + " logged in")` is unqueryable — you can grep it, but you cannot ask "how many logins from country X in the last hour" without regex. Structured logs turn that question into a filter.

❌ String concatenation with mixed severity:

```ts
// vulnerable to log injection AND unqueryable
console.log("user " + req.body.email + " failed login");
```

If `req.body.email` is `"admin@x.com\n2024-01-01 INFO user admin logged in successfully"`, an attacker has just forged an audit trail entry in your log stream. The newline is the vulnerability; string concatenation is the delivery mechanism.

✅ Structured logger. The field values are serialized by the library — newlines get escaped, not passed through:

```ts
// src/log.ts
import pino from "pino";

export const log = pino({
  level: process.env.LOG_LEVEL ?? "info",
  base: {
    service: "api",
    env: process.env.NODE_ENV,
    version: process.env.GIT_SHA,          // set at build time
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: [
      "req.headers.authorization",
      "req.headers.cookie",
      "req.headers['x-api-key']",
      "req.body.password",
      "req.body.token",
      "req.body.refresh_token",
      "req.body.card",
      "*.password",
      "*.token",
      "*.secret",
    ],
    censor: "[REDACTED]",
  },
});
```

Every log call gets an event name and a bag of fields — never interpolated strings:

```ts
// good
log.info({ userId, event: "auth.login.success" });
log.warn({ userId, event: "auth.login.failure", reason: "bad_password" });
```

The event name is the primary query key. Naming discipline matters: use `noun.verb.outcome` (`auth.login.success`, `webhook.stripe.duplicate_ignored`, `billing.charge.failed`). A grep-friendly, hierarchy-friendly namespace is what makes an alerting rule readable a year later.

## Redaction at the boundary

Redaction is easy to bolt on and easy to bolt on wrong. Two failure modes I've hit in production:

1. **Redacting on the way out of the logger, not on the way in.** The unredacted payload lives in memory long enough to be serialized somewhere else — a stack trace on Sentry, a debugger snapshot, a `console.error` that bypassed the logger. Redact at the point the object crosses your process boundary, not on write.
2. **Redacting the field name but not the field value.** If `password` is redacted but the same string appears in a free-text `notes` field the user pasted into a support form, the redaction misses it.

The pino config above handles case 1 for logs specifically. Case 2 needs an allow-list of what you're willing to log from a request body, not a deny-list of what to hide:

```ts
// src/middleware/request-logger.ts
import type { Request, Response, NextFunction } from "express";
import { log } from "../log";

// Fields safe to log from any request body. Extend per-route only when necessary.
const SAFE_BODY_FIELDS = new Set(["locale", "page", "sort", "filter"]);

function safeBody(body: unknown): Record<string, unknown> | undefined {
  if (!body || typeof body !== "object") return undefined;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(body as Record<string, unknown>)) {
    if (SAFE_BODY_FIELDS.has(k) && typeof v !== "object") out[k] = v;
  }
  return Object.keys(out).length ? out : undefined;
}

export function requestLogger(req: Request, res: Response, next: NextFunction) {
  const start = process.hrtime.bigint();
  const requestId = (req.headers["x-request-id"] as string) ?? crypto.randomUUID();
  res.setHeader("x-request-id", requestId);
  (req as any).requestId = requestId;

  res.on("finish", () => {
    const durationMs = Number((process.hrtime.bigint() - start) / 1_000_000n);
    log.info({
      event: "http.request",
      requestId,
      method: req.method,
      path: req.route?.path ?? req.path,     // route template, not raw path — avoids logging PII in :id
      status: res.statusCode,
      durationMs,
      userId: (req as any).user?.id,
      tenantId: (req as any).user?.tenantId,
      ip: req.ip,
      body: safeBody(req.body),              // allow-list, not deny-list
    });
  });

  next();
}
```

Two details that pay off:

- **Log `req.route.path`, not `req.path`.** `/users/123/reset-token/abc-xyz` becomes `/users/:id/reset-token/:token` — the request-id-in-URL never lands in logs and the log is more queryable ("all failing password resets" is one filter, not a regex).
- **`requestId` on every log line.** When a user reports a bug, one request-id gives you the full server-side story without cross-referencing timestamps.

> **Sentry / error reporters redact separately.** Pino's redaction doesn't apply to whatever your error reporter captures. Configure `beforeSend` in `@sentry/node` (or equivalent) with the same deny-list, or an error containing a raw JWT lands in an external SaaS that your redaction never touched.

## Append-only audit log

The audit log is a separate table, written from a service layer function, and never mutated. Its job: answer "who did what, to which resource, from where, and when" for compliance (SOC 2 CC7.2, ISO 27001 A.8.15, HIPAA §164.312(b)) and for post-incident forensics.

```sql
-- migrations/2024xxxx_audit_log.sql
CREATE TABLE audit_log (
  id              BIGSERIAL PRIMARY KEY,
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_type      TEXT NOT NULL CHECK (actor_type IN ('user', 'service', 'system')),
  actor_id        TEXT NOT NULL,             -- user UUID, service name, or 'system'
  tenant_id       UUID,                      -- null for cross-tenant actions
  action          TEXT NOT NULL,             -- e.g. 'user.role.changed'
  resource_type   TEXT NOT NULL,             -- e.g. 'user', 'billing.subscription'
  resource_id     TEXT NOT NULL,
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  request_id      TEXT,                      -- ties back to http.request logs
  ip              INET,
  user_agent      TEXT,
  prev_hash       TEXT,                      -- hash of previous row — tamper-evidence
  row_hash        TEXT NOT NULL              -- sha256(canonical(this row) || prev_hash)
);

-- append-only: no UPDATE, no DELETE
CREATE INDEX audit_log_tenant_time_idx ON audit_log (tenant_id, occurred_at DESC);
CREATE INDEX audit_log_actor_time_idx  ON audit_log (actor_id, occurred_at DESC);
CREATE INDEX audit_log_resource_idx    ON audit_log (resource_type, resource_id, occurred_at DESC);

-- enforce append-only at the database layer, not just in application code
REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC;
CREATE OR REPLACE FUNCTION audit_log_no_mutate() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'audit_log is append-only'; END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_no_mutate();
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_no_mutate();
```

The write path lives in one file — every privileged action calls it, no exceptions:

```ts
// src/audit.ts
import crypto from "node:crypto";
import type { Knex } from "knex";

export type AuditEvent = {
  actorType: "user" | "service" | "system";
  actorId: string;
  tenantId?: string;
  action: string;                            // 'user.role.changed', 'billing.subscription.canceled'
  resourceType: string;
  resourceId: string;
  metadata?: Record<string, unknown>;
  requestId?: string;
  ip?: string;
  userAgent?: string;
};

function canonicalize(obj: unknown): string {
  // JSON with sorted keys — SHA of {"a":1,"b":2} == SHA of {"b":2,"a":1}
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalize).join(",") + "]";
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalize((obj as any)[k])).join(",") + "}";
}

/**
 * Write one audit row inside a caller-supplied transaction. The caller MUST
 * be doing this alongside the state change it's auditing — see example below.
 */
export async function writeAudit(tx: Knex.Transaction, event: AuditEvent): Promise<void> {
  // Lock last row to serialize hash-chain writes. Row lock is cheap; contention
  // on the audit_log tail is what we want — audit writes are naturally serialized.
  const [prev] = await tx.raw(
    `SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1 FOR UPDATE`
  );
  const prevHash: string | null = prev?.row_hash ?? null;

  const row = {
    actor_type: event.actorType,
    actor_id: event.actorId,
    tenant_id: event.tenantId ?? null,
    action: event.action,
    resource_type: event.resourceType,
    resource_id: event.resourceId,
    metadata: event.metadata ?? {},
    request_id: event.requestId ?? null,
    ip: event.ip ?? null,
    user_agent: event.userAgent ?? null,
    prev_hash: prevHash,
  };

  const rowHash = crypto
    .createHash("sha256")
    .update(canonicalize(row) + (prevHash ?? ""))
    .digest("hex");

  await tx("audit_log").insert({ ...row, row_hash: rowHash });
}
```

Callers invoke it inside the same transaction as the state change — same pattern as [webhook idempotency](./webhooks.md#idempotency):

```ts
// src/services/user-service.ts
export async function changeUserRole(
  ctx: RequestContext,
  targetUserId: string,
  newRole: Role
): Promise<void> {
  await db.transaction(async (tx) => {
    const [old] = await tx("users").where({ id: targetUserId }).select("role");
    if (!old) throw new NotFoundError();
    if (old.role === newRole) return;                                  // no-op

    await tx("users").where({ id: targetUserId }).update({ role: newRole });

    await writeAudit(tx, {
      actorType: "user",
      actorId: ctx.userId,
      tenantId: ctx.tenantId,
      action: "user.role.changed",
      resourceType: "user",
      resourceId: targetUserId,
      metadata: { from: old.role, to: newRole },
      requestId: ctx.requestId,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
    });
  });
}
```

If the role change succeeds but the audit write fails, the transaction rolls back — you never have a state change without its audit row. That's the invariant compliance auditors actually care about.

> **Don't audit from middleware.** A common shortcut is a global middleware that writes an audit row for every `POST/PUT/PATCH/DELETE`. It sounds convenient; it produces useless audit data. The middleware sees the HTTP layer, not the domain — you get "user X POSTed to /api/users/123" instead of "user X changed user 123's role from `member` to `admin`." Middleware also runs *before* you know whether the state change succeeded. Audit at the service layer, next to the change.

### Tamper-evidence via hash chain

Each row's `row_hash` is `SHA-256(canonical(row_without_hash) || prev_hash)`. That means: if anyone alters row N, every row from N onward has a `prev_hash` that no longer matches. Verification is a linear scan:

```ts
// src/scripts/verify-audit-chain.ts
export async function verifyAuditChain(db: Knex): Promise<{ ok: boolean; firstBrokenId?: number }> {
  const rows = await db("audit_log")
    .orderBy("id", "asc")
    .select("id", "actor_type", "actor_id", "tenant_id", "action", "resource_type",
            "resource_id", "metadata", "request_id", "ip", "user_agent", "prev_hash", "row_hash");

  let prevHash: string | null = null;
  for (const r of rows) {
    const { id, row_hash, ...body } = r;
    const expected = crypto.createHash("sha256")
      .update(canonicalize(body) + (prevHash ?? ""))
      .digest("hex");
    if (expected !== row_hash) return { ok: false, firstBrokenId: id };
    prevHash = row_hash;
  }
  return { ok: true };
}
```

Run it nightly as a scheduled job; alert loudly on `ok: false`. This isn't cryptographic proof against a determined attacker with database write access — they can rewrite the whole chain. It **is** proof against silent tampering by a DBA, a rogue migration, or a broken backup restore that dropped rows mid-file.

## Alerting signals

Logs you don't alert on are landfill. These four signals catch the majority of real attacks against a SaaS API at a signal-to-noise ratio a small team can actually manage:

### 1. `auth.refresh_reuse_detected`

Refresh-token reuse is a token-theft indicator — see [Authentication chapter](./authentication.md#refresh-rotation). Any occurrence, page immediately:

```
alert: auth.refresh_reuse_detected
  when: count_over_time({event="auth.refresh_reuse_detected"}[5m]) > 0
  severity: page
```

There is no legitimate reason a client presents a rotated refresh token. Every hit is a stolen credential or a broken client — both worth waking someone up for.

### 2. Zod parse-failure spikes

Every validation failure is a client bug or an attacker probing. Normal traffic has a low baseline (a few percent). A spike is either a bad deploy or a fuzzer:

```ts
// wire the alerting counter into your validation middleware
app.use((req, res, next) => {
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    log.info({
      event: "validation.failed",
      path: req.route?.path,
      errors: parsed.error.errors.slice(0, 5),   // cap — attackers can send 10k errors
    });
    return res.status(400).json({ error: "invalid_input" });
  }
  next();
});
```

```
alert: validation_failure_spike
  when: rate({event="validation.failed"}[5m]) > 5 * rate({event="validation.failed"}[1h] offset 1h)
  severity: warn
```

Anomaly against baseline, not a fixed threshold — a fixed threshold is either always firing or never firing.

### 3. 401/403 bursts per source IP

The single cheapest recon detector. A source hitting many 401s in a short window is credential-stuffing; many 403s is IDOR-probing:

```
alert: auth_recon_burst
  when: count_over_time({event="http.request", status=~"401|403"}[5m]) by (ip) > 50
  severity: warn
```

Tune the threshold to your traffic. If a mobile app's expired-token retry loop trips this, that's a client bug — fix it, don't raise the threshold to hide it.

### 4. Webhook signature failures

Rare, and rare bursts mean either a rotated secret you forgot to deploy or someone trying forgeries. See [Webhooks — Operational notes](./webhooks.md#operational-notes):

```
alert: webhook_signature_failure_spike
  when: rate({event="webhook.stripe.signature_invalid"}[5m]) > 3 * rate({event="webhook.stripe.signature_invalid"}[24h] offset 24h)
  severity: warn
```

The threat is either an operational drift (rotate mismatched between Stripe dashboard and env var) or recon. Both matter, both are cheap to detect, and neither has a false-positive rate that matters at this volume.

## Tests

Redaction is the one part of a logger you can meaningfully unit-test — the alerting rules belong in your monitoring config's own test suite. These are the tests that would have caught the redaction bugs I've shipped:

```ts
// __tests__/logger.test.ts
import { describe, it, expect, vi } from "vitest";
import { log } from "../src/log";

describe("logger redaction", () => {
  it("redacts Authorization header from logged request", () => {
    const captured: string[] = [];
    const spy = vi.spyOn(process.stdout, "write").mockImplementation((chunk) => {
      captured.push(chunk.toString());
      return true;
    });

    log.info({
      event: "http.request",
      req: { headers: { authorization: "Bearer secret-jwt-value" } },
    });

    spy.mockRestore();
    const line = captured.join("");
    expect(line).not.toContain("secret-jwt-value");
    expect(line).toContain("[REDACTED]");
  });

  it("redacts password field regardless of nesting", () => {
    const captured: string[] = [];
    const spy = vi.spyOn(process.stdout, "write").mockImplementation((chunk) => {
      captured.push(chunk.toString());
      return true;
    });

    log.info({ user: { profile: { password: "hunter2" } } });

    spy.mockRestore();
    expect(captured.join("")).not.toContain("hunter2");
  });

  it("does not log the raw request body — only allow-listed fields", () => {
    const captured: string[] = [];
    const spy = vi.spyOn(process.stdout, "write").mockImplementation((chunk) => {
      captured.push(chunk.toString());
      return true;
    });

    // safeBody in the request-logger middleware should strip 'email'
    log.info({ event: "http.request", body: { locale: "en", email: "leak@example.com" } });

    spy.mockRestore();
    const line = captured.join("");
    expect(line).toContain("en");
    // NOTE: this test guards the *contract* of what request-logger passes to log —
    // put it against safeBody() directly for the middleware itself.
  });
});

describe("audit chain", () => {
  it("verifyAuditChain returns ok=true on an untampered chain", async () => {
    // arrange: seed 5 audit rows via writeAudit inside a tx, then verify.
    // (Full example in repo — see src/scripts/verify-audit-chain.test.ts.)
  });

  it("verifyAuditChain returns ok=false when a row's metadata is mutated post-write", async () => {
    // arrange: write 5 rows; use a raw UPDATE (bypassing the trigger) in a
    // dedicated test-only migration to mutate row 3's metadata; verify.
    // expect firstBrokenId === 3.
  });
});
```

The last two tests document the invariant the whole hash chain exists to protect. If they don't compile, the chain isn't actually verifying anything.

## Operational notes

- **Ship logs off the box.** File-based logging on the app server is a single-disk-failure-away-from-forensic-blindness pattern. Ship JSON to a queryable store (Loki, CloudWatch, Datadog, Elastic — the specific vendor matters less than the fact that logs outlive the pod).
- **Retention policy is a security control, not a housekeeping task.** SOC 2 CC7.2 wants at least a year of audit trail. GDPR wants no PII older than necessary. Reconcile the two: audit log gets 1+ year, operational log gets 30–90 days, and PII in operational logs is redacted so retention is moot.
- **Test log delivery in staging.** Alerts that never fire because the SIEM isn't receiving logs are the worst kind of "quiet." A synthetic `alert.self_test` event every 5 minutes with a synthetic alert on its absence catches broken pipes before the real event does.
- **Log the outcome of every failed authorization.** `authz.denied` with `{actor, resource, requiredRole}` is the log line you'll wish you had the first time a customer says "we found records we shouldn't have had access to." It's a nothing-happened event, and it's still worth the disk.
- **Don't log request bodies for `POST /auth/login`, `POST /auth/refresh`, `POST /billing/*`.** The redaction paths above cover the obvious fields, but a defense-in-depth rule is to skip body logging entirely on the routes where "one field slipped through the allow-list" is expensive.

## See also

- [OWASP A09 — Security Logging & Monitoring Failures](https://github.com/batuhan-satilmis/owasp-saas-hardening-guide/blob/main/chapters/09-logging-monitoring.md)
- [NIST SP 800-92 — Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [SOC 2 CC7.2 — System Monitoring](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2)
- [pino redaction docs](https://getpino.io/#/docs/redaction)
- [Webhooks — Operational notes](./webhooks.md#operational-notes) — the four-secret alerting pattern that hooks into these signals.
- [Authentication — Refresh rotation](./authentication.md#refresh-rotation) — where `auth.refresh_reuse_detected` comes from.
