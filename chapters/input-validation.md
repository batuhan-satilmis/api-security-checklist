# Input Validation

> Code-first reference for the Input Validation checklist items. See also: [OWASP SaaS Hardening Guide — A03 Injection](https://github.com/batuhan-satilmis/owasp-saas-hardening-guide/blob/main/chapters/03-injection.md).

The rule the whole chapter rests on: **every byte that enters your process from the network is hostile until a schema has touched it.** Validate at the edge, parse into a typed object, and pass that typed object — not the raw `req.body` — into the rest of the handler. If a value never gets validated, assume an attacker put it there.

## Zod schemas

❌ Hand-rolled validation drifts from the type and misses fields:

```ts
// vulnerable
app.post("/api/orders", async (req, res) => {
  const { sku, qty, notes } = req.body;          // ⛔ untyped, unbounded
  if (!sku) return res.status(400).end();
  await db.orders.insert({ sku, qty, notes });   // qty might be "9e99", notes might be 4MB
});
```

✅ Parse-don't-validate: a Zod schema returns a typed object, rejects unknown fields by default with `.strict()`, and gives you bounded primitives:

```ts
// secure
import { z } from "zod";

const OrderInput = z
  .object({
    sku:   z.string().regex(/^[A-Z0-9-]{3,32}$/),
    qty:   z.number().int().min(1).max(1000),
    notes: z.string().max(280).optional(),
  })
  .strict();                                     // unknown keys → ZodError

app.post("/api/orders", async (req, res) => {
  const parsed = OrderInput.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid_input", issues: parsed.error.issues });
  }
  await db.orders.insert(parsed.data);           // typed, bounded, no extras
});
```

Three things matter here:

1. **`.strict()` rejects unknown fields.** Without it, an attacker can ship `{ ..., role: "admin" }` and your downstream code may pass the extra key through to an ORM that happily writes it.
2. **Bounded numerics.** `z.number().int().min(1).max(1000)` makes `?qty=99999999` a 400, not a database-killing query.
3. **Bounded strings.** Caps on string length stop memory amplification attacks (`{ "notes": "A".repeat(50_000_000) }`).

> **One schema, two callers.** Export the inferred type (`type OrderInput = z.infer<typeof OrderInput>`) and use it in your handler signature. Your TypeScript and your runtime now agree about what's valid.

## ORDER BY traps

The injection class everyone forgets. Parameterized queries protect *values*, not *identifiers*. `ORDER BY` and `LIMIT` are usually built by string concatenation because the driver can't bind a column name.

❌ Both of these are SQL injection waiting for a curious user to send `sort=name; DROP TABLE users;--`:

```ts
// vulnerable
const { sort, dir } = req.query;
const rows = await db.raw(
  `SELECT id, name FROM users ORDER BY ${sort} ${dir} LIMIT 100`
);
```

```ts
// also vulnerable — parameterizing values does NOT save you here
const rows = await db.raw(
  `SELECT id, name FROM users ORDER BY ${req.query.sort} LIMIT ?`,
  [100]
);
```

✅ Allow-list the column and direction. The schema is the security boundary:

```ts
// secure
const ListUsersQuery = z.object({
  sort: z.enum(["id", "name", "createdAt"]).default("createdAt"),
  dir:  z.enum(["asc", "desc"]).default("desc"),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});

app.get("/api/users", async (req, res) => {
  const q = ListUsersQuery.parse(req.query);
  // q.sort and q.dir are now provably one of a fixed set — safe to interpolate.
  const rows = await db.raw(
    `SELECT id, name FROM users ORDER BY ${q.sort} ${q.dir} LIMIT ?`,
    [q.limit]
  );
  res.json(rows);
});
```

> **Why an enum, not a regex?** A regex like `/^[a-z]+$/` keeps the door open for `ORDER BY password`, exfiltrating hashes via timing. The set of sortable columns is *small and known* — write it down.

## File upload

Client-side checks are advisory; server-side is the security boundary. Reject by size first (cheap), then content-sniff the bytes (don't trust the extension or the `Content-Type` header).

❌ Trusting the client's `originalname` or `mimetype`:

```ts
// vulnerable
const upload = multer({ dest: "/tmp" });
app.post("/api/avatar", upload.single("file"), async (req, res) => {
  // attacker uploads `payload.php` and sets mimetype: "image/png"
  await s3.putObject({ Key: req.file.originalname, Body: req.file.buffer });
  res.json({ ok: true });
});
```

That accepts arbitrary filenames (path traversal via `../../`), unbounded sizes, and never looks at the actual bytes.

✅ Cap the size at the parser layer, sniff the magic bytes on the buffer, and never reuse the client-supplied filename:

```ts
// secure
import multer from "multer";
import { fileTypeFromBuffer } from "file-type";
import { randomUUID } from "node:crypto";

const upload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: 2 * 1024 * 1024, files: 1 }, // 2 MiB hard cap
});

const ALLOWED = new Set(["image/png", "image/jpeg", "image/webp"]);

app.post("/api/avatar", upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "file_required" });

  // Sniff the actual bytes; the client's mimetype is a suggestion, not a fact.
  const sniffed = await fileTypeFromBuffer(req.file.buffer);
  if (!sniffed || !ALLOWED.has(sniffed.mime)) {
    return res.status(415).json({ error: "unsupported_media_type" });
  }

  // Generate the stored name server-side. Never trust originalname.
  const key = `avatars/${req.user.id}/${randomUUID()}.${sniffed.ext}`;
  await s3.putObject({
    Bucket: AVATAR_BUCKET,
    Key: key,
    Body: req.file.buffer,
    ContentType: sniffed.mime,
    // S3 will still serve whatever Content-Type you set — keep it the sniffed one,
    // and pair with a CSP that forbids executing untrusted origins.
  });

  await db.users.update(req.user.id, { avatarKey: key });
  res.json({ ok: true });
});
```

> **Two layers, not one.** `multer.limits.fileSize` rejects the upload at the parser before allocating the full buffer; the sniff check rejects polyglot files (a valid PNG header concatenated with a PHP payload). Either alone is bypassable.

## Tests that catch the bad versions

```ts
// __tests__/input-validation.test.ts
import { describe, it, expect } from "vitest";
import request from "supertest";
import { app } from "../src/app";

describe("input validation", () => {
  it("rejects unknown fields on the order schema", async () => {
    const res = await request(app)
      .post("/api/orders")
      .send({ sku: "ABC-123", qty: 1, role: "admin" });          // extra key
    expect(res.status).toBe(400);
    expect(res.body.issues.some((i: any) => i.code === "unrecognized_keys")).toBe(true);
  });

  it("rejects qty above the cap", async () => {
    const res = await request(app)
      .post("/api/orders")
      .send({ sku: "ABC-123", qty: 99_999_999 });
    expect(res.status).toBe(400);
  });

  it("rejects sort values outside the allow-list", async () => {
    const res = await request(app).get("/api/users?sort=password");
    expect(res.status).toBe(400);
  });

  it("rejects a file above the size cap", async () => {
    const big = Buffer.alloc(3 * 1024 * 1024, 0); // 3 MiB
    const res = await request(app)
      .post("/api/avatar")
      .attach("file", big, { filename: "big.png", contentType: "image/png" });
    expect([413, 400]).toContain(res.status);
  });

  it("rejects an upload whose declared mimetype lies about the bytes", async () => {
    // Plain text body with a lying mimetype — sniff should reject.
    const fake = Buffer.from("<?php system($_GET['c']); ?>");
    const res = await request(app)
      .post("/api/avatar")
      .attach("file", fake, { filename: "x.png", contentType: "image/png" });
    expect(res.status).toBe(415);
  });
});
```

## Operational notes

- **Centralize the error shape.** A single `zodErrorToResponse(error)` helper keeps `400` responses consistent and forces every handler through the same redaction step.
- **Validate query strings too.** `z.coerce.number()` is the right tool — query strings arrive as strings.
- **Don't return the Zod issues to anonymous endpoints in production.** They're great for authenticated debugging; on public endpoints, return `{ error: "invalid_input" }` and log the issues server-side.
- **Re-use schemas for OpenAPI generation.** `zod-to-openapi` keeps your spec and your runtime in sync — the docs you publish are the contract you actually enforce.

## See also

- [OWASP A03 — Injection](https://github.com/batuhan-satilmis/owasp-saas-hardening-guide/blob/main/chapters/03-injection.md) — deeper treatment of injection classes, including ORDER BY.
- [OWASP API Security Top 10 (2023) — API8: Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [OWASP Cheat Sheet — Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [`file-type` on npm](https://www.npmjs.com/package/file-type) — content-sniffing library used above.
