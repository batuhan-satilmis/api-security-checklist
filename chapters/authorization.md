# Authorization

> Code-first reference for the authorization checklist. See also: [OWASP SaaS Hardening Guide — Chapter 1](https://github.com/batuhan-satilmis/owasp-saas-hardening-guide/blob/main/chapters/01-broken-access-control.md).

## Explicit roles per endpoint

❌ Centralized "is this user allowed to do *anything*" middleware lets bugs land easily.

✅ Each route declares its required role(s) inline:

```ts
const requireRole = (allowed) => (req, res, next) => {
  if (!allowed.includes(req.session.role)) return res.status(403).end();
  next();
};

app.get("/api/customers/:id", requireAuth, requireRole(["tenant_admin", "tenant_owner", "member"]), getCustomer);
app.delete("/api/customers/:id", requireAuth, requireRole(["tenant_owner"]), deleteCustomer);
```

The role list is right next to the handler. Code review catches "wait, why is `member` allowed to delete?"

## Tenant from JWT

❌ Reading `tenant_id` from the request body or path:

```ts
// vulnerable
const customer = await db.customers.findFirst({
  where: { id: req.params.id, tenantId: req.body.tenantId }   // ⛔ client controls tenantId
});
```

✅ Always from the server-issued session/JWT:

```ts
// secure
const tenantId = req.session.tenantId;   // server-side, never client-supplied
const customer = await db.customers.findFirst({ where: { id: req.params.id, tenantId } });
```

## RLS — DB-layer enforcement

✅ Postgres Row-Level Security so even a forgotten `WHERE tenant_id = ...` doesn't leak data:

```sql
ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE customers FORCE  ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON customers
  USING (tenant_id = current_setting('jwt.claim.tenant_id')::uuid);
```

> Use `FORCE` so the table owner respects the policy too. Without `FORCE`, a connection that uses the table-owner role can bypass RLS — exactly the credential a connection pool might use under load.

## Test that catches the bad version

```ts
test("Tenant A cannot read Tenant B customers via guessed IDs", async () => {
  const A = await seedTenant("A", { customers: 3 });
  const B = await seedTenant("B", { customers: 3 });
  const userA = await loginAs(A.users[0]);

  for (const c of B.customers) {
    const r = await request().get(`/api/customers/${c.id}`).set("Cookie", userA.cookie);
    expect(r.status).toBe(404);   // 404 not 403, to avoid existence oracle
  }
});

test("viewer cannot delete", async () => {
  const t = await seedTenant("A", { roles: ["viewer"] });
  const v = await loginAs(t.users[0]);
  const r = await request().delete(`/api/customers/${t.customers[0].id}`).set("Cookie", v.cookie);
  expect(r.status).toBe(403);
});
```

Run on every CI build. If it passes when you remove a layer of enforcement, the test isn't testing what it claims.

## See also

- [OWASP A01: Broken Access Control](https://github.com/batuhan-satilmis/owasp-saas-hardening-guide/blob/main/chapters/01-broken-access-control.md)
- [Supabase RLS guide](https://supabase.com/docs/guides/auth/row-level-security)
