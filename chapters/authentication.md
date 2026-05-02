# Authentication

> Code-first reference for the authentication checklist items. See also: [OWASP SaaS Hardening Guide — Chapter 7](https://github.com/batuhan-satilmis/owasp-saas-hardening-guide/blob/main/chapters/07-identification-authentication.md).

## HttpOnly cookies

❌ Storing JWTs in `localStorage` exposes them to any JavaScript on the page (including a single XSS):

```ts
// vulnerable
res.json({ token: jwt.sign({ uid }, SECRET, { expiresIn: "7d" }) });
// frontend stores in localStorage  ⛔ accessible to any script
```

✅ Use HttpOnly cookies. JS can't read them; XSS doesn't immediately become account takeover.

```ts
// secure
res.cookie("session", sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: "strict",
  maxAge: 7 * 24 * 3600 * 1000,
});
res.json({ user: publicUser });
```

## Lock the algorithm

❌ Default-permissive `jwt.verify` accepts whatever algorithm the token claims. Including `none`.

```ts
const claims = jwt.verify(token, SECRET);   // ⛔ alg whitelist not pinned
```

✅ Pin the algorithm.

```ts
const claims = jwt.verify(token, SECRET, { algorithms: ["HS256"] });
```

## Refresh rotation

✅ Refresh tokens **rotate on every refresh** and are stored hashed. Reuse of an invalidated token kills the entire token family.

```ts
// secure (sketch)
async function refresh(req, res) {
  const presented = req.cookies.refresh;
  const row = await db.refreshTokens.findByHash(sha256(presented));
  if (!row) return res.status(401).end();

  if (row.used) {
    // someone presented a token we already rotated.
    await db.refreshTokens.revokeFamily(row.familyId);
    auditLog("auth.refresh_reuse_detected", { userId: row.userId });
    return res.status(401).end();
  }

  await db.transaction(async (tx) => {
    await tx.refreshTokens.markUsed(row.id);
    const next = randomBase64(32);
    await tx.refreshTokens.insert({ userId: row.userId, familyId: row.familyId, hash: sha256(next) });
    res.cookie("refresh", next, refreshCookieOpts);
  });
}
```

## Rate limit

✅ Per-IP and per-user, with `Retry-After`:

```ts
import rateLimit from "express-rate-limit";
export const loginRateLimit = rateLimit({
  windowMs: 60_000,
  max: 5,
  standardHeaders: true,
  message: { error: "too_many_requests" },
});
```

> **Don't** lock the account on N failures — that's an attacker-controlled DoS on the user. Slow them, CAPTCHA them, alert. Don't lock them out.

## No enumeration

✅ Same response for "user exists" and "user doesn't" on `/password-reset/request`:

```ts
app.post("/password-reset/request", resetRateLimit, async (req, res) => {
  const { email } = z.object({ email: z.string().email() }).parse(req.body);
  const user = await db.users.findByEmail(email);
  if (user) {
    const token = randomBase64(32);
    await db.passwordResets.insert({ userId: user.id, hash: sha256(token), expiresAt: in15min() });
    await sendResetEmail(email, token);
  }
  // identical response either way
  return res.json({ ok: true, message: "If that email exists, a reset link was sent." });
});
```

Pair with constant-time-ish responses (small random sleep on the not-found path) to defeat timing oracles.

## Test that catches the bad version

```ts
test("refresh-token reuse kills entire family", async () => {
  const user = await seedUser();
  const { sessionCookie, refreshCookie } = await login(user);

  const r1 = await request().post("/api/refresh").set("Cookie", refreshCookie);
  expect(r1.status).toBe(200);
  const newRefresh = parseSetCookie(r1.headers["set-cookie"]).refresh;

  // replay original refresh
  const r2 = await request().post("/api/refresh").set("Cookie", refreshCookie);
  expect(r2.status).toBe(401);

  // even the legitimate "next" refresh is dead
  const r3 = await request().post("/api/refresh").set("Cookie", `refresh=${newRefresh}`);
  expect(r3.status).toBe(401);
});
```

## See also

- [OWASP A07: Identification & Authentication Failures](https://github.com/batuhan-satilmis/owasp-saas-hardening-guide/blob/main/chapters/07-identification-authentication.md) — deeper treatment.
- [OWASP Cheat Sheet: Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
