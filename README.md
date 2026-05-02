# API Security Checklist

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![OWASP API Top 10 (2023)](https://img.shields.io/badge/OWASP-API%20Top%2010%20(2023)-brightgreen.svg)](https://owasp.org/API-Security/editions/2023/en/0x00-introduction/)

> A practical, code-first checklist for hardening REST APIs — written from production hardening of multiple Node.js + Express SaaS APIs. Companion to my [OWASP SaaS Hardening Guide](https://github.com/batuhan-satilmis/owasp-saas-hardening-guide).

This is **not** a buzzword list. Every item is paired with concrete code, a test that would have caught the bug, and a one-line explanation of why it matters.

---

## How to use this

1. Skim the checklist to spot gaps in your API.
2. For each unchecked item, open the linked chapter for code + test.
3. Tick boxes as you implement. Re-run the tests on every release.

---

## Authentication & Session

- [ ] **JWTs are stored in HttpOnly cookies, not localStorage.** [Why](./chapters/authentication.md#httponly-cookies) · [Code](./chapters/authentication.md#httponly-cookies)
- [ ] **JWT signing algorithm is locked.** Reject `alg: none`. [Code](./chapters/authentication.md#lock-the-algorithm)
- [ ] **Refresh tokens rotate on every refresh, with reuse detection.** [Code](./chapters/authentication.md#refresh-rotation)
- [ ] **Login endpoint is rate-limited per-IP and per-user.** [Code](./chapters/authentication.md#rate-limit)
- [ ] **Password reset returns the same response regardless of email existence.** [Code](./chapters/authentication.md#no-enumeration)
- [ ] **MFA is supported and required for sensitive roles.**
- [ ] **Sessions can be revoked server-side on logout / password change.**
- [ ] **No token material in URL parameters, ever.** They end up in logs.

## Authorization

- [ ] **Every endpoint declares its required role explicitly.** Default: deny. [Code](./chapters/authorization.md#explicit-roles)
- [ ] **Tenant ID comes from the JWT, never from request body / path.** [Code](./chapters/authorization.md#tenant-from-jwt)
- [ ] **Database-layer enforcement** (RLS / equivalent) — bug at API doesn't leak data. [Code](./chapters/authorization.md#rls)
- [ ] **403 returns are uniform** — don't leak resource existence vs. permission.
- [ ] **Object-level access checks** — IDOR test in CI: as User A, attempt every User B object.

## Input Validation

- [ ] **Every request body and query is validated against a schema** (Zod, Joi, ajv). [Code](./chapters/input-validation.md#zod-schemas)
- [ ] **Schemas reject unknown fields by default.** Don't trust `additionalProperties: true`.
- [ ] **Numeric inputs have min/max bounds.** Stop the `?limit=99999999` query.
- [ ] **String inputs have max-length caps.** Defeats memory-amplification.
- [ ] **File-upload size and type checked server-side**, not by the client.

## Output Encoding

- [ ] **JSON serialization is the only output path** — no template-string assembly of responses.
- [ ] **Error responses sanitized in production.** Stack traces logged, not returned. [Code](./chapters/output.md#errors)
- [ ] **No internal IDs / pointers / secrets in error messages.**
- [ ] **Sensitive fields explicitly omitted** from API responses (use `pick()` patterns, not `omit()`).

## Rate Limiting & Abuse

- [ ] **Per-IP rate limit on every endpoint**, with `Retry-After` header. [Code](./chapters/rate-limiting.md)
- [ ] **Per-user (after auth) rate limit on expensive endpoints** (search, export, AI calls).
- [ ] **Stricter limits on auth, billing, password-reset endpoints.**
- [ ] **Alerting on 401/403 spikes** — recon signal.

## Secrets & Configuration

- [ ] **No secrets in source.** `gitleaks` / `trufflehog` runs in CI.
- [ ] **App refuses to boot if required env vars are missing or weak.** [Code](./chapters/config.md#fail-fast)
- [ ] **Secrets manager (Vault / KMS / Doppler / Supabase Vault)** in production.
- [ ] **Secrets rotated on a schedule + on suspicion.**
- [ ] **Different secrets per environment.** Production secret never seen by a developer locally.

## HTTP Headers

- [ ] **HSTS preload-eligible** (`max-age=31536000; includeSubDomains; preload`).
- [ ] **Strict CSP, no `unsafe-inline` / `unsafe-eval`.**
- [ ] **X-Content-Type-Options: nosniff.**
- [ ] **X-Frame-Options: DENY** (or CSP `frame-ancestors 'none'`).
- [ ] **Referrer-Policy: strict-origin-when-cross-origin.**
- [ ] **Permissions-Policy: minimal allow-list.**

## TLS & Network

- [ ] **TLS 1.2+ only. Prefer 1.3.**
- [ ] **HTTPS enforced everywhere, including dev environments.**
- [ ] **Modern cipher suites only** (no RC4, no 3DES).
- [ ] **Edge proxy in front of API origin.**
- [ ] **mTLS between internal services where applicable.**

## Logging & Monitoring

- [ ] **Every privileged action writes to an append-only audit log.** [Code](./chapters/logging.md#audit-log)
- [ ] **No PII / tokens / passwords in logs.** Redact at the boundary. [Code](./chapters/logging.md#redaction)
- [ ] **Structured logs (JSON), shipped to a queryable store.**
- [ ] **Alert on `auth.refresh_reuse_detected` events.**
- [ ] **Alert on Zod parse failure spikes** — cheap injection-attempt detector.
- [ ] **Webhook signature failures alerted.**

## Webhooks (Inbound)

- [ ] **Signature verified on every event** before any state change. [Code](./chapters/webhooks.md#signature)
- [ ] **Idempotent processing.** Replay → no-op. [Code](./chapters/webhooks.md#idempotency)
- [ ] **Webhook handler runs in a transaction with the resulting state change.**
- [ ] **Edge rate-limit on webhook endpoints** so unsigned floods are rejected fast.

## SSRF Defense (when accepting URLs)

- [ ] **Don't accept user-supplied URLs unless absolutely required.**
- [ ] **DNS resolved server-side, IP validated against public-only allow-list.** [Code](./chapters/ssrf.md)
- [ ] **HTTPS-only.** No `gopher:`, `file:`, `dict:`.
- [ ] **Redirects disabled** on outbound fetch.
- [ ] **AWS IMDSv2 enforced** if running on EC2.

## Vulnerability Management

- [ ] **Dependabot / Renovate enabled.**
- [ ] **`npm audit --audit-level=high` (or equivalent) gates CI.**
- [ ] **SBOM generated on every release.**
- [ ] **Subresource Integrity** for any CDN-loaded scripts.

## Documentation

- [ ] **OpenAPI spec is the source of truth** for the API contract.
- [ ] **Auth requirements documented per endpoint.**
- [ ] **Rate limits documented.**
- [ ] **`SECURITY.md` exists with a vulnerability disclosure policy.**

---

## Chapters (deep-dive code)

| Topic | Chapter |
|---|---|
| Authentication | [chapters/authentication.md](./chapters/authentication.md) |
| Authorization | [chapters/authorization.md](./chapters/authorization.md) |
| Input validation | [chapters/input-validation.md](./chapters/input-validation.md) |
| Output & errors | [chapters/output.md](./chapters/output.md) |
| Rate limiting | [chapters/rate-limiting.md](./chapters/rate-limiting.md) |
| Configuration | [chapters/config.md](./chapters/config.md) |
| Logging | [chapters/logging.md](./chapters/logging.md) |
| Webhooks | [chapters/webhooks.md](./chapters/webhooks.md) |
| SSRF | [chapters/ssrf.md](./chapters/ssrf.md) |

> **Status**: chapters are seeded with summary content and links into the [OWASP SaaS Hardening Guide](https://github.com/batuhan-satilmis/owasp-saas-hardening-guide). They expand over time (see [ROADMAP.md](./ROADMAP.md)).

## Companion repos

- 📚 [owasp-saas-hardening-guide](https://github.com/batuhan-satilmis/owasp-saas-hardening-guide) — OWASP Top 10 with code.
- 🎯 [threat-modeling-framework](https://github.com/batuhan-satilmis/threat-modeling-framework) — STRIDE templates.
- 🔍 [security-audit-toolkit](https://github.com/batuhan-satilmis/security-audit-toolkit) — Cloud config auditing.

## License

MIT
