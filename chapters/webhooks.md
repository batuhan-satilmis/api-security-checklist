# Webhooks (Inbound)

> Code-first reference for the Webhooks checklist items. See also: [OWASP SaaS Hardening Guide — A08 Software & Data Integrity](https://github.com/batuhan-satilmis/owasp-saas-hardening-guide/blob/main/chapters/08-software-data-integrity.md).

A webhook endpoint is an unauthenticated public POST that mutates state. That single sentence is most of the threat model. Three properties have to hold before any handler-specific logic runs:

1. **The bytes are from the sender we think they're from** — signature verification.
2. **Processing this event twice is the same as processing it once** — idempotency.
3. **A captured-then-replayed event can't be honoured indefinitely** — temporal tolerance.

Get any of those wrong and the consequences range from "duplicate fulfilment" to "stolen-event grants unbounded credits." This chapter is the production pattern, lifted from a Stripe + Express + Postgres stack and generalised.

## Signature

The signature check has three sub-rules that fail independently and silently if you skip any of them.

### Verify on the raw bytes, not the parsed JSON

❌ Express's default `express.json()` middleware mutates the body. By the time your handler runs, `req.body` is an object — the bytes the signature was computed over are gone. Re-serialising with `JSON.stringify(req.body)` does **not** reproduce them: key order, whitespace, and number formatting differ.

```ts
// vulnerable
app.use(express.json());
app.post("/webhooks/stripe", (req, res) => {
  // ⛔ signature check against a re-serialised string will pass-then-fail at random
  const ok = verify(JSON.stringify(req.body), req.headers["stripe-signature"]);
});
```

✅ Mount a raw-body parser **only** on the webhook route, before the global JSON parser:

```ts
// secure
import express from "express";
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, { apiVersion: "2024-06-20" });
const app = express();

// raw body for the webhook route ONLY — must come before express.json()
app.post(
  "/webhooks/stripe",
  express.raw({ type: "application/json", limit: "1mb" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"] as string | undefined;
    if (!sig) return res.status(400).end();

    let event: Stripe.Event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,                                  // Buffer, untouched bytes
        sig,
        process.env.STRIPE_WEBHOOK_SECRET!
      );
    } catch (err) {
      log.warn({ err }, "stripe.webhook.signature_invalid");
      return res.status(400).end();
    }
    // … see Idempotency below
  }
);

// everything else uses parsed JSON
app.use(express.json());
```

### Use the SDK's `constructEvent`, not a hand-rolled HMAC

The Stripe-Signature header is `t=<timestamp>,v1=<sig>` and the signed payload is `${t}.${rawBody}` — small detail, huge variance in failure mode. `constructEvent` enforces both the HMAC and the timestamp tolerance (default 300 s) in one call. Re-implementing it by hand to "be explicit" is the path that produces silent acceptance of replays. If you must roll your own (different provider), use a constant-time compare:

```ts
import crypto from "node:crypto";

function verifyHmac(rawBody: Buffer, signatureHex: string, secret: string): boolean {
  const expected = crypto.createHmac("sha256", secret).update(rawBody).digest();
  const provided = Buffer.from(signatureHex, "hex");
  // length check first — timingSafeEqual throws on mismatch
  if (provided.length !== expected.length) return false;
  return crypto.timingSafeEqual(expected, provided);
}
```

> **Never use `===` on HMAC outputs.** String comparison short-circuits on the first mismatched character; that's a timing oracle a remote attacker can exploit to recover the signature byte-by-byte.

### Enforce a timestamp tolerance

`constructEvent`'s third argument is `tolerance` — seconds between the signed timestamp and `Date.now()`. The default is 300 s. Passing `0` (no tolerance) breaks under clock skew; passing a large value (`60 * 60 * 24`) means any exfiltrated event can be replayed for a day. Stay near the default unless you have a documented reason. Add a regression test that a 6-minute-old payload is rejected (see [Tests](#tests)).

## Idempotency

The provider retries on any non-2xx — and even on a 2xx if the connection dropped mid-response. The handler will see the same event ID more than once. The handler must be safe to call N times and produce exactly the side-effects of one call.

The cheap, correct pattern is a database `INSERT … ON CONFLICT DO NOTHING` keyed on the provider's event ID, inside the same transaction as the business-level state change:

```sql
CREATE TABLE webhook_events (
  id              TEXT PRIMARY KEY,           -- provider event ID, e.g. "evt_1Q…"
  provider        TEXT NOT NULL,              -- "stripe", "github", "slack"
  type            TEXT NOT NULL,
  received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  processed_at    TIMESTAMPTZ
);
CREATE INDEX webhook_events_received_at_idx ON webhook_events (received_at);
```

```ts
// secure
async function handleStripeEvent(event: Stripe.Event) {
  await db.transaction(async (tx) => {
    const claim = await tx.raw(
      `INSERT INTO webhook_events (id, provider, type)
       VALUES ($1, 'stripe', $2)
       ON CONFLICT (id) DO NOTHING
       RETURNING id`,
      [event.id, event.type]
    );

    // No row returned → another worker already claimed this event. Bail.
    if (claim.rowCount === 0) {
      log.info({ eventId: event.id }, "webhook.duplicate_ignored");
      return;
    }

    switch (event.type) {
      case "checkout.session.completed":
        await fulfilCheckout(tx, event.data.object as Stripe.Checkout.Session);
        break;
      case "customer.subscription.deleted":
        await cancelSubscription(tx, event.data.object as Stripe.Subscription);
        break;
      // … other handlers
    }

    await tx.raw(
      `UPDATE webhook_events SET processed_at = now() WHERE id = $1`,
      [event.id]
    );
  });
}
```

Three properties hold:

1. **The `INSERT` is the claim.** If two workers receive the same retry, exactly one wins the `INSERT`; the other sees `rowCount === 0` and exits without touching anything. The database, not the application, serialises duplicates.
2. **The state change runs in the same transaction.** If the business-level write fails, the row is rolled back too — the next retry sees no claim and re-processes the event. Without this, a crash between the `INSERT` and the state change wedges the event into "claimed but never applied."
3. **`processed_at` is observable.** Backfills, drift detection, and operational dashboards have something to query without parsing logs.

> **Don't pre-acknowledge with a 200 before processing.** Returning 200 then enqueueing async work is the pattern that produces "we acknowledged it and then crashed before doing the thing." If processing is slow, do the synchronous part (claim + enqueue a job with the same event ID) inside the transaction; the worker that picks the job up later uses the same idempotency table.

## Transaction-bounded state changes

A common foot-gun is processing-then-claiming:

```ts
// vulnerable — race window between fulfil() and the INSERT
async function badHandler(event: Stripe.Event) {
  await fulfilCheckout(event.data.object);             // ⛔ runs on every retry
  await db.webhookEvents.insert({ id: event.id });
}
```

Two retries that arrive 50 ms apart both call `fulfilCheckout` before either reaches the `INSERT`. The user gets shipped two of whatever you sell. Always claim first, do work second, all in one transaction. See also: [threat-modeling-framework — T-015 coupon redemption race](https://github.com/batuhan-satilmis/threat-modeling-framework/blob/main/examples/saas-payment-flow.md#t-015-coupon-redemption-race) for the same pattern outside webhooks.

## Edge rate-limit on the endpoint

Signature verification is a SHA-256 HMAC — fast, but not free, and an attacker who learns the URL can POST junk at thousands of req/s. The HMAC will reject every one of them, but you're still spending CPU and log volume to do it. Cap unauthenticated POSTs at the edge before they reach your origin:

```ts
import rateLimit from "express-rate-limit";

const webhookEdgeLimit = rateLimit({
  windowMs: 60_000,
  max: 600,                                 // generous — providers retry in bursts
  standardHeaders: true,
  keyGenerator: (req) => req.ip!,
  skipSuccessfulRequests: false,
});

app.post("/webhooks/stripe", webhookEdgeLimit, express.raw({ type: "application/json", limit: "1mb" }), …);
```

For provider-IP allow-listing, prefer the provider's published CIDR list when available; for Stripe, the [webhook IPs list](https://stripe.com/docs/ips#webhook-notifications) changes rarely and is a reasonable defence-in-depth filter at the CDN — but not a primary control, since the signature is.

## Tests

These are the four tests every webhook endpoint should ship with — they catch the four most common implementation drifts:

```ts
// __tests__/webhooks.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import request from "supertest";
import crypto from "node:crypto";
import { app } from "../src/app";
import { db } from "../src/db";

const SECRET = process.env.STRIPE_WEBHOOK_SECRET!;

function signStripePayload(payload: object, ts: number = Math.floor(Date.now() / 1000)): {
  body: string;
  header: string;
} {
  const body = JSON.stringify(payload);
  const signed = `${ts}.${body}`;
  const v1 = crypto.createHmac("sha256", SECRET).update(signed).digest("hex");
  return { body, header: `t=${ts},v1=${v1}` };
}

describe("POST /webhooks/stripe", () => {
  beforeEach(async () => {
    await db.raw("TRUNCATE webhook_events RESTART IDENTITY CASCADE");
  });

  it("rejects requests with no signature header (400)", async () => {
    const res = await request(app)
      .post("/webhooks/stripe")
      .set("Content-Type", "application/json")
      .send(JSON.stringify({ id: "evt_1", type: "ping" }));
    expect(res.status).toBe(400);
  });

  it("rejects requests with a forged signature (400)", async () => {
    const { body } = signStripePayload({ id: "evt_2", type: "ping" });
    const res = await request(app)
      .post("/webhooks/stripe")
      .set("Content-Type", "application/json")
      .set("stripe-signature", "t=0,v1=deadbeef")
      .send(body);
    expect(res.status).toBe(400);
  });

  it("rejects payloads older than the tolerance window", async () => {
    const sixMinAgo = Math.floor(Date.now() / 1000) - 6 * 60;
    const { body, header } = signStripePayload(
      { id: "evt_3", type: "checkout.session.completed", data: { object: {} } },
      sixMinAgo
    );
    const res = await request(app)
      .post("/webhooks/stripe")
      .set("Content-Type", "application/json")
      .set("stripe-signature", header)
      .send(body);
    expect(res.status).toBe(400);
  });

  it("processes a valid event exactly once across duplicate deliveries", async () => {
    const { body, header } = signStripePayload({
      id: "evt_4",
      type: "checkout.session.completed",
      data: { object: { id: "cs_test_4", amount_total: 1000, currency: "usd" } },
    });

    // Send the same signed payload three times — simulates provider retry.
    for (let i = 0; i < 3; i++) {
      const res = await request(app)
        .post("/webhooks/stripe")
        .set("Content-Type", "application/json")
        .set("stripe-signature", header)
        .send(body);
      expect(res.status).toBe(200);
    }

    const rows = await db.raw(
      `SELECT COUNT(*)::int AS n FROM webhook_events WHERE id = 'evt_4'`
    );
    expect(rows[0].n).toBe(1);                            // claim row is unique

    const fulfilments = await db.raw(
      `SELECT COUNT(*)::int AS n FROM fulfilments WHERE checkout_id = 'cs_test_4'`
    );
    expect(fulfilments[0].n).toBe(1);                     // exactly one side-effect
  });
});
```

The fourth test is the one most repos skip and pays for later — it's the difference between "we have idempotency" and "we have idempotency under realistic provider retry behaviour."

## Operational notes

- **Log the event ID on every path** (accepted, duplicate, rejected). Without it, "why did this customer get charged twice" is unanswerable from logs.
- **Alert on signature-rejection spikes.** Junk POSTs are noise; a 100× burst is a recon signal — see [Logging & alerting signals](./logging.md#alerting-signals) once that chapter lands.
- **Don't redrive from the provider's dashboard without checking the idempotency table first.** The whole point of the table is that a redrive is safe — verify, then redrive.
- **Two-secret rotation.** Stripe lets you have two active webhook secrets at once. When rotating, accept either for the overlap window, then drop the old one. Your `constructEvent` wrapper should try the new secret first, then the old, before returning 400.

## See also

- [OWASP A08 — Software & Data Integrity Failures](https://github.com/batuhan-satilmis/owasp-saas-hardening-guide/blob/main/chapters/08-software-data-integrity.md)
- [Stripe — Best practices for using webhooks](https://stripe.com/docs/webhooks/best-practices)
- [threat-modeling-framework — T-014 webhook timestamp tolerance](https://github.com/batuhan-satilmis/threat-modeling-framework/blob/main/examples/saas-payment-flow.md#t-014-webhook-timestamp-tolerance) — STRIDE entry for the temporal-replay class.
- [`stripe.webhooks.constructEvent` (Node SDK)](https://stripe.com/docs/api/webhooks/construct_event)
