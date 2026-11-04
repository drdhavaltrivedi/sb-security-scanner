You are doing a security review of the Service Buddy backend. Stack: NestJS 10 on
Express, MongoDB (Mongoose), AWS S3, with Stripe, Rainforest (BuddyPay) and
QuickBooks Online integrations. A scanner has already run; its output is in
`./sb-security-report/` (`findings.tsv`, `routes.csv`, `REPORT.md`). Work through
every item below, reading the actual source for each, and produce a results
report. Do not change any code in this pass — only investigate and report.

## 1. Triage the scanner findings
Read `sb-security-report/findings.tsv` and `routes.csv`. For EVERY High and
Medium finding, open the file and line and decide: CONFIRMED (real), FALSE
POSITIVE (with one line why), or NEEDS-FIX-LATER. Keep the finding id.

## 2. Route-by-route access control (do this for every row in routes.csv)
For each route, confirm in code:
- it has an authentication guard (class or method `@UseGuards`, or a global `APP_GUARD`);
- sensitive routes (admin, settings, employees, payouts, refunds, exports,
  integrations, company, commissions) also have a role/permission check;
- every DB query it triggers is filtered by the caller's `companyId`/tenant, not
  only by an id taken from the URL or body. For each route that takes an `:id`,
  trace the service call and state whether another company's record could be
  read or modified (IDOR). List every route where this is NOT guaranteed.

## 3. MongoDB / data access
- Are request bodies and query objects typed DTOs validated with a global
  `ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })`?
- Is Mongo operator injection blocked (mongoose `sanitizeFilter`, or
  `express-mongo-sanitize`), so a body like `{"email": {"$ne": null}}` cannot
  bypass a lookup?
- Is user input ever used in `$regex`, `$where`, `mapReduce`, or passed to
  `.sort()/.select()/.populate()` without an allow-list?
- Can any update endpoint set privileged fields (`role`, `companyId`, `isAdmin`,
  `balance`, `stripeAccountId`, `realmId`) from the request (mass assignment)?

## 4. Authentication & tokens
- How is the login JWT signed, how long does it live, and can it be revoked on
  logout / password change / deactivation (tokenVersion, passwordChangedAt, jti)?
- Google sign-in: is the ID token verified with `OAuth2Client.verifyIdToken`
  AND an `audience` equal to our client id?
- Password reset / OTP: are tokens generated with `crypto` (not `Math.random`),
  hashed at rest, single-use, short-lived, and rate-limited with a lockout?
- Password policy: minimum length, breached-password check.
- Is there any hard-coded/master password or impersonation/login-as path?

## 5. Payments & integrations (highest money risk)
- Stripe: are webhooks verified with `stripe.webhooks.constructEvent` on the RAW
  body? Is the charge amount recomputed server-side from the invoice (never taken
  from the client)? Are idempotency keys used on charges/refunds? Is the
  connected-account id read from the company record, not the request?
- Rainforest (BuddyPay): is the webhook signature (and timestamp) verified? Is
  the merchant id taken from the company record? Is the session amount fixed
  server-side?
- QuickBooks: is the OAuth `state` validated on callback and `realmId` bound to
  the company? Are access/refresh tokens encrypted at rest and never returned to
  the browser? Is `intuit-signature` verified if QBO webhooks are enabled?
- Refunds: admin-only, capped at the captured amount, audit-logged?

## 6. Files, PII & secrets
- Is the S3 bucket private, with presigned URLs that expire within 1 hour and
  object keys generated server-side? Are uploads limited by type and size?
- Does any schema store card data (PAN/CVV)? It must store only provider tokens
  + last4. Are bank/tax/DOB fields encrypted? Are password fields `select:false`?
- Any secrets committed to code, `.env`, or git history? Is the JWT secret strong
  and loaded from config with validation?

## 7. Infrastructure & exposure
- helmet() enabled; CORS restricted to our own domains from config; raw-body kept
  for webhooks; global exception filter that does not leak Mongo/stack details.
- docker-compose: are MongoDB/Redis ports published to the host, and is auth on?
- Is Swagger / bull-board / GraphQL playground / `/metrics` disabled or behind
  admin auth in production?

## Deliverable
Write `sb-security-report/BACKEND_RESULTS.md` containing:
1. A gate table: G1–G8, each PASS/WARN/FAIL with High/Medium/Low counts after
   your triage.
2. A table of confirmed issues: id, file:line, severity, one-sentence fix.
3. The route table from routes.csv with a verdict column (OK / IDOR / no-auth /
   no-role) for each route.
4. A short list of false positives with the reason.
Then stop and show me the summary. Do not modify code until I approve the fixes.
