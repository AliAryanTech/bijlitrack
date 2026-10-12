# BijliTrack — Security Audit Report

**Project:** Lesco-Electricity-Moniter (BijliTrack)
**Path:** `D:\My-Github-Projects\Lesco-Electricity-Moniter`
**Stack:** Next.js 16.4.0 (App Router, route handlers), React 19, TypeScript, MongoDB/Mongoose 8, JWT (`jsonwebtoken`), bcryptjs, Nodemailer, Anthropic + Google Gemini SDKs
**Audit date:** 2026-10-12
**Methodology:** Manual source review (white-box) of all API route handlers, auth layer, data models, and client data sinks; secrets/tracking review; dependency audit (`npm audit`).
**Scope:** `src/` (app routes, lib, hooks, components), config (`next.config.ts`, `vercel.json`, `.gitignore`, `.env.example`).

---

## 1. Executive Summary

The application has a **solid authentication and authorization core**: every reference/dashboard/complaint endpoint enforces ownership, passwords are bcrypt-hashed, JWT is delivered via an `httpOnly` cookie, and the bill-upload endpoint validates file magic bytes. No dependency vulnerabilities are currently reported.

However, the audit found **4 High**, **8 Medium**, and **10 Low** issues. The most serious are:

1. **Unauthenticated, unmetered AI endpoints** (`/api/audit/parse`, `/api/audit/roast`, `/api/audit/generate-dispute`) that let anyone spend the owner's Anthropic/Gemini credits and push arbitrary content into the LLM.
2. **No rate limiting anywhere** — login brute-force, password-reset email bombing, and AI cost exhaustion are all trivially abusable.
3. **`/api/cron/daily-tracker` fails open** — when `CRON_SECRET` is unset it runs for anonymous callers.
4. **Host-header injection in the password-reset flow** can produce attacker-controlled reset links (account takeover) when `FRONTEND_URL` is unset.

None of these are remote code execution; they are access-control, abuse, and data-handling weaknesses. Overall risk is assessed as **Medium-High** and should be remediated before public scale-up.

---

## 2. Findings Summary

| ID | Severity | Title | Location |
|----|----------|-------|----------|
| H-1 | High | Unauthenticated AI bill/roast/dispute endpoints (cost abuse, prompt injection) | `src/app/api/audit/parse/route.ts:49`, `roast/route.ts:27`, `generate-dispute/route.ts:9` |
| H-2 | High | No rate limiting on auth, reset, report and AI endpoints | `src/app/api/auth/*`, `src/app/api/audit/*`, `report/generate/route.ts` |
| H-3 | High | `daily-tracker` cron fails open when `CRON_SECRET` unset | `src/app/api/cron/daily-tracker/route.ts:8-16` |
| H-4 | High | Host-header injection in password-reset link generation | `src/app/api/auth/forgot-password/route.ts:13-20,46-47` |
| M-1 | Medium | Stored data injected into `document.write` (same-origin XSS) | `src/app/dashboard/outages/page.tsx:143-184` + `api/dashboard/[referenceId]/save/route.ts:20-54` |
| M-2 | Medium | Reset token can be returned in API response (prod footgun) | `src/app/api/auth/forgot-password/route.ts:59-66` |
| M-3 | Medium | JWT survives password reset; token also persisted in `localStorage` | `src/lib/server/auth.ts`, `src/lib/api.ts:17`, `src/hooks/useAuth.tsx:73` |
| M-4 | Medium | No password strength policy at signup | `src/app/api/auth/signup/route.ts:12-18` |
| M-5 | Medium | Missing security headers (CSP, HSTS, frame-ancestors, nosniff) | `next.config.ts:3` |
| M-6 | Medium | Unbounded/unvalidated `Mixed` payload stored on save | `src/app/api/dashboard/[referenceId]/save/route.ts:20-54` |
| M-7 | Medium | Internal `error.message` leaked to API clients | `auth/signup:54`, `auth/login:52`, `auth/forgot-password:71`, `auth/reset-password:50` |
| M-8 | Medium | User enumeration on signup ("User already exists") | `src/app/api/auth/signup/route.ts:20-23` |
| L-1 | Low | JWT verification does not pin the signing algorithm | `src/lib/server/auth.ts:63` |
| L-2 | Low | Cookie not `__Host-` prefixed; `sameSite=lax`; 24h cookie vs 7d token mismatch | `src/lib/server/auth.ts:18,22-32` |
| L-3 | Low | Verbose logging of tokens/PII | `src/lib/api.ts:23-37`, `auth/login/route.ts:20,24,30` |
| L-4 | Low | `z.coerce.boolean()` truthiness bug (`"false"` → `true`) | `src/app/api/audit/roast/route.ts:20` |
| L-5 | Low | Malformed ObjectId produces 500 instead of 400 | `dashboard/[referenceId]/*`, `reference/[id]/route.ts` |
| L-6 | Low | No CSRF token (mitigated by `sameSite=lax` + Bearer) | app-wide |
| L-7 | Low | bcrypt cost factor 10 (consider 12) | `src/lib/server/models/User.ts:31` |
| L-8 | Low | Cron triggers internal endpoints via request origin | `src/app/api/cron/daily-audit/route.ts:31-46` |
| L-9 | Low | Live secrets present in local `.env.local` (verify never committed) | `.env.local` |
| L-10 | Low | Stub endpoints return fake success (misleading) | `audit/batch-validate/route.ts`, `tariffs/scrape-update/route.ts` |

---

## 3. Detailed Findings

### H-1 — Unauthenticated AI endpoints (High)
**CWE-306 (Missing Authentication), CWE-770 (Resource Exhaustion)**

`/api/audit/parse`, `/api/audit/roast`, and `/api/audit/generate-dispute` perform **no `verifyAuth` call** — unlike every dashboard route. Any anonymous caller can:

- Upload up to a 4.5 MB file to `/api/audit/parse`, which is forwarded to Anthropic/Gemini (`parseUtilityBill`), **billing the project owner**.
- Trigger LLM text generation via `roast` / `generate-dispute`.
- Feed arbitrary prompt content into the models (prompt-injection / content-abuse surface).

Evidence:
```ts
// src/app/api/audit/parse/route.ts:49 — no auth check
export async function POST(req: NextRequest) { ... parseUtilityBill(base64, mediaType) ... }
// src/app/api/audit/roast/route.ts:27 — no auth check
// src/app/api/audit/generate-dispute/route.ts:9 — no auth check
```

**Impact:** Financial cost abuse and DoS of a paid third-party dependency; the endpoint becomes a free public AI proxy. High.
**Remediation:** Add `verifyAuth(req)` (or `await requireUser(req)`) to all three handlers; return 401 otherwise. Optionally keep a lightweight anonymous tier with strict per-IP quotas.

---

### H-2 — No rate limiting (High)
**CWE-307 (Improper Restriction of Excessive Authentication Attempts), CWE-770**

Grep for `rate.?limit|throttle` returns **zero matches** in the codebase. Exposed, unmetered surfaces:

- `/api/auth/login` — unlimited credential guessing (no lockout, no backoff).
- `/api/auth/forgot-password` — unlimited reset emails → victim email flooding; also enables timing-based user enumeration.
- `/api/audit/parse|roast|generate-dispute` — unlimited AI spend.
- `/api/dashboard/[referenceId]/report/generate` — limited to 2/user/day but a user can spam other endpoints.

**Impact:** Brute force, spam, cost exhaustion, application-layer DoS. High.
**Remediation:** Add a rate-limiter (`@upstash/ratelimit` + Redis, `rate-limiter-flexible`, or Vercel/edge middleware) keyed by IP + account for auth routes, and by user/IP for AI routes. Add exponential backoff and temporary lockout after N failed logins.

---

### H-3 — `daily-tracker` cron fails open (High)
**CWE-306 (Missing Authentication for Critical Function)**

```ts
// src/app/api/cron/daily-tracker/route.ts:9-16
const cronSecret = process.env.CRON_SECRET;
if (cronSecret) {                       // <-- only enforced when set
  const authHeader = req.headers.get('authorization');
  if (authHeader !== `Bearer ${cronSecret}`) return 401;
}
```
If `CRON_SECRET` is unset, **the endpoint is fully public** and will iterate every active `Reference`, run server-side CCMS syncs, and write `ScraperLog` rows. This is both a resource-abuse vector and a data-processing trigger reachable by anonymous users. Contrast with `daily-audit`, which correctly **fails closed** in production (`daily-audit/route.ts:21-28`).

**Impact:** Unauthenticated triggering of server-side jobs; resource abuse; `referenceNo` values are partially exposed through `ScraperLog`/logs. High.
**Remediation:** Mirror the `daily-audit` logic — fail closed in production when `CRON_SECRET` is unset. Better: use Vercel's signed `CRON_SECRET` header only (`x-vercel-cron`), reject all else.

---

### H-4 — Host-header injection in password reset (High)
**CWE-644 (Improper Neutralization of HTTP Headers), CWE-601 (Open Redirect → Account Takeover)**

```ts
// src/app/api/auth/forgot-password/route.ts:13-20
const getFrontendUrl = (req: NextRequest) => {
  if (process.env.FRONTEND_URL) return process.env.FRONTEND_URL.replace(/\/$/, '');
  const host = req.headers.get('host') || 'localhost:3000';
  const proto = req.headers.get('x-forwarded-proto') || 'http';
  return `${proto}://${host}`;              // attacker-controlled if FRONTEND_URL unset
};
// :47
const resetUrl = `${baseUrl}/reset-password?token=${resetToken}`;
```
When `FRONTEND_URL` is not configured, the reset link base is derived from the request `Host` / `X-Forwarded-Proto`. An attacker who can influence those headers (or when deployed behind a permissive proxy) can cause a victim's reset email to point at an attacker domain, **capturing the reset token → account takeover**.

**Impact:** Full account takeover under the misconfiguration. High.
**Remediation:** Require `FRONTEND_URL` (fail loudly if unset) and never derive origin from request headers. If a fallback is needed, use a hard-coded allow-listed origin.

---

### M-1 — HTML injection into print window (Medium)
**CWE-79 (XSS)**

The outages page builds an HTML document from stored outage data and writes it into a new window:

```tsx
// src/app/dashboard/outages/page.tsx:159
<h2>Feeder: ${feederName} (${feederCode})</h2>
// :181-184
const printWindow = window.open('', '_blank');
printWindow.document.write(html);
```
`feederName`/`feederCode` originate from `/api/dashboard/[referenceId]/save`, which stores client-supplied `outageInfo` (`Mixed`) **without any validation or sanitization**:
```ts
// src/app/api/dashboard/[referenceId]/save/route.ts:21,44-52
const { consumerInfo, billingInfo, outageInfo } = body;   // never validated
```
`document.write` into an `about:blank` window runs in the **opener's origin**, so injected `<script>`/`<img onerror>` executes with access to `localStorage` (where the JWT is kept — see M-3). Chiefly self-XSS (a user poisoning their own data), but it becomes cross-user if any shared/admin view or aggregated feed renders this data, and CCMS is an external data source.

**Remediation:** Escape all interpolated values (or build the print DOM via `textContent`/`createElement`); add a strict schema + size limit on the `save` payload (see M-6).

---

### M-2 — Reset token can be returned in the API response (Medium)
**CWE-200 (Information Exposure)**

```ts
// forgot-password/route.ts:59-66
const shouldReturnLink =
  process.env.RETURN_PASSWORD_RESET_LINK === 'true' ||
  (process.env.NODE_ENV !== 'production' && !mailSent);
return NextResponse.json({ ..., ...(shouldReturnLink ? { resetToken, resetUrl } : {}) });
```
If `RETURN_PASSWORD_RESET_LINK=true` is ever set in production (or `NODE_ENV` is not exactly `production`), **the raw reset token is returned to any caller** who submits a victim's email → immediate account takeover.

**Remediation:** Remove the env toggle for production builds; gate the debug return strictly on a non-production build flag compiled out in prod. Prefer never returning the token via HTTP — log it to the server console only in local dev.

---

### M-3 — Token lifecycle weaknesses (Medium)
**CWE-613 (Insufficient Session Expiration), CWE-522 (Insufficiently Protected Credentials)**

- `reset-password` (`route.ts:39-42`) changes the password but **does not invalidate existing JWTs**. Because JWTs are stateless with no `jti`/version, any previously issued token stays valid for up to 7 days after a password reset/change.
- Signed token lifetime is 7 days (`auth.ts:18`), while the cookie `maxAge` is 24h (`auth.ts:30`) — inconsistent, and the **7-day token is also stored in `localStorage`** (`src/lib/api.ts:17`, `useAuth.tsx:73`) and sent as a `Bearer` header, which defeats the `httpOnly` cookie and is exfiltratable via any XSS (M-1).

**Remediation:** Add a `tokenVersion` (or `passwordChangedAt`) claim to the JWT and reject tokens issued before the last password change; drop the `localStorage` copy and rely on the `httpOnly` cookie; align cookie/token TTLs. Provide a `/auth/logout-all`.

---

### M-4 — No password policy at signup (Medium)
**CWE-521 (Weak Password Requirements)**

`signup/route.ts:12-18` checks only presence of `name/email/password`. No minimum length, complexity, or breach check — a one-character password is accepted. (`reset-password` does enforce ≥8 chars, inconsistently.)

**Remediation:** Enforce a shared password policy (e.g. min 8–12 chars, reject common/breached passwords) via a Zod schema used by both signup and reset. Optionally add email verification.

---

### M-5 — Missing security headers (Medium)
**CWE-693 (Protection Mechanism Failure)**

`next.config.ts` is empty:
```ts
const nextConfig: NextConfig = {};
```
No CSP, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`/`frame-ancestors`, `Referrer-Policy`, or `Permissions-Policy`. This leaves the app with no defense-in-depth against XSS (M-1) or clickjacking.

**Remediation:** Add `headers()` in `next.config.ts` (or `middleware.ts`) setting at minimum HSTS, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `X-Frame-Options: DENY`, and a Content-Security-Policy tuned to the app.

---

### M-6 — Unbounded/unvalidated stored payload (Medium)
**CWE-20 (Improper Input Validation), CWE-400 (Uncontrolled Resource Consumption)**

`POST /api/dashboard/[referenceId]/save` writes `consumerInfo`, `billingInfo`, `outageInfo` directly into `Mixed` fields and also iterates `outageInfo.days` / `billingInfo.histInfo` to upsert related collections — with **no schema, depth, or byte-size limit**. A client can:
- Store arbitrarily large objects (bounded only by MongoDB's 16 MB document cap and request limits).
- Inject unexpected keys that later flow into prompts and the print sink (M-1).

**Remediation:** Validate the payload with Zod (define the exact expected shape), cap sizes/counts (e.g. ≤ 40 days, ≤ 13 months, string length caps), and reject unknown keys.

---

### M-7 — Internal error messages leaked (Medium)
**CWE-209 (Generation of Error Message Containing Sensitive Information)**

Multiple handlers return `error.message` verbatim to clients, e.g.:
```ts
// auth/signup/route.ts:54
{ message: error.message || 'Error creating user' }, { status: 500 }
// auth/login/route.ts:52, auth/forgot-password/route.ts:71, auth/reset-password/route.ts:50
```
Mongoose/JWT/nodemailer errors can disclose stack-adjacent internals (collection names, driver errors, connectivity hints).

**Remediation:** Return generic client messages; log the detailed error server-side only.

---

### M-8 — User enumeration on signup (Medium)
**CWE-204 (Observable Response Discrepancy)**

`signup` returns `"User already exists"` (400) for a taken email (`signup/route.ts:20-23`), while `login` correctly uses a generic `"Invalid credentials"`. `forgot-password` is properly generic. Signup thus confirms account existence.

**Remediation:** Return a generic success/verify message for signup too, or move to an email-verification flow that does not reveal registration state.

---

### Low-severity findings

- **L-1 JWT algorithm pinning** — `jwt.verify(token, secret)` (`auth.ts:63`) does not pass `{ algorithms: ['HS256'] }`. Low risk with HMAC-only secrets but should be pinned.
- **L-2 Cookie hardening** — `AUTH_COOKIE_NAME = 'token'` (`auth.ts:8`), `sameSite: 'lax'`, no `__Host-` prefix; cookie (24h) vs token (7d) mismatch. Prefer `__Host-token`, `sameSite: 'strict'`, and aligned TTLs.
- **L-3 Verbose logging** — client `api.ts:23-37` logs every response body (may include the token from login) to the browser console; server logs user emails on login (`login/route.ts:20,24,30`). Reduce/mask.
- **L-4 Boolean coercion** — `isProtected: z.coerce.boolean()` (`roast/route.ts:20`) turns the string `"false"` into `true`. Use `z.boolean()` or explicit parsing.
- **L-5 CastError handling** — malformed `referenceId`/`id` on `_id` lookups raises a Mongoose `CastError` → 500 instead of 400. Validate ObjectId format or map to 400.
- **L-6 CSRF** — no CSRF token; mitigated because state-changing routes are POST/DELETE and the auth cookie is `SameSite=Lax`. Adding a token or `SameSite=Strict` would harden further.
- **L-7 bcrypt cost** — cost factor 10 (`User.ts:31`); consider 12 given modern hardware.
- **L-8 Cron origin fetch** — `daily-audit` calls `${req.nextUrl.origin}/api/...` (`daily-audit/route.ts:31-46`); harmless while protected, but prefer internal calls or a fixed base URL.
- **L-9 Local secrets** — `.env.local` exists with live `MONGODB_URI`, `JWT_SECRET`, `GEMINI_API_KEY`, `SMTP_PASS`, `VERCEL_OIDC_TOKEN`. Verified **not** tracked (`git ls-files` shows only `.env.example`; `.env.local` is in `.gitignore`). Keep it that way; rotate if the file ever left the machine.
- **L-10 Stub endpoints** — `audit/batch-validate` and `tariffs/scrape-update` return hard-coded fake success (`processedCount: 0`, `"updated": true`). Not a vulnerability, but misleading; gate behind auth or clearly mark as stubs.

---

## 4. Positive Controls Observed

- **IDOR/BOLA protected:** every `/api/reference/*` and `/api/dashboard/[referenceId]/*` handler scopes queries by `{ userId: authUser.id }` after `verifyAuth` (e.g. `reference/[id]/route.ts:22-25`, `dashboard/[referenceId]/route.ts:16`). Cascade deletes are also ownership-gated.
- **Upload hardening:** `audit/parse` validates declared size, Base64 charset, approximate decoded size, and verifies **magic bytes per MIME type** (`route.ts:21-143`) — a client-supplied `mediaType` cannot spoof the forwarded type.
- **Input validation:** Zod schemas with explicit max lengths/limits on `roast` and `generate-dispute`; `referenceNo` strictly validated to 14 digits; `ticketNo` URL-encoded.
- **NoSQL injection:** email is normalized with `?.toLowerCase().trim()` before `findOne`, so operator objects throw instead of being interpreted.
- **Credential storage:** bcrypt hashing via pre-save hook; reset tokens stored only as SHA-256 hash with 1-hour expiry and `select:false`; `me` strips `passwordHash`.
- **Cookie auth added:** `httpOnly` + `secure` (in prod) + `SameSite=Lax` for the session cookie; generic forgot-password response; logout clears the cookie.
- **Cron (daily-audit) fails closed** in production when the secret is unset.
- **Dependencies:** `npm audit --omit=dev` → **0 vulnerabilities**; `next@16.4.0`, `jsonwebtoken@9.0.3`, `axios@1.20.0`, `mongoose@8.24.4`.

---

## 5. Prioritized Remediation Roadmap

**Immediate (this week)**
1. Add auth to `/api/audit/parse`, `/roast`, `/generate-dispute` (H-1).
2. Fail closed on `daily-tracker` and require a cron secret (H-3).
3. Require `FRONTEND_URL`; stop deriving reset origin from headers (H-4).
4. Add rate limiting to auth + AI routes (H-2).

**Short term (2–4 weeks)**
5. Remove/or compile-out `RETURN_PASSWORD_RESET_LINK`; never return reset tokens over HTTP (M-2).
6. Escape the print HTML and validate the `save` payload with Zod + size caps (M-1, M-6).
7. Invalidate JWTs on password change (`tokenVersion`); drop `localStorage` token; align TTLs (M-3).
8. Add signup password policy (M-4).
9. Add security headers via `next.config.ts`/middleware (M-5).
10. Generic error responses + signup response to close info leaks/enumeration (M-7, M-8).

**Backlog**
11. Pin JWT algorithm; harden cookie (`__Host-`, `strict`) (L-1, L-2).
12. Reduce logging of tokens/PII (L-3); fix boolean coercion (L-4); validate ObjectId inputs (L-5); raise bcrypt cost (L-7).

---

## 6. Appendix — Verification Notes

- `npm audit --omit=dev` → `found 0 vulnerabilities`.
- `git ls-files | Select-String '\.env'` → only `.env.example` tracked (no committed secrets). Git history grep for real key patterns found only placeholder values.
- Working tree contains uncommitted auth changes (cookie-based session added in `src/lib/server/auth.ts`, `src/lib/api.ts`, `src/hooks/useAuth.tsx`, `login`/`signup` handlers, new `logout` route). This report reflects the **current working-tree state**.
- Client-side auth gating (`dashboard/layout.tsx:42-46`) is a UX redirect only; all sensitive data is protected server-side by `verifyAuth`, which is the effective control.

---

*End of report.*
