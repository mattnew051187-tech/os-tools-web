# SOS Tools — Security and Quality Phase 1

## Safety boundary

This work is being prepared on `sos-tools/security-and-quality-phase-1`. The production deployment tracks `main`; this branch is not deployed by the existing updater. Do not merge this branch or change the production deployment configuration without an explicit owner approval.

No production data, server configuration, or live deployment is changed by this plan.

## Priority 0 — close authentication bypasses safely

Static review of `server.js` found hard-coded fallback credentials accepted for the Matt account in password login, PIN unlock, and current-password verification. The first-run bootstrap also creates a predictable master credential when the user store is empty.

Implementation:
1. Confirm how the current production user store is populated and take a verified, restorable backup before any account migration.
2. Remove hard-coded fallback acceptance from all authentication and password-change paths.
3. Replace predictable first-run bootstrap credentials with a one-time setup flow that requires an operator-provided secret or a securely generated, single-use setup token. Never log or commit the token.
4. Preserve existing hashed credentials and verify that the real account password/PIN still works before revoking any legacy path.
5. Add regression tests proving fallback values cannot authenticate, unlock, or authorize password changes.
6. Rotate any credentials that may have been exposed in source history or deployment logs.

Do not deploy until the owner has confirmed a tested recovery/login path. If the production account currently relies on the fallback path, a blind removal could lock out the owner.

## Priority 1 — protect sessions and endpoints

- Add bounded rate limiting and generic failure responses to login and PIN verification; test lockout/abuse behavior without enabling a permanent denial-of-service vector.
- Review cookie flags, proxy trust, session expiry, and logout behavior. Prefer `Secure`, `HttpOnly`, and an appropriate `SameSite` policy when served over HTTPS.
- Review state-changing routes for CSRF protection where cookie authentication is used.
- Audit endpoints that currently omit authentication, especially data mutation and administrative operations, and document the intended access policy before changing behavior.
- Validate and bound request payloads; avoid leaking internal exception details to clients.

## Priority 2 — transport security and deployment

- Put the service behind HTTPS (for example, Caddy with an automatically renewed certificate once a domain points to the host).
- Keep the Node service bound behind the reverse proxy; restrict direct public access to the application port.
- Verify firewall rules, process supervision, backups, restore procedure, and deployment rollback.
- Confirm the live updater only deploys approved `main` commits. Do not change its production target as part of this branch.

## Priority 3 — repeatable quality checks

- Replace the placeholder build script with meaningful validation, or remove the misleading build step.
- Add automated tests for authentication, authorization, core API behavior, and storage modes.
- Add CI to run syntax checks, tests, and dependency/security checks on pull requests.
- Add browser smoke tests for login, navigation, key modules, and logout once a stable test environment exists.
- Keep test data isolated from production data; never run destructive tests against the live database.

## Multi-agent development workflow

- GitHub is the source of truth.
- Gemini, ChatGPT, and any local agent work on separate branches; no agent pushes directly to `main`.
- Each change is a small commit with a clear summary and test evidence.
- Pull requests target `main`, include risk/rollback notes, and require human review.
- Merge only after CI passes and the owner explicitly approves deployment.
- Keep a concise handover in this document or a dedicated issue: current branch, changed files, checks run, known risks, and next task.

## Acceptance gates before production

- [ ] Existing production user data backed up and restore verified.
- [ ] Owner login and PIN recovery tested using the real account store.
- [ ] Regression tests prove hard-coded fallback credentials no longer work.
- [ ] Admin/user permissions and protected routes covered by tests.
- [ ] HTTPS and secure cookie behavior verified on the deployed hostname.
- [ ] CI checks pass; browser smoke tests pass in staging.
- [ ] Rollback procedure documented and tested.
- [ ] Owner approves the PR and the production deployment separately.

## Current review notes

- The repository's `package.json` currently has a syntax-oriented lint script and a placeholder/no-op build script; no substantive automated test suite was identified in the initial review.
- The supplied live address uses plain HTTP. The running instance was not independently verified during this review; confirm its actual proxy/TLS configuration on the host.
- The initial source review is static. Validate all findings against the deployed revision and actual runtime configuration before production changes.
