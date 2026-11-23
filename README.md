# SOS Tools — Web Edition (central server)

The production platform. Everything lives centrally on this server:

- **User accounts** (usernames, scrypt-hashed passwords and PINs, themes) — one list for everyone
- **Activity log** — every login, unlock, user change, recovery action, and settings change, attributed per user
- **Module sources** — what each tab shows (built-in module / file on server / web URL)
- **Settings** — idle-lock timeout, update notice URL

Any device with a browser — Windows PC, Mac, tablet, phone — gets the full app by visiting
the server address. Content is refreshed from the server at every sign-in and unlock, so it
is always current.

## Running it

```bash
cd os-tools-web
npm install
npm start
```

Open **http://localhost:3000** (or your HTTPS reverse-proxy URL on a remote server).

### First-run administrator setup

When no user accounts exist yet (`data/users.json` is missing or empty, or the MongoDB `users` collection is empty), the server enters **Initial Administrator Setup** mode instead of creating default credentials:

1. **Setup token**: Either set `INITIAL_SETUP_TOKEN` (16+ characters) in `.env`/environment before starting the server, or read the auto-generated 48-character one-time token from `data/.setup-token` (created on boot with `0600` permissions). **Setup tokens are never printed to logs.**
2. **Transport safeguard**: Submitting `/api/setup` is only allowed over **HTTPS** (direct TLS or behind a trusted reverse proxy forwarding `X-Forwarded-Proto: https`) or direct loopback (`localhost` / `127.0.0.1`). Plain HTTP remote setup requests are rejected (`403`).
3. **Create the first admin**: Open the web UI, enter the setup token, choose the administrator username, a password (minimum 8 characters), and a 4-digit PIN. Once created, `data/.setup-token` is deleted and `/api/setup` is permanently disabled while any user account exists.

> Existing `users.json` installations keep working with their existing hashed credentials. No default password or PIN exists anywhere in the codebase.

## Offline administrator verification & recovery

If an administrator forgets their password/PIN or loses access on a JSON file store (`data/users.json`), **stop the server first** and run the offline CLI scripts as the server owner (or via `sudo` cleanly — ownership and `0600` permissions are preserved):

```bash
# Check stored credentials cleanly (supports JSON store; checks MongoDB store connectivity)
node scripts/verify-admin-credential.js

# Reset an administrator's password and/or 4-digit PIN offline
# (Refuses to overwrite if the SOS Tools server appears to be running)
node scripts/set-admin-credential.js
```

For MongoDB-backed deployments (`MONGODB_URI`), `set-admin-credential.js` intentionally refuses to modify the local JSON fallback file; manage accounts against the database directly or temporarily verify connectivity with `verify-admin-credential.js`.

## Migrating accounts from the desktop edition

The data format is identical. To bring your existing users across, copy:

```
C:\Users\<you>\AppData\Roaming\sos-tools\sos-tools-data\users.json
```

into `data/users.json` (while the server is stopped, with `0600` permissions) and restart it.

## Where data lives

Everything in file-store mode lives inside `./data/` (or `SOS_DATA_DIR`):

- `users.json` — accounts (passwords/PINs salted + hashed with scrypt, never plain text)
- `settings.json` — settings and module sources
- `activity-log.jsonl` — central audit trail
- `repairs.json`, `phone-reports.json`, `gamepad-reports.json`, `game-library.json`, `cex-cache.json`, `beta-projects.json` — workshop module data
- `.setup-token` — temporary `0600` first-run token (automatically deleted once setup completes)

Back up this directory regularly.

## Reverse proxy, HTTPS, cookies & CSRF protection

- **Reverse proxy (`TRUSTED_PROXIES`)**: Only loopback (`127.0.0.1`, `::1`) is trusted by default. If TLS terminates on an upstream proxy on a separate host, set `TRUSTED_PROXIES=<proxy-ip1>,<proxy-ip2>`. Spoofed `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` headers from untrusted sockets are ignored.
- **Session cookies (`sos_session`)**: Issued as `HttpOnly` with 12-hour server-side expiry (`SESSION_MAX_AGE_MS`).
  - Over HTTPS (direct TLS or trusted `X-Forwarded-Proto: https`) or when `FORCE_SECURE_COOKIES=1`, cookies include `Secure`.
  - Setting `NODE_ENV=production` alone does **not** force `Secure` cookies on plain HTTP (`http://<server-ip>:3000`), avoiding broken module iframe logins before TLS/Caddy/Nginx is configured.
  - Enable HTTPS (e.g. Caddy or Nginx + Let's Encrypt) before exposing the app on public/untrusted networks, and optionally set `FORCE_SECURE_COOKIES=1`.
- **CSRF protection**: All state-changing `/api/*` requests (`POST`, `PUT`, `PATCH`, `DELETE`) authenticated by cookie rather than `Authorization: Bearer` enforce same-origin checks (`Sec-Fetch-Site`, `Origin`, `Referer`) and block simple cross-site HTML form content types (`application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`).
- **Session revocation & lockout protection**:
  - `POST /api/logout`, own-password changes (`/api/change-own-password`), and admin password resets (`/api/users/reset-credentials`) immediately invalidate affected active sessions and clear the session cookie.
  - Rate limiting (`429` + `Retry-After`) protects `/api/login`, `/api/verify-pin` (invalidating the current session after repeated wrong PINs without permanent account lockout), and `/api/setup`.

## Hosting options

- **Oracle Cloud / Ubuntu VPS + Systemd + Caddy/Nginx HTTPS**: Install Node.js LTS, copy app files (never commit `data/` or `.env`), bind behind Caddy/Nginx with HTTPS, and configure automatic backups of `data/`.
- **Always-on shop PC / Tailscale**: Run `npm start` on a LAN workstation with Windows Firewall / Tailscale access control.
- **Render + MongoDB Atlas**: Set `MONGODB_URI`, `INITIAL_SETUP_TOKEN`, and `FORCE_SECURE_COOKIES=1`.
