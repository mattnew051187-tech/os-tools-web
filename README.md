# SOS Tools — Web Edition (central server)

The production platform. Everything lives centrally on this server:

- **User accounts** (usernames, hashed passwords, PINs, themes) — one list for everyone
- **Activity log** — every login, unlock, user change and settings change, attributed per user
- **Module sources** — what each tab shows (built-in placeholder / file on server / web URL)
- **Settings** — idle-lock timeout, update notice URL

Any device with a browser — Windows PC, Mac, tablet, phone — gets the full app by visiting
the server address. Content is refreshed from the server at every sign-in and unlock, so it
is always current. The desktop edition remains available as the beta-testing environment.

## Running it

```bash
cd SOSTools-Web
npm install
npm start
```

Then open **http://localhost:3000**. First run creates the master account:

| Username | Password | PIN |
|---|---|---|
| Admin | 12345 | 1234 |

(Change both immediately via Account / Users.)

## Migrating accounts from the desktop edition

The data format is identical. To bring your existing users across, copy:

```
C:\Users\<you>\AppData\Roaming\sos-tools\sos-tools-data\users.json
```

into `SOSTools-Web\data\users.json` (while the server is stopped) and restart it.

## Where data lives

Everything is in `SOSTools-Web\data\`:

- `users.json` — accounts (passwords/PINs salted + hashed, never plain text)
- `settings.json` — settings and module sources
- `activity-log.jsonl` — central audit trail

Back this folder up and it carries your entire user base.

## Hosting options

**Option B — free cloud hosting with a permanent address (Render + MongoDB Atlas):**

The app supports a cloud database out of the box: set the `MONGODB_URI` environment variable
and all accounts/settings/logs persist in MongoDB Atlas (free tier) instead of local files —
surviving restarts and redeploys.

1. Create a free **GitHub** account and a new repository (e.g. `sos-tools-web`), upload this
   folder's files (not `node_modules` or `data`)
2. Create a free **MongoDB Atlas** account → M0 cluster → database user → network access
   `0.0.0.0/0` → copy the connection string
3. Create a free **Render** Web Service connected to that repo — build `npm install`, start
   `node server.js`, environment variable `MONGODB_URI` = the Atlas connection string
   (also set `NODE_ENV=production`)
4. Render gives you a permanent address like `https://sos-tools.onrender.com`
5. Future deploys: update the files in the GitHub repo → Render redeploys automatically

Free-tier notes: Render spins the app down after ~15 min idle (first visitor waits ~1 min
for wake-up; logins during the day keep it warm) and shows a `onrender.com` subdomain.

**Option A — run it on one always-on PC at the shop (free):**

See the step-by-step below. Short version: run `start-server.bat` on the shop PC, tell staff
the address `http://<shop-pc-ip>:3000`, and (optionally) install Tailscale for access from
outside the shop.

### Option A step-by-step

1. Copy the `SOSTools-Web` folder to the always-on PC (USB is fine) and install Node.js LTS
   there if it isn't installed
2. Run `npm install` once in that folder
3. Double-click `start-server.bat` — the server runs while that window is open
4. Find the PC's address: open PowerShell there and run `ipconfig` — note the **IPv4 Address**
   (e.g. `192.168.1.50`). Staff use `http://192.168.1.50:3000`
5. Allow the port through Windows Firewall (PowerShell as admin):
   `netsh advfirewall firewall add rule name="SOS Tools" dir=in action=allow protocol=TCP localport=3000`
6. In the router, give that PC a fixed DHCP reservation so its IP never changes
7. Auto-start on boot: press Win+R, type `shell:startup`, Enter — put a shortcut to
   `start-server.bat` in that folder. For crash-recovery too, use PM2:
   `npm install -g pm2` then `pm2 start server.js --name sos-tools`, `pm2 save`,
   `pm2 startup` (follow its printed instruction)
8. Access from outside the shop: install **Tailscale** (free) on the server PC and on each
   device that needs remote access; then use the Tailscale name instead of the IP

**Option B (chosen) — Oracle Cloud free-forever VPS:**

A real always-on Ubuntu server, £0 forever, no sleeping. Deploy via:

1. Create a free GitHub account and a **public** repo `sos-tools-web`; upload this folder's
   files (not `node_modules` or `data` — `data` must never be uploaded, it holds accounts)
2. Sign up at cloud.oracle.com (free tier; needs a card for identity checks, never charged;
   **home region: UK South (London)** — this cannot be changed later)
3. Compute → Create Instance: Ubuntu 22.04, shape **VM.Standard.E2.1.Micro** (tick "Always
   Free eligible"), generate/download the SSH keys and keep them safe
4. Under *Advanced options → Management → Add cloud-init script*: paste the contents of
   `deploy/oracle-cloud-init.txt` **after replacing GITHUB_USERNAME with your GitHub username**
5. After creation: note the instance's **Public IP address**, then open port 3000 in the
   cloud firewall: Networking → Virtual Cloud Networks → your VCN → Security Lists →
   Default Security List → Add Ingress Rule: source `0.0.0.0/0`, protocol TCP, port 3000
6. Wait ~5 minutes for cloud-init to finish, then open `http://<PUBLIC-IP>:3000`
7. Sign in Admin/12345 → change the password immediately

From then on, updating the live site = changing the files in the GitHub repo; the VM pulls
and applies them automatically every 10 minutes (only restarting if something changed).

HTTPS note: the site is HTTP until you attach a domain name (~£1–10/yr) — then we add a free
Let's Encrypt certificate via Caddy for full HTTPS. Not urgent for an internal tool, but
recommended before long-term public use.

**Option C — proper paid web hosting (a few pounds/month):**

Any host that runs Node.js works (Render, Railway, a small VPS, etc.). Deploy the
`SOSTools-Web` folder, set `PORT` if needed, and attach persistent storage for the `data`
folder. The host provides the HTTPS certificate automatically.

**Option C — free host with a database** — possible, but the JSON file store works best with
Options A/B. Ask if you want a database-backed variant.

## Security

- Session cookies are httpOnly; passwords/PINs hashed with scrypt
- Set `NODE_ENV=production` when deployed behind HTTPS so cookies are marked Secure
- All privileged endpoints require an authenticated session; admin ones require the admin role
