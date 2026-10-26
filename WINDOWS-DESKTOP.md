# Windows desktop packaging

SOS Tools can run in two modes from the Windows installer:

- **Local Desktop** — binds to loopback only, so the UI is private to the computer running it.
- **Central Server (LAN)** — binds to all network interfaces and displays the local network URL(s) for other devices. Configure Windows Firewall to permit the app/port on trusted private networks only.

The desktop wrapper uses the same Express server and application files as the web edition. Local data is stored under the current Windows user's Electron application data folder, in `SOS Tools/data`; it is not stored inside the installed application folder and is preserved when the app is upgraded or uninstalled.

## Build on Windows

Install Node.js 22 LTS, then from the repository folder run:

```powershell
npm install
npm run lint
npm run build:windows
```

The installer is written to `dist/installer/SOS-Tools-Setup-1.1.0-x64.exe`.

## Run the central web server without the desktop shell

```powershell
npm install
$env:HOST = "0.0.0.0"
$env:PORT = "3000"
npm start
```

Other devices can browse to `http://<server-PC-IP>:3000`. For a shared production installation, keep the host on a trusted network, configure the firewall deliberately, and change default credentials immediately. The desktop installer does not configure router/firewall access automatically.

## Build artifact

GitHub Actions builds the Windows installer on Windows for pushes, pull requests, and manual runs. Download the `SOS-Tools-Windows-Installer` artifact from the workflow run. Pushing a version tag such as `v1.1.1` also attaches the installer to a GitHub Release.

Unsigned builds may trigger Windows SmartScreen warnings. A trusted code-signing certificate is required for a signed production installer.
