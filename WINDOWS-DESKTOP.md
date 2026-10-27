# SOS Tools Windows desktop test build

This desktop wrapper runs the same app code locally for testing. It does not need the live website to be online for Local Desktop mode.

## Modes

- **Local Desktop** binds only to `127.0.0.1`. Offline features continue to work; features that call external services need an internet connection.
- **Central Server (LAN)** binds to the local network so other devices may connect. Use only on a trusted network and configure Windows Firewall deliberately.

## Local data

Desktop data lives in the current Windows user's Electron application-data folder, outside the installed program files, so upgrades do not overwrite it. On first launch, the wrapper copies data from the legacy location `%APPDATA%\sos-tools\sos-tools-data` only if the new data folder is empty. It does not overwrite files during this migration.

## Build on Windows

Install Node.js 22 LTS, then run:

```powershell
npm install
npm run lint
npm run build:windows
```

The installer is written to `dist/installer/SOS-Tools-Setup-1.1.1-x64.exe`. The build is unsigned and Windows SmartScreen may show a warning.

## In-app updates

Packaged builds check GitHub Releases when online. If a newer release is found, the app asks before downloading and asks again before restarting to install. If offline, update checks fail quietly and the local app still opens.

The existing installed build does not contain this updater, so one replacement installation is required to add the updater capability. Future published releases can be downloaded from inside the app. For each release, increase the version in `package.json` and `server.js`, merge the tested changes, then push a matching tag such as `v1.1.2`. The release workflow publishes the NSIS installer plus the metadata and blockmap files used by Electron's updater.

## Website remains separate

The website's `npm start` command still runs `node server.js`. The desktop installer uses `desktop/main.js` as its entry point. Local Desktop mode uses its own data directory and only accesses external services for features that need them.
