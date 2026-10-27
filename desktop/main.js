const { app, BrowserWindow, dialog } = require('electron');
const { autoUpdater } = require('electron-updater');
const http = require('http');
const net = require('net');
const path = require('path');
const fs = require('fs');

let mainWindow;

function reservePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const port = probe.address().port;
      probe.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function waitForServer(url, attempts = 60) {
  return new Promise((resolve, reject) => {
    let remaining = attempts;
    const check = () => {
      const request = http.get(url, (response) => {
        response.resume();
        if (response.statusCode && response.statusCode < 500) return resolve();
        retry();
      });
      request.setTimeout(1000, () => request.destroy(new Error('timeout')));
      request.on('error', retry);
      function retry() {
        if (--remaining <= 0) return reject(new Error('SOS Tools server did not start.'));
        setTimeout(check, 500);
      }
    };
    check();
  });
}

function migrateLegacyData(dataDir) {
  const legacyDir = path.join(app.getPath('appData'), 'sos-tools', 'sos-tools-data');
  fs.mkdirSync(dataDir, { recursive: true });
  // Never overwrite data that already exists in the new location.
  if (fs.readdirSync(dataDir).length !== 0 || !fs.existsSync(legacyDir)) return;
  for (const entry of fs.readdirSync(legacyDir, { withFileTypes: true })) {
    const source = path.join(legacyDir, entry.name);
    const destination = path.join(dataDir, entry.name);
    if (fs.existsSync(destination)) continue;
    if (entry.isDirectory()) {
      fs.cpSync(source, destination, { recursive: true, force: false, errorOnExist: false });
    } else if (entry.isFile()) {
      fs.copyFileSync(source, destination);
    }
  }
  console.log('[Data] Copied legacy local data into the new data folder.');
}

function configureAutoUpdates() {
  if (!app.isPackaged) return;
  autoUpdater.autoDownload = false;
  autoUpdater.autoInstallOnAppQuit = true;

  autoUpdater.on('error', (error) => {
    // Offline update checks must not prevent Local Desktop from opening.
    console.warn('[Updater] Update check failed:', error.message);
  });

  autoUpdater.on('update-available', async (info) => {
    if (!mainWindow) return;
    const answer = await dialog.showMessageBox(mainWindow, {
      type: 'info',
      title: 'SOS Tools update available',
      message: 'A newer SOS Tools test build is available.',
      detail: 'Version ' + info.version + ' can be downloaded. Your local test data is stored separately.',
      buttons: ['Download update', 'Later'],
      defaultId: 0,
      cancelId: 1,
      noLink: true
    });
    if (answer.response === 0) {
      try {
        await autoUpdater.downloadUpdate();
      } catch (error) {
        dialog.showErrorBox('SOS Tools update failed', error.message);
      }
    }
  });

  autoUpdater.on('update-downloaded', async (info) => {
    if (!mainWindow) return;
    const answer = await dialog.showMessageBox(mainWindow, {
      type: 'info',
      title: 'SOS Tools update ready',
      message: 'SOS Tools ' + info.version + ' has downloaded.',
      detail: 'Restart to install the update. Local test data will be kept.',
      buttons: ['Restart and install', 'Later'],
      defaultId: 0,
      cancelId: 1,
      noLink: true
    });
    if (answer.response === 0) autoUpdater.quitAndInstall();
  });

  autoUpdater.checkForUpdates().catch((error) => {
    console.warn('[Updater] Could not check for updates:', error.message);
  });
}

async function start() {
  const choice = await dialog.showMessageBox({
    type: 'question',
    title: 'Start SOS Tools',
    message: 'How would you like to run SOS Tools?',
    detail: 'Local Desktop is private to this PC. Central Server allows other devices on your network to connect to this computer.',
    buttons: ['Local Desktop', 'Central Server (LAN)', 'Cancel'],
    defaultId: 0,
    cancelId: 2,
    noLink: true
  });
  if (choice.response === 2) {
    app.quit();
    return;
  }

  const dataDir = path.join(app.getPath('userData'), 'data');
  migrateLegacyData(dataDir);
  process.env.SOS_TOOLS_DATA_DIR = dataDir;
  const port = await reservePort();
  process.env.PORT = String(port);
  process.env.HOST = choice.response === 1 ? '0.0.0.0' : '127.0.0.1';

  // Electron bundles Node; the Express app serves local files without internet.
  require('../server.js');
  const localUrl = 'http://127.0.0.1:' + port;
  await waitForServer(localUrl + '/');

  mainWindow = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 960,
    minHeight: 650,
    title: 'SOS Tools',
    autoHideMenuBar: true,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true }
  });
  mainWindow.loadURL(localUrl);
  mainWindow.on('closed', () => { mainWindow = null; });

  if (choice.response === 1) {
    const os = require('os');
    const addresses = Object.values(os.networkInterfaces()).flat()
      .filter((item) => item && item.family === 'IPv4' && !item.internal)
      .map((item) => item.address);
    const urls = [...new Set(addresses)].map((address) => 'http://' + address + ':' + port);
    dialog.showMessageBox({
      type: 'info',
      title: 'SOS Tools Central Server',
      message: 'SOS Tools may be reachable from other devices on your local network.',
      detail: 'This PC: ' + localUrl + '\n\nNetwork address(es):\n' +
        (urls.join('\n') || 'No local network address detected') +
        '\n\nAllow Windows Firewall access only on trusted private networks.',
      buttons: ['OK']
    });
  }
}

app.whenReady().then(async () => {
  await start();
  if (mainWindow) configureAutoUpdates();
}).catch((error) => {
  dialog.showErrorBox('SOS Tools could not start', error.message);
  app.quit();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
