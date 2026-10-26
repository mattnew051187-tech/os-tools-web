const { app, BrowserWindow, dialog } = require('electron');
const http = require('http');
const net = require('net');
const path = require('path');
const fs = require('fs');

let mainWindow;
let selectedPort = 3000;

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
  fs.mkdirSync(dataDir, { recursive: true });
  selectedPort = await reservePort();
  process.env.SOS_TOOLS_DATA_DIR = dataDir;
  process.env.PORT = String(selectedPort);
  process.env.HOST = choice.response === 1 ? '0.0.0.0' : '127.0.0.1';

  // Run the existing Express app in this process; Electron bundles its Node runtime.
  require('../server.js');
  const localUrl = `http://127.0.0.1:${selectedPort}`;
  await waitForServer(`${localUrl}/`);

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
    const addresses = Object.values(os.networkInterfaces()).flat().filter((item) => item && item.family === 'IPv4' && !item.internal).map((item) => item.address);
    const urls = [...new Set(addresses)].map((address) => `http://${address}:${selectedPort}`);
    dialog.showMessageBox({
      type: 'info',
      title: 'SOS Tools Central Server',
      message: 'SOS Tools is available on this PC and may be reachable from other devices on your local network.',
      detail: `This PC: ${localUrl}\n\nNetwork address(es):\n${urls.join('\n') || 'No local network address detected'}\n\nIf other devices cannot connect, allow SOS Tools through Windows Firewall for private networks.`,
      buttons: ['OK']
    });
  }
}

app.whenReady().then(() => start().catch((error) => {
  dialog.showErrorBox('SOS Tools could not start', `${error.message}\n\nIf another service is interfering, close it and try again.`);
  app.quit();
}));

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
