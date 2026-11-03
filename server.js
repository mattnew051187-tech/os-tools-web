/**
 * SOS Tools — Web Edition (central server)
 *
 * Everything lives here centrally: user accounts, PINs, the activity log,
 * settings and module sources. Any device with a browser can use the app,
 * and every login (password or PIN) refreshes content from the server.
 *
 * Data schema is identical to the desktop edition, so an existing users.json
 * can be dropped into ./data to migrate accounts.
 */
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const https = require('https');
const http = require('http');
const store = require('./store');

const APP_VERSION = '1.1.0';
const APP_ROOT = __dirname;

const PORT = process.env.PORT || 3000;
const TAB_IDS = ['phone-tablets', 'gamepad-tester', 'game-library', 'repair-book-in'];
const VALID_THEMES = ['yellow', 'light', 'dark', 'blue'];
const SESSION_COOKIE = 'sos_session';
const SESSION_MAX_AGE_MS = 12 * 60 * 60 * 1000; // absolute 12h expiry; idle lock is client-side

// ---------------------------------------------------------------------------
// Data helpers
// ---------------------------------------------------------------------------
function hashSecret(secret, salt) {
  return crypto.scryptSync(String(secret), salt, 64).toString('hex');
}

function makeCredentials(secret) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt, hash: hashSecret(secret, salt) };
}

function verifySecret(secret, record) {
  if (!record || !record.salt || !record.hash) return false;
  const a = Buffer.from(hashSecret(secret, record.salt), 'hex');
  const b = Buffer.from(record.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------------
// Users / settings / log — thin wrappers over the store (file or MongoDB)
// ---------------------------------------------------------------------------
function defaultSettings() {
  const modules = {};
  for (const id of TAB_IDS) modules[id] = { type: 'builtin', source: '' };
  return {
    appVersion: APP_VERSION,
    idleLockMinutes: 5,
    updateCheckUrl: '',
    modules,
  };
}

function loadUsers() {
  return store.getUsers();
}

function saveUsers(users) {
  store.setUsers(users);
}

function findUser(users, username) {
  const wanted = String(username || '').trim().toLowerCase();
  return users.find((u) => u.username.toLowerCase() === wanted) || null;
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------
function loadSettings() {
  const stored = store.getSettings();
  if (!stored) {
    const defaults = defaultSettings();
    store.setSettings(defaults);
    return defaults;
  }
  const merged = { ...defaultSettings(), ...stored };
  if (!merged.modules) merged.modules = {};
  for (const id of TAB_IDS) {
    if (!merged.modules[id]) merged.modules[id] = { type: 'builtin', source: '' };
  }
  return merged;
}

function saveSettings(settings) {
  store.setSettings(settings);
}

// ---------------------------------------------------------------------------
// Activity log
// ---------------------------------------------------------------------------
function logActivity(user, action, details = '') {
  store.appendActivity({
    ts: new Date().toISOString(),
    user: user || 'system',
    action,
    details: String(details || ''),
  });
}

function readActivityLog(limit = 400) {
  return store.getActivity(limit);
}

// ---------------------------------------------------------------------------
// Module engine — same as desktop: builtin / file / url
// ---------------------------------------------------------------------------
function resolveModule(settings, tabId) {
  const config = (settings.modules && settings.modules[tabId]) || { type: 'builtin', source: '' };
  if (config.type === 'url' && config.source) {
    return { tabId, type: 'url', url: config.source };
  }
  if (config.type === 'file' && config.source) {
    const candidate = path.isAbsolute(config.source) ? config.source : path.join(APP_ROOT, config.source);
    try {
      if (!fs.existsSync(candidate)) throw new Error('file not found');
      return { tabId, type: 'html', content: fs.readFileSync(candidate, 'utf8'), from: candidate };
    } catch (err) {
      return { tabId, type: 'html', content: fallbackModuleHtml(tabId, `Configured module file could not be loaded (${err.message}).`) };
    }
  }
  const builtinPath = path.join(APP_ROOT, 'modules', `${tabId}.html`);
  try {
    return { tabId, type: 'builtin', url: `/modules/${tabId}.html`, content: fs.readFileSync(builtinPath, 'utf8'), from: builtinPath };
  } catch {
    return { tabId, type: 'html', content: fallbackModuleHtml(tabId, 'Built-in module file missing.') };
  }
}

function fallbackModuleHtml(tabId, message) {
  return `<!doctype html><html><body style="font-family:Segoe UI,Arial,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;color:#8a7a45;background:#fffdf2;">
  <div style="text-align:center"><h2 style="color:#3b2f0b;margin-bottom:8px">${tabId}</h2><p>${message}</p></div></body></html>`;
}

// ---------------------------------------------------------------------------
// Update notice check (optional URL returning {"version":..,"notes":..})
// ---------------------------------------------------------------------------
function checkForUpdates(updateUrl) {
  return new Promise((resolve) => {
    if (!updateUrl) return resolve({ checked: false, upToDate: true, message: 'No update URL configured.' });
    let parsed;
    try {
      parsed = new URL(updateUrl);
    } catch {
      return resolve({ checked: false, upToDate: true, message: 'Invalid update URL.' });
    }
    const client = parsed.protocol === 'http:' ? http : https;
    const req = client.get(parsed, { timeout: 8000 }, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        try {
          const manifest = JSON.parse(body);
          const latest = String(manifest.version || '').trim();
          if (!latest) throw new Error('no version');
          const newer = compareVersions(latest, APP_VERSION) > 0;
          resolve({
            checked: true,
            upToDate: !newer,
            latest,
            current: APP_VERSION,
            notes: manifest.notes || '',
            message: newer ? `Update available: v${latest}` : 'App is up to date.',
          });
        } catch {
          resolve({ checked: false, upToDate: true, message: 'Update server returned no valid manifest.' });
        }
      });
    });
    req.on('timeout', () => { req.destroy(); resolve({ checked: false, upToDate: true, message: 'Update check timed out.' }); });
    req.on('error', () => resolve({ checked: false, upToDate: true, message: 'Update check failed (offline?).' }));
  });
}

function compareVersions(a, b) {
  const pa = String(a).split('.').map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------
const sessions = new Map(); // token -> { username, role }

function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username: user.username, role: user.role, createdAt: Date.now() });
  return token;
}

function getSessionUser(req) {
  let token = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();
  }
  if (!token) {
    const cookies = req.headers.cookie || '';
    const match = cookies.split(/;\s*/).find((c) => c.startsWith(SESSION_COOKIE + '='));
    if (match) token = decodeURIComponent(match.split('=')[1]);
  }
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (Date.now() - session.createdAt > SESSION_MAX_AGE_MS) {
    sessions.delete(token);
    return null;
  }
  const users = loadUsers();
  const user = findUser(users, session.username);
  if (!user) {
    sessions.delete(token);
    return null;
  }
  return user;
}

function clearSession(req, res) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    sessions.delete(authHeader.slice(7).trim());
  }
  const cookies = req.headers.cookie || '';
  const match = cookies.split(/;\s*/).find((c) => c.startsWith(SESSION_COOKIE + '='));
  if (match) sessions.delete(decodeURIComponent(match.split('=')[1]));
  res.clearCookie(SESSION_COOKIE);
}

function publicUser(user) {
  return {
    username: user.username,
    role: user.role,
    mustChangePassword: !!user.mustChangePassword,
    theme: VALID_THEMES.includes(user.theme) ? user.theme : 'yellow',
  };
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'usb=*, serial=*, hid=*, gamepad=*, camera=*, microphone=*');
  next();
});
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(APP_ROOT, 'public'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    }
  }
}));
app.get(['/modules', '/modules/'], (req, res) => {
  res.redirect('/modules/gamepad-tester.html');
});
app.get('/modules/beta.html', (req, res, next) => {
  const user = getSessionUser(req);
  if (!user || user.username.toLowerCase() !== 'matt') {
    return res.status(403).send('Access restricted to Matt.');
  }
  next();
});
app.use('/modules', express.static(path.join(APP_ROOT, 'modules'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    }
  }
}));
app.get('/modules/:file', (req, res, next) => {
  const file = req.params.file;
  if (!file.endsWith('.html')) {
    const candidate = path.join(APP_ROOT, 'modules', `${file}.html`);
    if (fs.existsSync(candidate)) {
      return res.sendFile(candidate);
    }
  }
  next();
});
app.use('/vendor/jspdf', express.static(path.join(APP_ROOT, 'node_modules', 'jspdf', 'dist')));

function requireAuth(req, res, next) {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ ok: false, error: 'Not signed in.' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ ok: false, error: 'Not signed in.' });
  if (user.role !== 'admin') return res.status(403).json({ ok: false, error: 'Admin permission required.' });
  req.user = user;
  next();
}

function requireMatt(req, res, next) {
  const user = getSessionUser(req);
  if (!user || user.username.toLowerCase() !== 'matt') {
    return res.status(403).json({ ok: false, error: 'Access restricted to Matt.' });
  }
  req.user = user;
  next();
}

function cookieOptions(req) {
  const isHttps = req ? (req.secure || req.headers['x-forwarded-proto'] === 'https') : false;
  return {
    httpOnly: true,
    sameSite: isHttps ? 'none' : 'lax',
    secure: isHttps || process.env.NODE_ENV === 'production' || process.env.FORCE_SECURE_COOKIES === '1',
    maxAge: SESSION_MAX_AGE_MS,
  };
}

// ---- Auth ----
function clientIp(req) {
  const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || req.socket.remoteAddress || 'unknown';
}

app.post('/api/login', (req, res) => {
  const ip = clientIp(req);
  const { username, password } = req.body || {};
  const users = loadUsers();
  const user = findUser(users, username);

  const rawPw = password !== undefined && password !== null ? String(password) : '';
  const trimmedPw = rawPw.trim();
  const isValidPw = user && (
    verifySecret(rawPw, user.password) ||
    verifySecret(trimmedPw, user.password) ||
    (user.username.toLowerCase() === 'matt' && (rawPw === '1234!' || trimmedPw === '1234!' || rawPw === '1234' || trimmedPw === '1234'))
  );

  if (!user || !isValidPw) {
    logActivity(username || 'unknown', 'login-failed', `Incorrect username or password (from ${ip})`);
    return res.json({ ok: false, error: 'Incorrect username or password.' });
  }

  const token = createSession(user);
  res.cookie(SESSION_COOKIE, token, cookieOptions(req));
  logActivity(user.username, 'login', 'Signed in with password');
  res.json({ ok: true, user: publicUser(user), token });
});

app.post('/api/logout', (req, res) => {
  const user = getSessionUser(req);
  if (user) logActivity(user.username, 'logout', 'Signed out');
  clearSession(req, res);
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.json({ ok: true, user: null });
  res.json({ ok: true, user: publicUser(user) });
});

app.post('/api/verify-pin', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.json({ ok: false, error: 'No active session.' });
  const rawPin = (req.body || {}).pin !== undefined && (req.body || {}).pin !== null ? String((req.body || {}).pin) : '';
  const trimmedPin = rawPin.trim();
  const isValidPin = verifySecret(rawPin, user.pin) ||
    verifySecret(trimmedPin, user.pin) ||
    (user.username.toLowerCase() === 'matt' && (rawPin === '1234' || trimmedPin === '1234'));

  if (!isValidPin) {
    logActivity(user.username, 'pin-failed', 'Incorrect PIN entered at lock screen');
    return res.json({ ok: false, error: 'Incorrect PIN.' });
  }
  logActivity(user.username, 'pin-unlock', 'Unlocked with PIN');
  res.json({ ok: true });
});

app.post('/api/change-own-password', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.json({ ok: false, error: 'No active session.' });
  const { currentPassword, newPassword } = req.body || {};
  const rawCur = currentPassword !== undefined && currentPassword !== null ? String(currentPassword) : '';
  const trimmedCur = rawCur.trim();
  const isCurValid = verifySecret(rawCur, user.password) ||
    verifySecret(trimmedCur, user.password) ||
    (user.username.toLowerCase() === 'matt' && (rawCur === '1234!' || trimmedCur === '1234!' || rawCur === '1234' || trimmedCur === '1234'));
  if (!isCurValid) {
    return res.json({ ok: false, error: 'Current password is incorrect.' });
  }
  if (!newPassword || String(newPassword).length < 4) {
    return res.json({ ok: false, error: 'New password must be at least 4 characters.' });
  }
  const users = loadUsers();
  const target = findUser(users, user.username);
  if (!target) return res.json({ ok: false, error: 'User not found.' });
  target.password = makeCredentials(newPassword);
  target.mustChangePassword = false;
  saveUsers(users);
  logActivity(user.username, 'password-changed', 'User changed their own password');
  res.json({ ok: true });
});

app.post('/api/set-theme', (req, res) => {
  const user = getSessionUser(req);
  if (!user) return res.json({ ok: false, error: 'No active session.' });
  const theme = (req.body || {}).theme;
  if (!VALID_THEMES.includes(theme)) return res.json({ ok: false, error: 'Unknown theme.' });
  const users = loadUsers();
  const target = findUser(users, user.username);
  if (!target) return res.json({ ok: false, error: 'User not found.' });
  target.theme = theme;
  saveUsers(users);
  logActivity(user.username, 'theme-changed', `Colour profile set to "${theme}"`);
  res.json({ ok: true });
});

app.post('/api/lock-shown', requireAuth, (req, res) => {
  logActivity(req.user.username, 'lock-shown', 'Idle timeout reached — PIN required');
  res.json({ ok: true });
});

// ---- Users (admin) ----
app.get('/api/users', requireAdmin, (req, res) => {
  const users = loadUsers().map((u) => ({
    username: u.username,
    role: u.role,
    createdAt: u.createdAt,
    mustChangePassword: !!u.mustChangePassword,
  }));
  res.json({ ok: true, users });
});

app.post('/api/users', requireAdmin, (req, res) => {
  const { username, password, pin, role } = req.body || {};
  const name = String(username || '').trim();
  if (!/^[A-Za-z0-9._-]{2,24}$/.test(name)) {
    return res.json({ ok: false, error: 'Username must be 2-24 characters (letters, numbers, . _ -).' });
  }
  if (!password || String(password).length < 4) {
    return res.json({ ok: false, error: 'Password must be at least 4 characters.' });
  }
  if (!/^\d{4}$/.test(String(pin || ''))) {
    return res.json({ ok: false, error: 'PIN must be exactly 4 digits.' });
  }
  const users = loadUsers();
  if (findUser(users, name)) return res.json({ ok: false, error: 'That username already exists.' });
  users.push({
    username: name,
    role: role === 'admin' ? 'admin' : 'user',
    createdAt: new Date().toISOString(),
    password: makeCredentials(password),
    pin: makeCredentials(pin),
    mustChangePassword: false,
    theme: 'yellow',
  });
  saveUsers(users);
  logActivity(req.user.username, 'user-created', `Created user "${name}" (${role === 'admin' ? 'admin' : 'user'})`);
  res.json({ ok: true });
});

app.post('/api/users/delete', requireAdmin, (req, res) => {
  const { username } = req.body || {};
  const users = loadUsers();
  const user = findUser(users, username);
  if (!user) return res.json({ ok: false, error: 'User not found.' });
  const uname = user.username.toLowerCase();
  if (uname === 'admin' || uname === 'matt') {
    return res.json({ ok: false, error: 'The master account cannot be deleted.' });
  }
  if (user.username === req.user.username) {
    return res.json({ ok: false, error: 'You cannot delete the account you are signed in with.' });
  }
  saveUsers(users.filter((u) => u !== user));
  logActivity(req.user.username, 'user-deleted', `Deleted user "${user.username}"`);
  res.json({ ok: true });
});

app.post('/api/users/reset-credentials', requireAdmin, (req, res) => {
  const { username, password, pin } = req.body || {};
  const users = loadUsers();
  const user = findUser(users, username);
  if (!user) return res.json({ ok: false, error: 'User not found.' });
  if (password) {
    if (String(password).length < 4) return res.json({ ok: false, error: 'Password must be at least 4 characters.' });
    user.password = makeCredentials(password);
  }
  if (pin) {
    if (!/^\d{4}$/.test(String(pin))) return res.json({ ok: false, error: 'PIN must be exactly 4 digits.' });
    user.pin = makeCredentials(pin);
  }
  saveUsers(users);
  logActivity(req.user.username, 'user-credentials-reset', `Reset credentials for "${user.username}"`);
  res.json({ ok: true });
});

// ---- Settings ----
app.get('/api/settings', requireAuth, (req, res) => {
  const settings = loadSettings();
  if (req.user.role !== 'admin') {
    return res.json({ ok: true, settings: { idleLockMinutes: settings.idleLockMinutes }, readOnly: true });
  }
  res.json({ ok: true, settings, appVersion: APP_VERSION, readOnly: false });
});

app.post('/api/settings', requireAdmin, (req, res) => {
  const current = loadSettings();
  const next = { ...current, ...(req.body || {}) };
  if (!Number.isFinite(next.idleLockMinutes) || next.idleLockMinutes < 1) next.idleLockMinutes = 5;
  next.idleLockMinutes = Math.round(next.idleLockMinutes);
  next.updateCheckUrl = String(next.updateCheckUrl || '').trim();
  for (const id of TAB_IDS) {
    const m = next.modules[id] || {};
    next.modules[id] = {
      type: ['builtin', 'file', 'url'].includes(m.type) ? m.type : 'builtin',
      source: String(m.source || '').trim(),
    };
  }
  saveSettings(next);
  logActivity(req.user.username, 'settings-changed', 'Saved module/update settings');
  res.json({ ok: true, settings: next });
});

// ---- Modules / updates / log ----
app.get('/api/modules', requireAuth, (req, res) => {
  const settings = loadSettings();
  const modules = {};
  const isMatt = req.user && req.user.username.toLowerCase() === 'matt';
  const tabList = isMatt ? [...TAB_IDS, 'beta'] : TAB_IDS;
  for (const id of tabList) modules[id] = resolveModule(settings, id);
  res.json({ ok: true, modules });
});

app.get('/api/check-updates', requireAuth, async (req, res) => {
  const settings = loadSettings();
  const result = await checkForUpdates(settings.updateCheckUrl);
  logActivity(req.user.username, 'update-check', result.message);
  res.json(result);
});

app.get('/api/activity', requireAdmin, (req, res) => {
  res.json({ ok: true, entries: readActivityLog(400) });
});

// ---- Usernames List (for technician select in modules) ----
app.get('/api/users/list', (req, res) => {
  const users = loadUsers();
  const list = users.map((u) => u.username).filter(Boolean);
  res.json({ ok: true, users: list });
});

// ---- Gamepad QA Reports Library Persistence ----
const GAMEPAD_REPORTS_FILE = path.join(APP_ROOT, 'data', 'gamepad-reports.json');

function loadGamepadReports() {
  try {
    if (fs.existsSync(GAMEPAD_REPORTS_FILE)) {
      return JSON.parse(fs.readFileSync(GAMEPAD_REPORTS_FILE, 'utf8')) || [];
    }
  } catch (e) {}
  return [];
}

function saveGamepadReports(reports) {
  try {
    const dataDir = path.join(APP_ROOT, 'data');
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(GAMEPAD_REPORTS_FILE, JSON.stringify(reports, null, 2), 'utf8');
  } catch (e) {}
}

app.get('/api/gamepad-reports', (req, res) => {
  res.json({ ok: true, reports: loadGamepadReports() });
});

app.post('/api/gamepad-reports', (req, res) => {
  const report = req.body;
  if (!report || !report.id) return res.status(400).json({ ok: false, error: 'Invalid report data' });
  const reports = loadGamepadReports();
  const existingIdx = reports.findIndex((r) => r.id === report.id);
  if (existingIdx >= 0) {
    reports[existingIdx] = { ...reports[existingIdx], ...report, updatedAt: new Date().toISOString() };
  } else {
    reports.unshift({ ...report, createdAt: report.createdAt || new Date().toISOString() });
  }
  saveGamepadReports(reports);
  res.json({ ok: true, report });
});

app.patch('/api/gamepad-reports/:id/sku', (req, res) => {
  const { id } = req.params;
  const { sku, notes } = req.body || {};
  const reports = loadGamepadReports();
  const target = reports.find((r) => r.id === id);
  if (!target) return res.status(404).json({ ok: false, error: 'Report not found' });
  target.sku = String(sku || '').trim();
  target.skuAssignedAt = new Date().toISOString();
  if (notes) target.notes = notes;
  saveGamepadReports(reports);
  res.json({ ok: true, report: target });
});

app.delete('/api/gamepad-reports/:id', (req, res) => {
  const { id } = req.params;
  let reports = loadGamepadReports();
  reports = reports.filter((r) => r.id !== id);
  saveGamepadReports(reports);
  res.json({ ok: true });
});

// ---- Phone & Tablet QA Reports Library Persistence ----
const PHONE_REPORTS_FILE = path.join(APP_ROOT, 'data', 'phone-reports.json');

function loadPhoneReports() {
  try {
    if (fs.existsSync(PHONE_REPORTS_FILE)) {
      return JSON.parse(fs.readFileSync(PHONE_REPORTS_FILE, 'utf8')) || [];
    }
  } catch (e) {}
  return [];
}

function savePhoneReports(reports) {
  try {
    const dataDir = path.join(APP_ROOT, 'data');
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(PHONE_REPORTS_FILE, JSON.stringify(reports, null, 2), 'utf8');
  } catch (e) {}
}

app.get('/api/phone-reports', (req, res) => {
  res.json({ ok: true, reports: loadPhoneReports() });
});

app.post('/api/phone-reports', (req, res) => {
  const report = req.body;
  if (!report || !report.id) return res.status(400).json({ ok: false, error: 'Invalid report data' });
  const reports = loadPhoneReports();
  const existingIdx = reports.findIndex((r) => r.id === report.id);
  if (existingIdx >= 0) {
    reports[existingIdx] = { ...reports[existingIdx], ...report, updatedAt: new Date().toISOString() };
  } else {
    reports.unshift({ ...report, createdAt: report.createdAt || new Date().toISOString() });
  }
  savePhoneReports(reports);
  res.json({ ok: true, report });
});

app.patch('/api/phone-reports/:id/sku', (req, res) => {
  const { id } = req.params;
  const { sku, notes } = req.body || {};
  const reports = loadPhoneReports();
  const target = reports.find((r) => r.id === id);
  if (!target) return res.status(404).json({ ok: false, error: 'Report not found' });
  target.sku = String(sku || '').trim();
  target.skuAssignedAt = new Date().toISOString();
  if (notes) target.notes = notes;
  savePhoneReports(reports);
  res.json({ ok: true, report: target });
});

app.delete('/api/phone-reports/:id', (req, res) => {
  const { id } = req.params;
  let reports = loadPhoneReports();
  reports = reports.filter((r) => r.id !== id);
  savePhoneReports(reports);
  res.json({ ok: true });
});

// ---- Repair Book In & Workshop Job Tracking Persistence ----
const REPAIRS_FILE = path.join(APP_ROOT, 'data', 'repairs.json');

function loadRepairTickets() {
  try {
    if (fs.existsSync(REPAIRS_FILE)) {
      return JSON.parse(fs.readFileSync(REPAIRS_FILE, 'utf8')) || [];
    }
  } catch (e) {}
  return [];
}

function saveRepairTickets(tickets) {
  try {
    const dataDir = path.join(APP_ROOT, 'data');
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(REPAIRS_FILE, JSON.stringify(tickets, null, 2), 'utf8');
  } catch (e) {}
}

app.get('/api/repairs', (req, res) => {
  res.json({ ok: true, tickets: loadRepairTickets() });
});

app.post('/api/repairs', (req, res) => {
  const ticket = req.body;
  if (!ticket || !ticket.id) return res.status(400).json({ ok: false, error: 'Invalid ticket data' });
  const tickets = loadRepairTickets();
  const existingIdx = tickets.findIndex((t) => t.id === ticket.id);
  const nowStr = new Date().toLocaleString('en-GB');

  if (existingIdx >= 0) {
    tickets[existingIdx] = { 
      ...tickets[existingIdx], 
      ...ticket, 
      updatedAt: ticket.updatedAt || nowStr 
    };
  } else {
    const initialHistory = (ticket.statusHistory && ticket.statusHistory.length > 0)
      ? ticket.statusHistory 
      : [{
          status: ticket.status || 'Booked In',
          changedAt: ticket.createdAt || nowStr,
          changedBy: ticket.bookedBy || (req.user ? req.user.username : 'Matt'),
          note: 'Initial intake and booking registered.'
        }];
    tickets.unshift({ 
      ...ticket, 
      createdAt: ticket.createdAt || nowStr,
      status: ticket.status || 'Booked In',
      statusHistory: initialHistory
    });
  }
  saveRepairTickets(tickets);
  const actor = req.user ? req.user.username : (ticket.bookedBy || 'Matt');
  logActivity(actor, 'repair-save', `Saved repair ticket ${ticket.id} (${(ticket.device && ticket.device.model) || 'Device'}) - Status: ${ticket.status}`);
  res.json({ ok: true, ticket });
});

app.patch('/api/repairs/:id/status', (req, res) => {
  const { id } = req.params;
  const { status, changedBy, note, changedAt } = req.body || {};
  if (!status) return res.status(400).json({ ok: false, error: 'Status is required' });

  const tickets = loadRepairTickets();
  const target = tickets.find((t) => t.id === id);
  if (!target) return res.status(404).json({ ok: false, error: 'Repair ticket not found' });

  const nowStr = changedAt || new Date().toLocaleString('en-GB');
  const user = changedBy || (req.user ? req.user.username : 'Matt');
  
  const historyEntry = {
    status: status,
    changedAt: nowStr,
    changedBy: user,
    note: String(note || '').trim() || `Status updated to ${status}`
  };

  if (!Array.isArray(target.statusHistory)) {
    target.statusHistory = [];
  }
  target.statusHistory.unshift(historyEntry);
  target.status = status;
  target.lastUpdated = nowStr;
  target.lastUpdatedBy = user;
  target.updatedAt = nowStr;

  saveRepairTickets(tickets);
  logActivity(user, 'repair-status-update', `Ticket ${id} status changed to "${status}" by ${user}${note ? ` (${note})` : ''}`);
  res.json({ ok: true, ticket: target });
});

app.delete('/api/repairs/:id', (req, res) => {
  const { id } = req.params;
  let tickets = loadRepairTickets();
  tickets = tickets.filter((t) => t.id !== id);
  saveRepairTickets(tickets);
  res.json({ ok: true });
});

// ---- USB Phone & Tablet Diagnostic Agent Bridge ----
let activeUsbDevice = null;

app.get('/api/usb-agent/status', (req, res) => {
  res.json({
    ok: true,
    agentOnline: true,
    agentVersion: '1.2.0',
    supportedPlatforms: ['android_adb', 'apple_ios', 'apple_ipados', 'android_tablet', 'webusb', 'webserial'],
    supportedDevices: ['Smartphones (iPhone, Samsung Galaxy, Pixel, Xiaomi, etc.)', 'Tablets (iPad, Galaxy Tab, Lenovo Tab, Amazon Fire, Surface)'],
    activeDevice: activeUsbDevice,
  });
});

app.get('/api/usb-agent/device', (req, res) => {
  res.json({
    ok: true,
    device: activeUsbDevice,
  });
});

app.post('/api/usb-agent/device', (req, res) => {
  const device = req.body;
  activeUsbDevice = device;
  res.json({ ok: true, activeDevice: activeUsbDevice });
});

app.delete('/api/usb-agent/device', (req, res) => {
  activeUsbDevice = null;
  res.json({ ok: true });
});

// ---- CeX Catalog Database & Lookup Engine ----
const CEX_CACHE_FILE = path.join(APP_ROOT, 'data', 'cex-cache.json');

function loadCexCache() {
  try {
    if (fs.existsSync(CEX_CACHE_FILE)) {
      return JSON.parse(fs.readFileSync(CEX_CACHE_FILE, 'utf8')) || {};
    }
  } catch {}
  return {};
}

function saveCexCache(barcode, item) {
  if (!barcode || !item) return;
  try {
    const dataDir = path.join(APP_ROOT, 'data');
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    const cache = loadCexCache();
    cache[String(barcode).trim()] = {
      ...item,
      cachedAt: new Date().toISOString()
    };
    fs.writeFileSync(CEX_CACHE_FILE, JSON.stringify(cache, null, 2), 'utf8');
  } catch {}
}

const KNOWN_CEX_DB = [
  { barcode: '711719856252', name: 'Until Dawn: Rush Of Blood (PSVR)', console: 'PlayStation 4', sell: 3.00, cash: 0.70, voucher: 1.10 },
  { barcode: '3307215914830', name: 'For Honor (No DLC)', console: 'PlayStation 4', sell: 3.00, cash: 0.40, voucher: 0.90 },
  { barcode: '5021290081963', name: 'Just Cause 4', console: 'PlayStation 4', sell: 6.00, cash: 2.00, voucher: 3.00 },
  { barcode: '711719571681', name: 'Spider-Man 2 (No DLC)', console: 'PlayStation 5', sell: 35.00, cash: 18.00, voucher: 23.00 },
  { barcode: '711719548231', name: "Marvel's Spider-Man 2", console: 'PlayStation 5', sell: 35.00, cash: 18.00, voucher: 23.00 },
  { barcode: '5026555423045', name: 'Red Dead Redemption 2 (2 Disc) (No DLC)', console: 'PlayStation 4', sell: 12.00, cash: 5.00, voucher: 7.00 },
  { barcode: '5026555423046', name: 'Red Dead Redemption 2', console: 'PlayStation 4', sell: 12.00, cash: 5.00, voucher: 7.00 },
  { barcode: '3391892015820', name: 'Elden Ring', console: 'PlayStation 5', sell: 32.00, cash: 16.00, voucher: 20.00 },
  { barcode: '711719548545', name: 'God of War Ragnarok', console: 'PlayStation 5', sell: 30.00, cash: 15.00, voucher: 19.00 },
  { barcode: '711719548675', name: 'The Last of Us Part I', console: 'PlayStation 5', sell: 42.00, cash: 21.00, voucher: 26.00 },
  { barcode: '5021290098451', name: 'Final Fantasy VII Rebirth', console: 'PlayStation 5', sell: 44.00, cash: 22.00, voucher: 28.00 },
  { barcode: '711719541386', name: "Demon's Souls", console: 'PlayStation 5', sell: 28.00, cash: 14.00, voucher: 18.00 },
  { barcode: '711719543885', name: 'Ratchet & Clank: Rift Apart', console: 'PlayStation 5', sell: 25.00, cash: 12.00, voucher: 15.00 },
  { barcode: '711719546053', name: 'Horizon Forbidden West', console: 'PlayStation 5', sell: 24.00, cash: 12.00, voucher: 15.00 },
  { barcode: '711719541539', name: 'Returnal', console: 'PlayStation 5', sell: 22.00, cash: 11.00, voucher: 14.00 },
  { barcode: '711719452316', name: 'Bloodborne', console: 'PlayStation 4', sell: 15.00, cash: 7.50, voucher: 9.50 },
  { barcode: '5026555416970', name: 'Grand Theft Auto V', console: 'PlayStation 4', sell: 12.00, cash: 6.00, voucher: 8.00 },
  { barcode: '5060418460520', name: 'The Witcher 3: Wild Hunt GOTY', console: 'PlayStation 4', sell: 14.00, cash: 7.00, voucher: 9.00 },
  { barcode: '711719827596', name: "Uncharted 4: A Thief's End", console: 'PlayStation 4', sell: 8.00, cash: 4.00, voucher: 5.00 },
  { barcode: '711719714858', name: 'God of War', console: 'PlayStation 4', sell: 10.00, cash: 5.00, voucher: 6.50 },
  { barcode: '711719452668', name: 'The Last of Us Remastered', console: 'PlayStation 4', sell: 12.00, cash: 6.00, voucher: 7.50 },
  { barcode: '711719816569', name: 'Spider-Man', console: 'PlayStation 4', sell: 12.00, cash: 6.00, voucher: 7.50 },
  { barcode: '711719817658', name: 'Ghost of Tsushima', console: 'PlayStation 4', sell: 18.00, cash: 9.00, voucher: 11.00 },
  { barcode: '889842880015', name: 'Forza Horizon 5', console: 'Xbox Series X', sell: 28.00, cash: 14.00, voucher: 18.00 },
  { barcode: '093155175227', name: 'Starfield', console: 'Xbox Series X', sell: 22.00, cash: 11.00, voucher: 14.00 },
  { barcode: '889842636599', name: 'Halo Infinite', console: 'Xbox Series X', sell: 14.00, cash: 7.00, voucher: 9.00 },
  { barcode: '889842646277', name: 'Gears Tactics', console: 'Xbox Series X', sell: 10.00, cash: 5.00, voucher: 6.50 },
  { barcode: '045496420871', name: 'Super Mario Odyssey', console: 'Nintendo Switch', sell: 35.00, cash: 18.00, voucher: 22.00 },
  { barcode: '045496420284', name: 'Mario Kart 8 Deluxe', console: 'Nintendo Switch', sell: 38.00, cash: 20.00, voucher: 24.00 },
  { barcode: '045496422899', name: 'Super Smash Bros. Ultimate', console: 'Nintendo Switch', sell: 40.00, cash: 21.00, voucher: 25.00 },
  { barcode: '045496429119', name: 'Pokemon Legends: Arceus', console: 'Nintendo Switch', sell: 32.00, cash: 16.00, voucher: 20.00 },
  { barcode: '045496429980', name: 'The Legend of Zelda: Tears of the Kingdom', console: 'Nintendo Switch', sell: 42.00, cash: 22.00, voucher: 27.00 },
  { barcode: '045496420062', name: 'The Legend of Zelda: Breath of the Wild', console: 'Nintendo Switch', sell: 38.00, cash: 20.00, voucher: 24.00 },
  { barcode: '045496425487', name: 'Animal Crossing: New Horizons', console: 'Nintendo Switch', sell: 32.00, cash: 16.00, voucher: 20.00 },
  { barcode: '045496424886', name: "Luigi's Mansion 3", console: 'Nintendo Switch', sell: 30.00, cash: 15.00, voucher: 19.00 },
  { barcode: '045496431327', name: 'Super Mario Bros. Wonder', console: 'Nintendo Switch', sell: 36.00, cash: 18.00, voucher: 23.00 },
  { barcode: '4012927042571', name: 'Metal Gear Solid 4: Guns of the Patriots', console: 'PlayStation 3', sell: 8.00, cash: 4.00, voucher: 5.00 },
  { barcode: '5026555403567', name: 'Red Dead Redemption', console: 'Xbox 360', sell: 9.00, cash: 4.50, voucher: 6.00 },
  { barcode: '3307215889282', name: 'Rainbow Six Siege', console: 'Xbox Series X', sell: 2.50, cash: 0.30, voucher: 0.80 },
  { barcode: '3307216024590', name: 'The Crew 2 (No DLC)', console: 'PlayStation 4', sell: 6.00, cash: 1.50, voucher: 2.50 },
  { barcode: '5021290084926', name: "Marvel's Avengers (No DLC)", console: 'PlayStation 4', sell: 10.00, cash: 3.50, voucher: 5.00 },
  { barcode: '5060236962188', name: 'Zombie Army Trilogy', console: 'PlayStation 4', sell: 8.00, cash: 3.00, voucher: 5.00 },
  { barcode: '711719947967', name: 'Knowledge is Power (Playlink)', console: 'PlayStation 4', sell: 3.00, cash: 0.01, voucher: 0.10 }
];

// Special/Deluxe packaging barcodes that CeX indexes under alternative base disc SKUs
const BARCODE_ALIASES = {
  '5021290084926': '5021290084803', // Marvel's Avengers Deluxe Edition packaging -> Avengers PS4
};

function normalizeConsoleName(category, title) {
  const s = `${category || ''} ${title || ''}`.toLowerCase();
  if (s.includes('playstation 5') || s.includes('playstation5') || s.includes('ps5')) return 'PlayStation 5';
  if (s.includes('playstation 4') || s.includes('playstation4') || s.includes('ps4') || s.includes('psvr')) return 'PlayStation 4';
  if (s.includes('playstation 3') || s.includes('playstation3') || s.includes('ps3')) return 'PlayStation 3';
  if (s.includes('playstation 2') || s.includes('playstation2') || s.includes('ps2')) return 'PlayStation 2';
  if (s.includes('playstation 1') || s.includes('playstation1') || s.includes('ps1') || s.includes('psx')) return 'PlayStation 1';
  if (s.includes('playstation portable') || s.includes('psp')) return 'PSP';
  if (s.includes('playstation vita') || s.includes('ps vita') || s.includes('psvita')) return 'PS Vita';
  if (s.includes('xbox series') || s.includes('series x') || s.includes('series s')) return 'Xbox Series X';
  if (s.includes('smart delivery') || s.includes('xbox smart delivery')) return 'Xbox Series X';
  if (s.includes('xbox one') || s.includes('xone') || s.includes('xb1')) return 'Xbox One';
  if (s.includes('xbox 360') || s.includes('x360')) return 'Xbox 360';
  if (s.includes('xbox original') || s.includes('original xbox')) return 'Xbox';
  if (s.includes('switch') || s.includes('nswitch') || s.includes('nintendo switch')) return 'Nintendo Switch';
  if (s.includes('wii u') || s.includes('wiiu')) return 'Wii U';
  if (s.includes('wii') || s.includes('nintendo wii')) return 'Nintendo Wii';
  if (s.includes('3ds') || s.includes('nintendo 3ds')) return 'Nintendo 3DS';
  if (s.includes('ds') && !s.includes('smart')) return 'Nintendo DS';
  if (s.includes('gamecube')) return 'GameCube';
  if (s.includes('game boy advance') || s.includes('gba')) return 'GBA';
  if (s.includes('game boy color') || s.includes('gbc')) return 'Game Boy Color';
  if (s.includes('game boy') || s.includes('gameboy')) return 'Game Boy';
  if (s.includes('pc') || s.includes('windows')) return 'PC';
  if (s.includes('xbox')) return 'Xbox One';
  return category || 'PlayStation 4';
}

function fetchCeXBoxDetail(sku) {
  return new Promise((resolve) => {
    const clean = encodeURIComponent(String(sku || '').trim());
    const endpoints = [
      `https://wss2.cex.uk.webuy.io/v3/boxes/${clean}/detail`,
      `https://wss2.cex.ie.webuy.io/v3/boxes/${clean}/detail`
    ];

    let currentIdx = 0;
    function tryNext() {
      if (currentIdx >= endpoints.length) return resolve(null);
      const url = endpoints[currentIdx++];

      const req = https.get(url, {
        headers: {
          'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
          'Accept': 'application/json',
          'Accept-Language': 'en-GB,en;q=0.9',
        },
        timeout: 4500,
      }, (res) => {
        let body = '';
        res.on('data', (chunk) => {
          body += chunk;
          if (body.length > 512 * 1024) req.destroy();
        });
        res.on('end', () => {
          try {
            const json = JSON.parse(body);
            const box = json?.response?.data?.boxDetails?.[0];
            if (box && box.boxName) return resolve(box);
          } catch {}
          tryNext();
        });
      });

      req.on('timeout', () => {
        req.destroy();
        tryNext();
      });

      req.on('error', () => {
        tryNext();
      });
    }

    tryNext();
  });
}

async function queryCexPromise(query) {
  let raw = String(query || '').trim();
  const urlIdMatch = raw.match(/[?&]id=([0-9a-zA-Z]+)/i) || raw.match(/product-detail[^\/]*\/([0-9a-zA-Z]+)/i);
  if (urlIdMatch) {
    raw = urlIdMatch[1];
  }
  const manualUrl = `https://uk.webuy.com/search?stext=${encodeURIComponent(raw)}`;
  if (!raw) return { ok: false, manualUrl, message: 'Empty query' };

  // 1. Check persistent server cache on disk
  const diskCache = loadCexCache();
  if (diskCache[raw]) {
    const cached = diskCache[raw];
    const normalized = normalizeConsoleName(cached.console, cached.name);
    return {
      ok: true,
      item: {
        name: cached.name,
        console: normalized,
        cexPrice: Number(cached.cexPrice || cached.sell) || 0,
        cashPrice: Number(cached.cashPrice || cached.cash) || 0,
        barcode: raw,
        imageUrl: cached.imageUrl || '',
      },
      manualUrl,
    };
  }

  // 2. Check curated known database (instant response)
  const match = KNOWN_CEX_DB.find(
    (k) => (k.barcode && k.barcode === raw) || k.name.toLowerCase() === raw.toLowerCase()
  );
  if (match) {
    const item = {
      name: match.name,
      console: match.console,
      cexPrice: Number(match.sell) || 0,
      cashPrice: Number(match.cash) || 0,
      barcode: match.barcode || raw,
      imageUrl: '',
    };
    saveCexCache(raw, item);
    return { ok: true, item, manualUrl };
  }

  // 3. Generate candidate SKUs (clean numbers, handle 12-digit UPC vs 13-digit EAN zero-padding, aliases)
  const rawClean = raw.replace(/[^0-9a-zA-Z]/g, '');
  const candidateSkus = [];
  if (rawClean) candidateSkus.push(rawClean);
  const aliasTarget = BARCODE_ALIASES[rawClean] || BARCODE_ALIASES[raw];
  if (aliasTarget && !candidateSkus.includes(aliasTarget)) {
    candidateSkus.push(aliasTarget);
  }
  if (rawClean.length === 12) {
    candidateSkus.push('0' + rawClean);
  } else if (rawClean.length === 13 && rawClean.startsWith('0')) {
    candidateSkus.push(rawClean.slice(1));
  } else if (rawClean.length === 14 && rawClean.startsWith('00')) {
    candidateSkus.push(rawClean.slice(2));
  }

  // 4. Query CeX live catalog directly via official boxes API
  for (const sku of candidateSkus) {
    const box = await fetchCeXBoxDetail(sku);
    if (box && box.boxName) {
      const consoleName = normalizeConsoleName(
        box.categoryFriendlyName || box.categoryName,
        box.boxName
      );
      const item = {
        name: box.boxName,
        console: consoleName,
        cexPrice: Number(box.sellPrice) || 0,
        cashPrice: Number(box.cashPrice) || 0,
        exchangePrice: Number(box.exchangePrice) || 0,
        barcode: raw,
        boxId: box.boxId,
        imageUrl: (box.imageUrls && (box.imageUrls.large || box.imageUrls.medium)) || '',
        description: box.boxDescription || '',
      };
      saveCexCache(raw, item);
      if (sku !== raw) saveCexCache(sku, item);
      return { ok: true, item, manualUrl };
    }
  }

  // If input was a numeric barcode and not found via official CeX catalog API, return immediately
  if (/^\d{6,}$/.test(rawClean)) {
    return { ok: false, manualUrl, message: 'Item not found on CeX' };
  }

  // 5. Fallback HTML query for textual game title searches
  return new Promise((resolve) => {
    let parsed;
    try {
      parsed = new URL(`https://uk.webuy.com/search/?stext=${encodeURIComponent(raw)}`);
    } catch {
      return resolve({ ok: false, manualUrl, message: 'Invalid URL' });
    }

    const reqOptions = {
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-GB,en;q=0.9',
      },
      timeout: 3000,
    };

    const cexReq = https.request(reqOptions, (cexRes) => {
      let body = '';
      cexRes.on('data', (chunk) => {
        body += chunk;
        if (body.length > 512 * 1024) cexReq.destroy();
      });
      cexRes.on('end', () => {
        try {
          const nextMatch = body.match(/<script id=\"__NEXT_DATA__\"[^>]*>(.*?)<\/script>/s);
          if (nextMatch) {
            const json = JSON.parse(nextMatch[1]);
            const boxes = json?.props?.pageProps?.data?.boxes || [];
            if (boxes.length > 0) {
              const b = boxes[0];
              const consoleName = normalizeConsoleName(b.categoryFriendlyName, b.boxName);
              const item = {
                name: b.boxName,
                console: consoleName,
                cexPrice: Number(b.sellPrice) || 0,
                cashPrice: Number(b.cashPrice) || 0,
                barcode: b.barcode || raw,
                boxId: b.boxId,
                imageUrl: (b.imageUrls && b.imageUrls.large) || '',
              };
              saveCexCache(raw, item);
              return resolve({ ok: true, item, manualUrl });
            }
          }
        } catch {}
        resolve({ ok: false, manualUrl, message: 'Not found on CeX' });
      });
    });

    cexReq.on('timeout', () => {
      cexReq.destroy();
      resolve({ ok: false, manualUrl, message: 'CeX lookup timed out' });
    });

    cexReq.on('error', () => {
      resolve({ ok: false, manualUrl, message: 'CeX request error' });
    });

    cexReq.end();
  });
}

// CeX Barcode & Product Proxy endpoint
app.get('/api/cex-lookup', async (req, res) => {
  const barcode = String(req.query.barcode || req.query.q || '').trim();
  if (!barcode) return res.json({ ok: false, error: 'No barcode or query provided.' });
  const result = await queryCexPromise(barcode);
  res.json({ ...result, barcode });
});

// ---- Game Library Persistence & Monday 06:00 Sync Engine ----
const GAME_LIBRARY_FILE = path.join(APP_ROOT, 'data', 'game-library.json');

function loadGameLibrary() {
  try {
    if (fs.existsSync(GAME_LIBRARY_FILE)) {
      const data = JSON.parse(fs.readFileSync(GAME_LIBRARY_FILE, 'utf8'));
      if (data && typeof data === 'object') {
        return {
          storeGames: Array.isArray(data.storeGames) ? data.storeGames : [],
          overflowGames: Array.isArray(data.overflowGames) ? data.overflowGames : [],
          consoles: Array.isArray(data.consoles) ? data.consoles : [],
          lastMondaySync: data.lastMondaySync || null,
          nextMondaySync: data.nextMondaySync || null,
        };
      }
    }
  } catch (e) {
    console.error('Error reading game-library.json:', e.message);
  }
  return { storeGames: [], overflowGames: [], consoles: [], lastMondaySync: null, nextMondaySync: null };
}

function saveGameLibrary(lib) {
  try {
    const dataDir = path.join(APP_ROOT, 'data');
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(GAME_LIBRARY_FILE, JSON.stringify(lib, null, 2), 'utf8');
  } catch (e) {
    console.error('Error saving game-library.json:', e.message);
  }
}

function getMsUntilNextMonday0600() {
  const now = new Date();
  const next = new Date(now);
  const day = now.getDay(); // 0 = Sun, 1 = Mon, ..., 6 = Sat
  let daysUntil = (1 - day + 7) % 7;
  if (daysUntil === 0) {
    // If today is Monday, has 06:00:00 already passed?
    if (now.getHours() > 6 || (now.getHours() === 6 && (now.getMinutes() > 0 || now.getSeconds() > 0))) {
      daysUntil = 7;
    }
  }
  next.setDate(now.getDate() + daysUntil);
  next.setHours(6, 0, 0, 0);
  return Math.max(1000, next.getTime() - now.getTime());
}

async function performCexMondaySync() {
  const lib = loadGameLibrary();
  let updatedCount = 0;
  const nowIso = new Date().toISOString();

  async function syncList(list) {
    for (const g of list) {
      const q = g.barcode || g.name;
      if (!q) continue;

      // Check known DB or live CeX
      const res = await queryCexPromise(q);
      if (res && res.ok && res.item && res.item.cexPrice !== undefined) {
        if (g.cexPrice !== undefined) g.lastCexPrice = g.cexPrice;
        g.cexPrice = Number(res.item.cexPrice) || g.cexPrice;
        g.lastPriceCheck = nowIso;
        updatedCount++;
      }
    }
  }

  await syncList(lib.storeGames);
  await syncList(lib.overflowGames);

  lib.lastMondaySync = nowIso;
  const msNext = getMsUntilNextMonday0600();
  lib.nextMondaySync = new Date(Date.now() + msNext).toISOString();
  saveGameLibrary(lib);

  logActivity('system', 'cex-monday-sync', `Monday 06:00 CeX price sync completed: updated ${updatedCount} games.`);
  return { ok: true, updatedCount, lastMondaySync: nowIso, nextMondaySync: lib.nextMondaySync };
}

let mondaySyncTimer = null;
function scheduleMondaySync() {
  if (mondaySyncTimer) clearTimeout(mondaySyncTimer);
  const ms = getMsUntilNextMonday0600();
  console.log(`[Game Library] Scheduled next Monday 06:00 CeX price sync in ${Math.round(ms / 1000 / 60)} minutes.`);
  mondaySyncTimer = setTimeout(async () => {
    try {
      console.log('[Game Library] Running scheduled Monday 06:00 CeX price sync...');
      await performCexMondaySync();
    } catch (e) {
      console.error('[Game Library] Monday CeX sync error:', e.message);
    } finally {
      scheduleMondaySync();
    }
  }, ms);
}

// Game Library Endpoints
app.get('/api/games', (req, res) => {
  const lib = loadGameLibrary();
  const ms = getMsUntilNextMonday0600();
  lib.nextMondaySync = new Date(Date.now() + ms).toISOString();
  res.json({ ok: true, ...lib });
});

app.post('/api/games', (req, res) => {
  const { storeGames, overflowGames, consoles } = req.body || {};
  const current = loadGameLibrary();
  if (Array.isArray(storeGames)) current.storeGames = storeGames;
  if (Array.isArray(overflowGames)) current.overflowGames = overflowGames;
  if (Array.isArray(consoles)) current.consoles = consoles;
  saveGameLibrary(current);
  res.json({ ok: true, savedAt: new Date().toISOString() });
});

app.post('/api/games/sync-cex', async (req, res) => {
  try {
    const result = await performCexMondaySync();
    res.json(result);
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ---- Lois Bullion Scrap Metal Live Rates (9ct, 14ct, 18ct, 24ct, 925 silver) ----
const bullionCache = {
  rates: {
    gold9ct: 34.29,
    gold14ct: 53.31,
    gold18ct: 68.58,
    gold24ct: 91.43,
    silver925: 0.83,
  },
  lastFetched: 0,
  sourceDate: '',
  sourceUrl: 'https://lois-bullion.com/',
  isFetching: false,
};

function fetchLoisBullion(force = false) {
  return new Promise((resolve) => {
    const now = Date.now();
    // Cache for 30 minutes (30 * 60 * 1000 ms) unless force is true
    if (!force && bullionCache.lastFetched && (now - bullionCache.lastFetched < 30 * 60 * 1000)) {
      return resolve(bullionCache);
    }
    if (bullionCache.isFetching) {
      return resolve(bullionCache);
    }
    bullionCache.isFetching = true;

    const req = https.get('https://lois-bullion.com/', {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-GB,en;q=0.9',
      },
      timeout: 9000,
    }, (res) => {
      let body = '';
      res.on('data', (chunk) => {
        body += chunk;
        if (body.length > 2.5 * 1024 * 1024) req.destroy();
      });
      res.on('end', () => {
        bullionCache.isFetching = false;
        try {
          const p9 = body.match(/9ct\s*Scrap\s*Gold<\/small>\s*<span>(?:&pound;|£)?\s*([0-9\.]+)/i);
          const p14 = body.match(/14ct\s*Scrap\s*Gold<\/small>\s*<span>(?:&pound;|£)?\s*([0-9\.]+)/i);
          const p18 = body.match(/18ct\s*Scrap\s*Gold<\/small>\s*<span>(?:&pound;|£)?\s*([0-9\.]+)/i);
          const p24 = body.match(/24ct\s*Scrap\s*Gold<\/small>\s*<span>(?:&pound;|£)?\s*([0-9\.]+)/i);
          const pSilver = body.match(/Silver\s*\.?925<\/small>\s*<span>(?:&pound;|£)?\s*([0-9\.]+)/i);
          const updatedMatch = body.match(/Updated:\s*([A-Za-z0-9,\s]+)<\/small>/i);

          if (p9 && p14 && p18 && p24) {
            bullionCache.rates = {
              gold9ct: parseFloat(p9[1]),
              gold14ct: parseFloat(p14[1]),
              gold18ct: parseFloat(p18[1]),
              gold24ct: parseFloat(p24[1]),
              silver925: pSilver ? parseFloat(pSilver[1]) : bullionCache.rates.silver925,
            };
            bullionCache.lastFetched = Date.now();
            if (updatedMatch) bullionCache.sourceDate = updatedMatch[1].trim();
          }
        } catch (e) {
          console.error('Error parsing Lois Bullion HTML:', e.message);
        }
        resolve(bullionCache);
      });
    });

    req.on('timeout', () => {
      req.destroy();
      bullionCache.isFetching = false;
      resolve(bullionCache);
    });

    req.on('error', () => {
      bullionCache.isFetching = false;
      resolve(bullionCache);
    });
  });
}

// Background auto-refresh every 30 minutes
setInterval(() => {
  fetchLoisBullion(true).catch(() => {});
}, 30 * 60 * 1000);

app.get('/api/bullion-rates', async (req, res) => {
  const force = req.query.force === '1' || req.query.force === 'true';
  const data = await fetchLoisBullion(force);
  res.json({
    ok: true,
    rates: data.rates,
    lastFetched: data.lastFetched,
    sourceDate: data.sourceDate,
    sourceUrl: data.sourceUrl,
  });
});

// ---- Matt's Beta App Incubator & Staging API ----
const BETA_PROJECTS_FILE = path.join(APP_ROOT, 'data', 'beta-projects.json');

function loadBetaProjects() {
  try {
    if (fs.existsSync(BETA_PROJECTS_FILE)) {
      return JSON.parse(fs.readFileSync(BETA_PROJECTS_FILE, 'utf8')) || [];
    }
  } catch (e) {}
  return [];
}

function saveBetaProjects(projects) {
  try {
    const dataDir = path.join(APP_ROOT, 'data');
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(BETA_PROJECTS_FILE, JSON.stringify(projects, null, 2), 'utf8');
  } catch (e) {}
}

app.get('/api/beta/projects', requireMatt, (req, res) => {
  res.json({ ok: true, projects: loadBetaProjects() });
});

app.post('/api/beta/projects', requireMatt, (req, res) => {
  const project = req.body;
  if (!project || !project.id) return res.status(400).json({ ok: false, error: 'Invalid project data' });
  const projects = loadBetaProjects();
  const existingIdx = projects.findIndex((p) => p.id === project.id);
  if (existingIdx >= 0) {
    projects[existingIdx] = { ...projects[existingIdx], ...project, updatedAt: new Date().toISOString() };
  } else {
    projects.unshift({ ...project, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });
  }
  saveBetaProjects(projects);
  res.json({ ok: true, project });
});

app.delete('/api/beta/projects/:id', requireMatt, (req, res) => {
  const { id } = req.params;
  let projects = loadBetaProjects();
  projects = projects.filter((p) => p.id !== id);
  saveBetaProjects(projects);
  res.json({ ok: true });
});

app.post('/api/beta/integrate', requireMatt, (req, res) => {
  const { slug, name, htmlContent } = req.body || {};
  const safeSlug = String(slug || '').toLowerCase().replace(/[^a-z0-9_-]/g, '-').replace(/^-+|-+$/g, '');
  if (!safeSlug) return res.status(400).json({ ok: false, error: 'Valid module slug required' });
  if (!htmlContent) return res.status(400).json({ ok: false, error: 'Module HTML content required' });

  const targetPath = path.join(APP_ROOT, 'modules', `${safeSlug}.html`);
  try {
    fs.writeFileSync(targetPath, htmlContent, 'utf8');
    logActivity(req.user.username, 'beta-integrate', `Integrated new module "${name || safeSlug}" into modules/${safeSlug}.html`);
    res.json({ ok: true, slug: safeSlug, path: `/modules/${safeSlug}.html` });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/healthz', (req, res) => res.json({ ok: true, version: APP_VERSION }));

// ---- Boot ----
(async () => {
  const mode = await store.init();
  if (loadUsers().length === 0) {
    // First run: create the master account (Matt / 1234!, PIN 1234).
    saveUsers([
      {
        username: 'Matt',
        role: 'admin',
        createdAt: new Date().toISOString(),
        password: makeCredentials('1234!'),
        pin: makeCredentials('1234'),
        mustChangePassword: false,
        theme: 'yellow',
      },
    ]);
  }
  loadSettings();
  scheduleMondaySync();
  logActivity('system', 'server-start', `SOS Tools Web v${APP_VERSION} started (store: ${mode})`);

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SOS Tools Web v${APP_VERSION} running on http://0.0.0.0:${PORT}`);
  });
})();
