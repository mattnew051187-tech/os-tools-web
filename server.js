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
const TAB_IDS = ['phone-tablets', 'gamepad-tester', 'game-library', 'product-search'];
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
  return { ...defaultSettings(), ...stored };
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
    return { tabId, type: 'html', content: fs.readFileSync(builtinPath, 'utf8'), from: builtinPath };
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
  const cookies = req.headers.cookie || '';
  const match = cookies.split(/;\s*/).find((c) => c.startsWith(SESSION_COOKIE + '='));
  if (!match) return null;
  const token = decodeURIComponent(match.split('=')[1]);
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
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(APP_ROOT, 'public')));

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

function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production' || process.env.FORCE_SECURE_COOKIES === '1',
    maxAge: SESSION_MAX_AGE_MS,
  };
}

// ---- Auth ----
// Simple brute-force protection: block an IP after repeated failed logins.
const failedLogins = new Map(); // ip -> { count, firstTs }
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILURES = 8;

function clientIp(req) {
  const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || req.socket.remoteAddress || 'unknown';
}

function isLoginBlocked(ip) {
  const rec = failedLogins.get(ip);
  if (!rec) return false;
  if (Date.now() - rec.firstTs > LOGIN_WINDOW_MS) {
    failedLogins.delete(ip);
    return false;
  }
  return rec.count >= LOGIN_MAX_FAILURES;
}

function recordLoginFailure(ip) {
  const rec = failedLogins.get(ip);
  if (!rec || Date.now() - rec.firstTs > LOGIN_WINDOW_MS) {
    failedLogins.set(ip, { count: 1, firstTs: Date.now() });
  } else {
    rec.count++;
  }
}

app.post('/api/login', (req, res) => {
  const ip = clientIp(req);
  if (isLoginBlocked(ip)) {
    logActivity('unknown', 'login-rate-limited', `Blocked further login attempts from ${ip}`);
    return res.json({ ok: false, error: 'Too many failed attempts — try again in 15 minutes.' });
  }
  const { username, password } = req.body || {};
  const users = loadUsers();
  const user = findUser(users, username);
  if (!user || !verifySecret(password, user.password)) {
    recordLoginFailure(ip);
    logActivity(username || 'unknown', 'login-failed', `Incorrect username or password (from ${ip})`);
    return res.json({ ok: false, error: 'Incorrect username or password.' });
  }
  failedLogins.delete(ip);
  const token = createSession(user);
  res.cookie(SESSION_COOKIE, token, cookieOptions());
  logActivity(user.username, 'login', 'Signed in with password');
  res.json({ ok: true, user: publicUser(user) });
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
  if (!verifySecret((req.body || {}).pin, user.pin)) {
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
  if (!verifySecret(currentPassword, user.password)) {
    return res.json({ ok: false, error: 'Current password is incorrect.' });
  }
  if (!newPassword || String(newPassword).length < 5) {
    return res.json({ ok: false, error: 'New password must be at least 5 characters.' });
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
  if (!password || String(password).length < 5) {
    return res.json({ ok: false, error: 'Password must be at least 5 characters.' });
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
  if (user.username.toLowerCase() === 'admin') {
    return res.json({ ok: false, error: 'The master Admin account cannot be deleted.' });
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
    if (String(password).length < 5) return res.json({ ok: false, error: 'Password must be at least 5 characters.' });
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
  for (const id of TAB_IDS) modules[id] = resolveModule(settings, id);
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

app.get('/healthz', (req, res) => res.json({ ok: true, version: APP_VERSION }));

// ---- Boot ----
(async () => {
  const mode = await store.init();
  if (loadUsers().length === 0) {
    // First run: create the master account (Admin / 12345, PIN 1234).
    saveUsers([
      {
        username: 'Admin',
        role: 'admin',
        createdAt: new Date().toISOString(),
        password: makeCredentials('12345'),
        pin: makeCredentials('1234'),
        mustChangePassword: true,
        theme: 'yellow',
      },
    ]);
  }
  loadSettings();
  logActivity('system', 'server-start', `SOS Tools Web v${APP_VERSION} started (store: ${mode})`);

  app.listen(PORT, () => {
    console.log(`SOS Tools Web v${APP_VERSION} running on http://localhost:${PORT}`);
  });
})();
