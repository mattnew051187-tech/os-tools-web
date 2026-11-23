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
const net = require('net');
const store = require('./store');

const APP_VERSION = '1.1.0';
const APP_ROOT = __dirname;
const DATA_DIR = store.DATA_DIR || path.join(APP_ROOT, 'data');

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

function verifySecretAny(secret, record) {
  const raw = secret !== undefined && secret !== null ? String(secret) : '';
  const trimmed = raw.trim();
  if (verifySecret(raw, record)) return true;
  if (trimmed !== raw && verifySecret(trimmed, record)) return true;
  return false;
}

// ---------------------------------------------------------------------------
// First-run setup token (only populated when loadUsers().length === 0)
// ---------------------------------------------------------------------------
const SETUP_TOKEN_FILE = path.join(DATA_DIR, '.setup-token');
let initialSetupToken = null;

let setupInProgress = false;

function isSetupRequired() {
  return loadUsers().length === 0;
}

function cleanupSetupTokenFile() {
  try {
    if (fs.existsSync(SETUP_TOKEN_FILE)) {
      fs.unlinkSync(SETUP_TOKEN_FILE);
    }
  } catch {}
}

function initSetupState() {
  if (!isSetupRequired()) {
    initialSetupToken = null;
    cleanupSetupTokenFile();
    return;
  }
  const envToken = String(process.env.INITIAL_SETUP_TOKEN || '').trim();
  if (envToken.length >= 16) {
    initialSetupToken = envToken;
    cleanupSetupTokenFile();
    console.log('====================================================================');
    console.log('  FIRST-RUN SETUP REQUIRED — No user accounts exist yet.');
    console.log('  Open the SOS Tools Web UI and enter INITIAL_SETUP_TOKEN.');
    console.log('====================================================================');
  } else {
    initialSetupToken = null;
    try {
      if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
      let reusable = false;
      try {
        const st = fs.lstatSync(SETUP_TOKEN_FILE);
        if (st.isSymbolicLink()) {
          fs.unlinkSync(SETUP_TOKEN_FILE);
        } else if (st.isFile()) {
          const existing = fs.readFileSync(SETUP_TOKEN_FILE, 'utf8').trim();
          if (/^[a-f0-9]{48}$/i.test(existing)) {
            initialSetupToken = existing;
            reusable = true;
          }
        }
      } catch {}
      if (!reusable) {
        initialSetupToken = crypto.randomBytes(24).toString('hex');
        fs.writeFileSync(SETUP_TOKEN_FILE, `${initialSetupToken}\n`, { encoding: 'utf8', mode: 0o600 });
      }
      fs.chmodSync(SETUP_TOKEN_FILE, 0o600);
    } catch (err) {
      if (!initialSetupToken) initialSetupToken = crypto.randomBytes(24).toString('hex');
      console.error(`Failed to persist setup token file (${SETUP_TOKEN_FILE}):`, err.message);
    }
    console.log('====================================================================');
    console.log('  FIRST-RUN SETUP REQUIRED — No user accounts exist yet.');
    console.log(`  One-time setup token saved to: ${SETUP_TOKEN_FILE} (mode 0600)`);
    console.log('  Read that file on the server (never printed to logs) to complete setup.');
    console.log('====================================================================');
  }
}

function verifySetupToken(candidate) {
  if (!isSetupRequired() || !initialSetupToken) return false;
  const supplied = String(candidate || '').trim();
  const a = Buffer.from(supplied, 'utf8');
  const b = Buffer.from(initialSetupToken, 'utf8');
  return a.length === b.length && a.length > 0 && crypto.timingSafeEqual(a, b);
}

function normalizeIp(ip) {
  let n = String(ip || '').trim();
  if (n.startsWith('[') && n.includes(']')) {
    n = n.slice(1, n.indexOf(']'));
  }
  n = n.replace(/^::ffff:/i, '');
  const zoneIdx = n.indexOf('%');
  if (zoneIdx !== -1) n = n.slice(0, zoneIdx);
  return n.trim();
}

function isLoopbackIp(ip) {
  const n = normalizeIp(ip);
  if (!n) return false;
  if (n === '::1' || n === '0:0:0:0:0:0:0:1') return true;
  return net.isIPv4(n) && n.startsWith('127.');
}

function getConfiguredTrustedProxies() {
  const raw = String(process.env.TRUSTED_PROXIES || process.env.TRUSTED_PROXY_IPS || '');
  const set = new Set();
  for (const part of raw.split(',')) {
    const n = normalizeIp(part);
    if (n && net.isIP(n) !== 0) {
      set.add(n);
    }
  }
  return set;
}

function isTrustedProxySocket(ip) {
  const n = normalizeIp(ip);
  if (!n || net.isIP(n) === 0) return false;
  if (isLoopbackIp(n)) return true;
  return getConfiguredTrustedProxies().has(n);
}

function isRequestHttps(req) {
  if (!req) return false;
  if (req.socket && req.socket.encrypted) return true;
  const socketIp = req.socket ? req.socket.remoteAddress : '';
  if (!isTrustedProxySocket(socketIp)) return false;
  const fwdProto = String((req.headers && req.headers['x-forwarded-proto']) || '').split(',')[0].trim().toLowerCase();
  return fwdProto === 'https';
}

function isSetupHttps(req) {
  return isRequestHttps(req);
}

function isSetupTransportAllowed(req) {
  if (isSetupHttps(req)) return true;
  const socketIp = req && req.socket ? req.socket.remoteAddress : '';
  if (!isLoopbackIp(socketIp)) return false;
  const fwdProto = String((req && req.headers && req.headers['x-forwarded-proto']) || '').split(',')[0].trim().toLowerCase();
  if (fwdProto && fwdProto !== 'https') return false;
  const fwdForRaw = String((req && req.headers && req.headers['x-forwarded-for']) || '');
  const fwdHops = fwdForRaw.split(',').map((h) => h.trim()).filter(Boolean);
  if (fwdHops.some((hop) => !isLoopbackIp(hop))) return false;
  return true;
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
// Sessions & Auth Rate Limiting
// ---------------------------------------------------------------------------
const sessions = new Map(); // token -> { username, role, createdAt, pinFails }

const RATE_LIMIT_CONFIG = {
  windowMs: 15 * 60 * 1000,
  loginUserIpMax: 5,
  loginIpMax: 15,
  pinSessionMax: 3,
  pinIpMax: 12,
  setupIpMax: 5,
  maxBuckets: 10000,
};

const rateLimitBuckets = new Map(); // key -> { count, firstAt, resetAt }

function pruneRateLimits(now = Date.now()) {
  for (const [key, entry] of rateLimitBuckets.entries()) {
    if (!entry || now >= entry.resetAt) {
      rateLimitBuckets.delete(key);
    }
  }
  while (rateLimitBuckets.size >= RATE_LIMIT_CONFIG.maxBuckets) {
    const oldestKey = rateLimitBuckets.keys().next().value;
    if (oldestKey === undefined) break;
    rateLimitBuckets.delete(oldestKey);
  }
}

setInterval(() => pruneRateLimits(), 60 * 1000).unref();

function checkRateLimit(key, maxAttempts, now = Date.now()) {
  const entry = rateLimitBuckets.get(key);
  if (!entry) return { limited: false, remaining: maxAttempts, retryAfterSec: 0 };
  if (now >= entry.resetAt) {
    rateLimitBuckets.delete(key);
    return { limited: false, remaining: maxAttempts, retryAfterSec: 0 };
  }
  if (entry.count >= maxAttempts) {
    const retryAfterSec = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
    return { limited: true, remaining: 0, retryAfterSec };
  }
  return { limited: false, remaining: Math.max(0, maxAttempts - entry.count), retryAfterSec: 0 };
}

function recordRateLimitFailure(key, windowMs = RATE_LIMIT_CONFIG.windowMs, now = Date.now()) {
  pruneRateLimits(now);
  let entry = rateLimitBuckets.get(key);
  if (!entry || now >= entry.resetAt) {
    entry = { count: 0, firstAt: now, resetAt: now + windowMs };
  }
  entry.count += 1;
  // Refresh insertion order for bounded LRU eviction
  rateLimitBuckets.delete(key);
  rateLimitBuckets.set(key, entry);
  return {
    count: entry.count,
    retryAfterSec: Math.max(1, Math.ceil((entry.resetAt - now) / 1000)),
  };
}

function clearRateLimit(key) {
  rateLimitBuckets.delete(key);
}

function sendRateLimited(res, retryAfterSec, message, extraPayload = {}) {
  const seconds = Math.max(1, Math.ceil(retryAfterSec || 1));
  res.setHeader('Retry-After', String(seconds));
  return res.status(429).json({
    ok: false,
    error: message,
    retryAfter: seconds,
    ...extraPayload,
  });
}

function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username: user.username, role: user.role, createdAt: Date.now(), pinFails: 0 });
  return token;
}

function extractSessionToken(req) {
  let token = null;
  const authHeader = req && req.headers ? req.headers.authorization : null;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();
  }
  if (!token) {
    const cookies = (req && req.headers && req.headers.cookie) || '';
    const match = cookies.split(/;\s*/).find((c) => c.startsWith(SESSION_COOKIE + '='));
    if (match) token = decodeURIComponent(match.split('=')[1]);
  }
  return token;
}

function getSessionInfo(req) {
  const token = extractSessionToken(req);
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
  return { token, session, user };
}

function getSessionUser(req) {
  const info = getSessionInfo(req);
  return info ? info.user : null;
}

function revokeUserSessions(username) {
  const wanted = String(username || '').trim().toLowerCase();
  if (!wanted) return 0;
  let revoked = 0;
  for (const [token, session] of sessions.entries()) {
    if (session && String(session.username || '').trim().toLowerCase() === wanted) {
      sessions.delete(token);
      revoked++;
    }
  }
  return revoked;
}

function clearCookieOptions(req) {
  const opts = cookieOptions(req);
  delete opts.maxAge;
  return opts;
}

function clearSession(req, res) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    sessions.delete(authHeader.slice(7).trim());
  }
  const cookies = req.headers.cookie || '';
  const match = cookies.split(/;\s*/).find((c) => c.startsWith(SESSION_COOKIE + '='));
  if (match) sessions.delete(decodeURIComponent(match.split('=')[1]));
  res.clearCookie(SESSION_COOKIE, clearCookieOptions(req));
}

function publicUser(user) {
  return {
    username: user.username,
    role: user.role,
    mustChangePassword: !!user.mustChangePassword,
    theme: VALID_THEMES.includes(user.theme) ? user.theme : 'yellow',
  };
}

const CSRF_SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const CSRF_BLOCKED_FORM_CONTENT_TYPES = new Set([
  'application/x-www-form-urlencoded',
  'multipart/form-data',
  'text/plain',
]);

function getExpectedRequestHost(req) {
  const socketIp = req && req.socket ? req.socket.remoteAddress : '';
  const rawFwdHost = isTrustedProxySocket(socketIp) && req.headers && req.headers['x-forwarded-host'];
  const rawHost = rawFwdHost || (req.headers && req.headers.host) || '';
  return String(rawHost).split(',')[0].trim().toLowerCase();
}

function csrfProtection(req, res, next) {
  const method = String(req.method || 'GET').toUpperCase();
  if (CSRF_SAFE_METHODS.has(method)) {
    return next();
  }

  // Requests carrying an explicit Authorization Bearer token cannot be triggered by cross-site forms/cookies
  const authHeader = String((req.headers && req.headers.authorization) || '').trim();
  if (authHeader.startsWith('Bearer ') && authHeader.slice(7).trim().length > 0) {
    return next();
  }

  const secFetchSite = String((req.headers && req.headers['sec-fetch-site']) || '').trim().toLowerCase();
  if (secFetchSite && secFetchSite !== 'same-origin' && secFetchSite !== 'none') {
    return res.status(403).json({ ok: false, error: 'Cross-site request blocked (CSRF protection).' });
  }

  const contentType = String((req.headers && req.headers['content-type']) || '').split(';')[0].trim().toLowerCase();
  if (CSRF_BLOCKED_FORM_CONTENT_TYPES.has(contentType)) {
    return res.status(403).json({ ok: false, error: 'Cross-site request blocked (CSRF protection).' });
  }

  const expectedHost = getExpectedRequestHost(req);
  const origin = req.headers && req.headers.origin;
  if (origin !== undefined) {
    const trimmedOrigin = String(origin).trim();
    if (!trimmedOrigin || trimmedOrigin.toLowerCase() === 'null') {
      return res.status(403).json({ ok: false, error: 'Cross-site request blocked (CSRF protection).' });
    }
    let originHost = '';
    try {
      originHost = new URL(trimmedOrigin).host.toLowerCase();
    } catch {
      originHost = '';
    }
    if (!expectedHost || !originHost || originHost !== expectedHost) {
      return res.status(403).json({ ok: false, error: 'Cross-site request blocked (CSRF protection).' });
    }
    return next();
  }

  const referer = req.headers && req.headers.referer;
  if (referer !== undefined) {
    let refererHost = '';
    try {
      refererHost = new URL(String(referer).trim()).host.toLowerCase();
    } catch {
      refererHost = '';
    }
    if (!expectedHost || !refererHost || refererHost !== expectedHost) {
      return res.status(403).json({ ok: false, error: 'Cross-site request blocked (CSRF protection).' });
    }
  }

  return next();
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();
app.set('trust proxy', (ip) => isTrustedProxySocket(normalizeIp(ip)));
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'usb=*, serial=*, hid=*, gamepad=*, camera=*, microphone=*');
  next();
});
app.use('/api', csrfProtection);
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
  if (!user) {
    return res.status(401).send('Authentication required.');
  }
  if (user.username.toLowerCase() !== 'matt') {
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
  const info = getSessionInfo(req);
  if (!info) return res.status(401).json({ ok: false, error: 'Not signed in.' });
  req.user = info.user;
  req.session = info.session;
  req.sessionToken = info.token;
  next();
}

function requireAdmin(req, res, next) {
  const info = getSessionInfo(req);
  if (!info) return res.status(401).json({ ok: false, error: 'Not signed in.' });
  if (info.user.role !== 'admin') return res.status(403).json({ ok: false, error: 'Admin permission required.' });
  req.user = info.user;
  req.session = info.session;
  req.sessionToken = info.token;
  next();
}

function requireMatt(req, res, next) {
  const info = getSessionInfo(req);
  if (!info) {
    return res.status(401).json({ ok: false, error: 'Not signed in.' });
  }
  if (info.user.username.toLowerCase() !== 'matt') {
    return res.status(403).json({ ok: false, error: 'Access restricted to Matt.' });
  }
  req.user = info.user;
  req.session = info.session;
  req.sessionToken = info.token;
  next();
}

function cookieOptions(req) {
  const isHttps = isRequestHttps(req);
  return {
    httpOnly: true,
    sameSite: isHttps ? 'none' : 'lax',
    secure: isHttps || process.env.FORCE_SECURE_COOKIES === '1',
    maxAge: SESSION_MAX_AGE_MS,
  };
}

// ---- Auth ----
function clientIp(req) {
  const rawSocket = normalizeIp(req && req.socket ? req.socket.remoteAddress : '');
  if (!rawSocket) return 'unknown';
  if (!isTrustedProxySocket(rawSocket)) {
    return rawSocket;
  }
  const xffRaw = String((req && req.headers && req.headers['x-forwarded-for']) || '');
  if (!xffRaw) return rawSocket;
  const hops = xffRaw.split(',').map((h) => normalizeIp(h)).filter(Boolean);
  let resolved = rawSocket;
  for (let i = hops.length - 1; i >= 0; i--) {
    const hop = hops[i];
    if (net.isIP(hop) === 0) {
      return resolved;
    }
    if (!isTrustedProxySocket(hop)) {
      return hop;
    }
    resolved = hop;
  }
  return resolved;
}

app.get('/api/setup/status', (req, res) => {
  const setupRequired = isSetupRequired();
  const setupAllowed = isSetupTransportAllowed(req);
  res.json({
    ok: true,
    setupRequired,
    setupAllowed,
    httpsRequired: !setupAllowed,
  });
});

app.post('/api/setup', (req, res) => {
  const ip = clientIp(req);
  if (setupInProgress) {
    return res.status(409).json({ ok: false, error: 'Initial setup is already in progress.' });
  }
  setupInProgress = true;
  try {
    if (!isSetupRequired()) {
      initialSetupToken = null;
      cleanupSetupTokenFile();
      return res.status(403).json({ ok: false, error: 'Initial setup has already been completed.' });
    }
    if (!isSetupTransportAllowed(req)) {
      logActivity('system', 'setup-blocked-http', `Blocked insecure plain-HTTP first-run setup attempt (from ${ip})`);
      return res.status(403).json({
        ok: false,
        error: 'First-run setup requires HTTPS (or direct localhost access). Open the app over HTTPS before submitting the setup token, administrator password, and PIN.',
      });
    }
    const setupRateKey = `setup-ip:${ip}`;
    const setupLimitState = checkRateLimit(setupRateKey, RATE_LIMIT_CONFIG.setupIpMax);
    if (setupLimitState.limited) {
      logActivity('system', 'setup-rate-limited', `Rate-limited first-run setup attempt (from ${ip})`);
      return sendRateLimited(
        res,
        setupLimitState.retryAfterSec,
        'Too many failed setup attempts. Please wait and try again later.'
      );
    }

    const { setupToken, username, password, pin } = req.body || {};
    if (!verifySetupToken(setupToken)) {
      const failState = recordRateLimitFailure(setupRateKey);
      logActivity('system', 'setup-failed', `Invalid first-run setup token attempt (from ${ip})`);
      if (failState.count >= RATE_LIMIT_CONFIG.setupIpMax) {
        return sendRateLimited(
          res,
          failState.retryAfterSec,
          'Too many failed setup attempts. Please wait and try again later.'
        );
      }
      return res.status(403).json({ ok: false, error: 'Invalid or missing setup token.' });
    }
    const name = String(username || '').trim();
    if (!/^[A-Za-z0-9._-]{2,24}$/.test(name)) {
      return res.status(400).json({ ok: false, error: 'Username must be 2-24 characters (letters, numbers, . _ -).' });
    }
    const pw = password !== undefined && password !== null ? String(password) : '';
    if (pw.length < 8) {
      return res.status(400).json({ ok: false, error: 'Administrator password must be at least 8 characters.' });
    }
    const pinStr = String(pin || '').trim();
    if (!/^\d{4}$/.test(pinStr)) {
      return res.status(400).json({ ok: false, error: 'PIN must be exactly 4 digits.' });
    }
    if (!isSetupRequired()) {
      initialSetupToken = null;
      return res.status(403).json({ ok: false, error: 'Initial setup has already been completed.' });
    }

    const adminUser = {
      username: name,
      role: 'admin',
      createdAt: new Date().toISOString(),
      password: makeCredentials(pw),
      pin: makeCredentials(pinStr),
      mustChangePassword: false,
      theme: 'yellow',
    };
    saveUsers([adminUser]);
    initialSetupToken = null;
    cleanupSetupTokenFile();
    clearRateLimit(setupRateKey);
    logActivity(name, 'setup-complete', `Initial administrator "${name}" created via first-run setup (from ${ip})`);

    const token = createSession(adminUser);
    res.cookie(SESSION_COOKIE, token, cookieOptions(req));
    return res.json({ ok: true, user: publicUser(adminUser), token });
  } finally {
    setupInProgress = false;
  }
});

app.post('/api/login', (req, res) => {
  const ip = clientIp(req);
  if (isSetupRequired()) {
    return res.json({ ok: false, error: 'Initial administrator setup is required before signing in.' });
  }
  const { username, password } = req.body || {};
  const unameKey = String(username || '').trim().toLowerCase() || '__empty__';
  const ipKey = `login-ip:${ip}`;
  const userIpKey = `login-user-ip:${ip}:${unameKey}`;

  const ipLimit = checkRateLimit(ipKey, RATE_LIMIT_CONFIG.loginIpMax);
  const userIpLimit = checkRateLimit(userIpKey, RATE_LIMIT_CONFIG.loginUserIpMax);
  if (ipLimit.limited || userIpLimit.limited) {
    const retryAfterSec = Math.max(ipLimit.retryAfterSec, userIpLimit.retryAfterSec);
    logActivity('system', 'login-rate-limited', `Rate-limited login attempt (from ${ip})`);
    return sendRateLimited(
      res,
      retryAfterSec,
      'Too many failed sign-in attempts. Please wait and try again later.'
    );
  }

  const users = loadUsers();
  const user = findUser(users, username);
  const isValidPw = user && verifySecretAny(password, user.password);

  if (!user || !isValidPw) {
    const ipFail = recordRateLimitFailure(ipKey);
    const userIpFail = recordRateLimitFailure(userIpKey);
    logActivity(username || 'unknown', 'login-failed', `Incorrect username or password (from ${ip})`);
    if (ipFail.count >= RATE_LIMIT_CONFIG.loginIpMax || userIpFail.count >= RATE_LIMIT_CONFIG.loginUserIpMax) {
      const retryAfterSec = Math.max(ipFail.retryAfterSec, userIpFail.retryAfterSec);
      return sendRateLimited(
        res,
        retryAfterSec,
        'Too many failed sign-in attempts. Please wait and try again later.'
      );
    }
    return res.json({ ok: false, error: 'Incorrect username or password.' });
  }

  clearRateLimit(userIpKey);
  const token = createSession(user);
  res.cookie(SESSION_COOKIE, token, cookieOptions(req));
  logActivity(user.username, 'login', `Signed in with password (cryptographically verified, from ${ip})`);
  res.json({ ok: true, user: publicUser(user), token });
});

app.post('/api/logout', (req, res) => {
  const user = getSessionUser(req);
  if (user) logActivity(user.username, 'logout', 'Signed out');
  clearSession(req, res);
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const setupRequired = isSetupRequired();
  const user = getSessionUser(req);
  if (!user) return res.json({ ok: true, user: null, setupRequired });
  res.json({ ok: true, user: publicUser(user), setupRequired: false });
});

app.post('/api/verify-pin', requireAuth, (req, res) => {
  const user = req.user;
  const session = req.session;
  const ip = clientIp(req);
  const pinIpKey = `pin-ip:${ip}`;

  const pinIpLimit = checkRateLimit(pinIpKey, RATE_LIMIT_CONFIG.pinIpMax);
  if (pinIpLimit.limited || (session && session.pinFails >= RATE_LIMIT_CONFIG.pinSessionMax)) {
    if (req.sessionToken) sessions.delete(req.sessionToken);
    res.clearCookie(SESSION_COOKIE, clearCookieOptions(req));
    const retryAfterSec = pinIpLimit.limited
      ? pinIpLimit.retryAfterSec
      : Math.ceil(RATE_LIMIT_CONFIG.windowMs / 1000);
    return sendRateLimited(
      res,
      retryAfterSec,
      'Too many incorrect PIN attempts — session invalidated. Please sign in again.',
      { sessionRevoked: true }
    );
  }

  const isValidPin = verifySecretAny((req.body || {}).pin, user.pin);

  if (!isValidPin) {
    if (session) session.pinFails = (session.pinFails || 0) + 1;
    const ipFail = recordRateLimitFailure(pinIpKey);
    const sessionFails = session ? session.pinFails : RATE_LIMIT_CONFIG.pinSessionMax;
    if (sessionFails >= RATE_LIMIT_CONFIG.pinSessionMax || ipFail.count >= RATE_LIMIT_CONFIG.pinIpMax) {
      if (req.sessionToken) sessions.delete(req.sessionToken);
      res.clearCookie(SESSION_COOKIE, clearCookieOptions(req));
      logActivity(user.username, 'pin-locked', `Session invalidated after repeated incorrect PIN attempts (from ${ip})`);
      return sendRateLimited(
        res,
        ipFail.retryAfterSec,
        'Too many incorrect PIN attempts — session invalidated. Please sign in again.',
        { sessionRevoked: true }
      );
    }
    logActivity(user.username, 'pin-failed', `Incorrect PIN entered at lock screen (${sessionFails}/${RATE_LIMIT_CONFIG.pinSessionMax}, from ${ip})`);
    return res.json({
      ok: false,
      error: 'Incorrect PIN.',
      attemptsRemaining: RATE_LIMIT_CONFIG.pinSessionMax - sessionFails,
    });
  }

  if (session) session.pinFails = 0;
  logActivity(user.username, 'pin-unlock', 'Unlocked with PIN (cryptographically verified)');
  res.json({ ok: true });
});

app.post('/api/change-own-password', requireAuth, (req, res) => {
  const user = req.user;
  const { currentPassword, newPassword } = req.body || {};
  if (!verifySecretAny(currentPassword, user.password)) {
    return res.json({ ok: false, error: 'Current password is incorrect.' });
  }
  if (!newPassword || String(newPassword).length < 8) {
    return res.json({ ok: false, error: 'New password must be at least 8 characters.' });
  }
  const users = loadUsers();
  const target = findUser(users, user.username);
  if (!target) return res.json({ ok: false, error: 'User not found.' });
  target.password = makeCredentials(newPassword);
  target.mustChangePassword = false;
  saveUsers(users);
  const revokedCount = revokeUserSessions(target.username);
  res.clearCookie(SESSION_COOKIE, clearCookieOptions(req));
  logActivity(user.username, 'password-changed', `User changed their own password (${revokedCount} session(s) invalidated)`);
  res.json({ ok: true, reauthRequired: true, sessionsRevoked: revokedCount });
});

app.post('/api/change-own-pin', requireAuth, (req, res) => {
  const user = req.user;
  const { currentPassword, newPin } = req.body || {};
  if (!verifySecretAny(currentPassword, user.password)) {
    return res.json({ ok: false, error: 'Current password is incorrect.' });
  }
  const pinStr = String(newPin || '').trim();
  if (!/^\d{4}$/.test(pinStr)) {
    return res.json({ ok: false, error: 'PIN must be exactly 4 digits.' });
  }
  const users = loadUsers();
  const target = findUser(users, user.username);
  if (!target) return res.json({ ok: false, error: 'User not found.' });
  target.pin = makeCredentials(pinStr);
  saveUsers(users);
  logActivity(user.username, 'pin-changed', 'User changed their own PIN');
  res.json({ ok: true });
});

app.post('/api/set-theme', requireAuth, (req, res) => {
  const user = req.user;
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
  if (!password || String(password).length < 8) {
    return res.json({ ok: false, error: 'Password must be at least 8 characters.' });
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
  revokeUserSessions(user.username);
  logActivity(req.user.username, 'user-deleted', `Deleted user "${user.username}"`);
  res.json({ ok: true });
});

app.post('/api/users/reset-credentials', requireAdmin, (req, res) => {
  const { username, password, pin } = req.body || {};
  if (!password && !pin) {
    return res.json({ ok: false, error: 'Provide a new password and/or 4-digit PIN.' });
  }
  const users = loadUsers();
  const user = findUser(users, username);
  if (!user) return res.json({ ok: false, error: 'User not found.' });
  const passwordWasReset = Boolean(password);
  if (password) {
    if (String(password).length < 8) return res.json({ ok: false, error: 'Password must be at least 8 characters.' });
    user.password = makeCredentials(password);
    user.mustChangePassword = false;
  }
  if (pin) {
    if (!/^\d{4}$/.test(String(pin))) return res.json({ ok: false, error: 'PIN must be exactly 4 digits.' });
    user.pin = makeCredentials(pin);
  }
  saveUsers(users);
  let revokedCount = 0;
  const resetSelf = user.username.toLowerCase() === req.user.username.toLowerCase();
  if (passwordWasReset) {
    revokedCount = revokeUserSessions(user.username);
    if (resetSelf) {
      res.clearCookie(SESSION_COOKIE, clearCookieOptions(req));
    }
  }
  logActivity(
    req.user.username,
    'user-credentials-reset',
    `Reset credentials for "${user.username}"${passwordWasReset ? ` (${revokedCount} session(s) invalidated)` : ''}`
  );
  res.json({
    ok: true,
    sessionsRevoked: revokedCount,
    reauthRequired: passwordWasReset && resetSelf,
  });
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
app.get('/api/users/list', requireAuth, (req, res) => {
  const users = loadUsers();
  const list = users.map((u) => u.username).filter(Boolean);
  res.json({ ok: true, users: list });
});

// ---- Gamepad QA Reports Library Persistence ----
const GAMEPAD_REPORTS_FILE = path.join(DATA_DIR, 'gamepad-reports.json');

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
    const dataDir = DATA_DIR;
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(GAMEPAD_REPORTS_FILE, JSON.stringify(reports, null, 2), 'utf8');
  } catch (e) {}
}

app.get('/api/gamepad-reports', requireAuth, (req, res) => {
  res.json({ ok: true, reports: loadGamepadReports() });
});

app.post('/api/gamepad-reports', requireAuth, (req, res) => {
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

app.patch('/api/gamepad-reports/:id/sku', requireAuth, (req, res) => {
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

app.delete('/api/gamepad-reports/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  let reports = loadGamepadReports();
  reports = reports.filter((r) => r.id !== id);
  saveGamepadReports(reports);
  res.json({ ok: true });
});

// ---- Phone & Tablet QA Reports Library Persistence ----
const PHONE_REPORTS_FILE = path.join(DATA_DIR, 'phone-reports.json');

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
    const dataDir = DATA_DIR;
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(PHONE_REPORTS_FILE, JSON.stringify(reports, null, 2), 'utf8');
  } catch (e) {}
}

app.get('/api/phone-reports', requireAuth, (req, res) => {
  res.json({ ok: true, reports: loadPhoneReports() });
});

app.post('/api/phone-reports', requireAuth, (req, res) => {
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

app.patch('/api/phone-reports/:id/sku', requireAuth, (req, res) => {
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

app.delete('/api/phone-reports/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  let reports = loadPhoneReports();
  reports = reports.filter((r) => r.id !== id);
  savePhoneReports(reports);
  res.json({ ok: true });
});

// ---- Repair Book In & Workshop Job Tracking Persistence ----
const REPAIRS_FILE = path.join(DATA_DIR, 'repairs.json');

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
    const dataDir = DATA_DIR;
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(REPAIRS_FILE, JSON.stringify(tickets, null, 2), 'utf8');
  } catch (e) {}
}

app.get('/api/repairs', requireAuth, (req, res) => {
  res.json({ ok: true, tickets: loadRepairTickets() });
});

app.post('/api/repairs', requireAuth, (req, res) => {
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
          changedBy: ticket.bookedBy || req.user.username,
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
  const actor = req.user.username;
  logActivity(actor, 'repair-save', `Saved repair ticket ${ticket.id} (${(ticket.device && ticket.device.model) || 'Device'}) - Status: ${ticket.status}`);
  res.json({ ok: true, ticket });
});

app.patch('/api/repairs/:id/status', requireAuth, (req, res) => {
  const { id } = req.params;
  const { status, changedBy, note, changedAt } = req.body || {};
  if (!status) return res.status(400).json({ ok: false, error: 'Status is required' });

  const tickets = loadRepairTickets();
  const target = tickets.find((t) => t.id === id);
  if (!target) return res.status(404).json({ ok: false, error: 'Repair ticket not found' });

  const nowStr = changedAt || new Date().toLocaleString('en-GB');
  const user = changedBy || req.user.username;
  
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

app.delete('/api/repairs/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  let tickets = loadRepairTickets();
  tickets = tickets.filter((t) => t.id !== id);
  saveRepairTickets(tickets);
  res.json({ ok: true });
});

// ---- USB Phone & Tablet Diagnostic Agent Bridge ----
let activeUsbDevice = null;

app.get('/api/usb-agent/status', requireAuth, (req, res) => {
  res.json({
    ok: true,
    agentOnline: true,
    agentVersion: '1.2.0',
    supportedPlatforms: ['android_adb', 'apple_ios', 'apple_ipados', 'android_tablet', 'webusb', 'webserial'],
    supportedDevices: ['Smartphones (iPhone, Samsung Galaxy, Pixel, Xiaomi, etc.)', 'Tablets (iPad, Galaxy Tab, Lenovo Tab, Amazon Fire, Surface)'],
    activeDevice: activeUsbDevice,
  });
});

app.get('/api/usb-agent/device', requireAuth, (req, res) => {
  res.json({
    ok: true,
    device: activeUsbDevice,
  });
});

app.post('/api/usb-agent/device', requireAuth, (req, res) => {
  const device = req.body;
  if (!device || typeof device !== 'object' || Array.isArray(device)) {
    return res.status(400).json({ ok: false, error: 'Valid device payload required.' });
  }
  activeUsbDevice = device;
  res.json({ ok: true, activeDevice: activeUsbDevice });
});

app.delete('/api/usb-agent/device', requireAuth, (req, res) => {
  activeUsbDevice = null;
  res.json({ ok: true });
});

// ---- CeX Catalog Database & Lookup Engine ----
const CEX_CACHE_FILE = path.join(DATA_DIR, 'cex-cache.json');

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
    const dataDir = DATA_DIR;
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
            const box = (json && json.response && json.response.data && json.response.data.boxDetails && json.response.data.boxDetails[0]) || null;
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

function searchCexAlgolia(query, hitsPerPage = 6) {
  return new Promise((resolve) => {
    const q = String(query || '').trim();
    if (!q) return resolve([]);
    const postData = JSON.stringify({ query: q, hitsPerPage });
    const req = https.request('https://search.webuy.io/1/indexes/prod_cex_uk/query', {
      method: 'POST',
      headers: {
        'X-Algolia-Application-Id': 'LNNFEEWZVA',
        'X-Algolia-API-Key': 'bf79f2b6699e60a18ae330a1248b452c',
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      },
      timeout: 4500,
    }, (res) => {
      let d = '';
      res.on('data', (c) => { d += c; if (d.length > 512 * 1024) req.destroy(); });
      res.on('end', () => {
        try {
          const json = JSON.parse(d);
          resolve(Array.isArray(json.hits) ? json.hits : []);
        } catch {
          resolve([]);
        }
      });
    });
    req.on('timeout', () => { req.destroy(); resolve([]); });
    req.on('error', () => resolve([]));
    req.write(postData);
    req.end();
  });
}

function reverseBarcodeToTitle(barcode) {
  return new Promise((resolve) => {
    const b = String(barcode || '').trim();
    if (!b || b.length < 6) return resolve(null);
    const req = https.get('https://html.duckduckgo.com/html/?q=' + encodeURIComponent(b), {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-GB,en;q=0.9',
      },
      timeout: 4000,
    }, (res) => {
      let d = '';
      res.on('data', (c) => { d += c; if (d.length > 1024 * 1024) req.destroy(); });
      res.on('end', () => {
        try {
          const matches = [...d.matchAll(/class=\"result__title\"[\s\S]*?<a[^>]*>([\s\S]*?)<\/a>/g)]
            .map((m) => m[1].replace(/<[^>]+>/g, '').replace(/&#x27;/g, "'").replace(/&amp;/g, '&').trim());
          for (const m of matches) {
            let clean = m
              .replace(/\|.*$/i, '')
              .replace(/-.*(eBay|Amazon|CEX|Game|PriceSpy|Argos).*$/i, '')
              .replace(new RegExp(b, 'g'), '')
              .replace(/\b(EAN|UPC|Barcode|Deluxe Edition|Steelbook|Special Edition)\b/gi, '')
              .replace(/\s+/g, ' ')
              .trim();
            if (clean.length > 3) return resolve(clean);
          }
        } catch {}
        resolve(null);
      });
    });
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
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
        exchangePrice: Number(cached.exchangePrice || cached.voucher) || 0,
        barcode: raw,
        boxId: cached.boxId || raw,
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
      exchangePrice: Number(match.voucher) || 0,
      barcode: match.barcode || raw,
      boxId: match.barcode || raw,
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

  // 4. Query CeX live catalog directly via official boxes detail API
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

  // 5. Query CeX live Algolia index via search.webuy.io proxy
  const hits = await searchCexAlgolia(rawClean || raw, 6);
  if (hits && hits.length > 0) {
    const top = hits[0];
    const consoleName = normalizeConsoleName(top.categoryFriendlyName || top.categoryName, top.boxName);
    const item = {
      name: top.boxName,
      console: consoleName,
      cexPrice: Number(top.sellPrice) || 0,
      cashPrice: Number(top.cashPriceCalculated || top.cashBuyPrice) || 0,
      exchangePrice: Number(top.exchangePriceCalculated || top.exchangePrice) || 0,
      barcode: raw,
      boxId: top.boxId || top.objectID,
      imageUrl: (top.imageUrls && (top.imageUrls.large || top.imageUrls.medium)) || '',
    };
    saveCexCache(raw, item);
    if (top.boxId && top.boxId !== raw) {
      BARCODE_ALIASES[rawClean] = top.boxId;
      saveCexCache(top.boxId, item);
    }
    return { ok: true, item, manualUrl, hits };
  }

  // 6. Reverse Barcode Lookup Fallback: if barcode was not found on CeX directly,
  // query product name from web and check CeX index with discovered title!
  if (/^\d{6,}$/.test(rawClean)) {
    const discoveredTitle = await reverseBarcodeToTitle(rawClean);
    if (discoveredTitle) {
      const titleHits = await searchCexAlgolia(discoveredTitle, 4);
      if (titleHits && titleHits.length > 0) {
        const top = titleHits[0];
        const consoleName = normalizeConsoleName(top.categoryFriendlyName || top.categoryName, top.boxName);
        const item = {
          name: top.boxName,
          console: consoleName,
          cexPrice: Number(top.sellPrice) || 0,
          cashPrice: Number(top.cashPriceCalculated || top.cashBuyPrice) || 0,
          exchangePrice: Number(top.exchangePriceCalculated || top.exchangePrice) || 0,
          barcode: raw,
          boxId: top.boxId || top.objectID,
          imageUrl: (top.imageUrls && (top.imageUrls.large || top.imageUrls.medium)) || '',
        };
        saveCexCache(raw, item);
        BARCODE_ALIASES[rawClean] = top.boxId;
        return { ok: true, item, manualUrl, hits: titleHits };
      }
    }
  }

  return { ok: false, manualUrl, message: 'Item not found on CeX' };
}

// CeX Barcode & Product Proxy endpoint
app.get('/api/cex-lookup', requireAuth, async (req, res) => {
  const barcode = String(req.query.barcode || req.query.q || '').trim();
  if (!barcode) return res.json({ ok: false, error: 'No barcode or query provided.' });
  const result = await queryCexPromise(barcode);
  res.json({ ...result, barcode });
});

// ---- Game Library Persistence & Monday 06:00 Sync Engine ----
const GAME_LIBRARY_FILE = path.join(DATA_DIR, 'game-library.json');

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
    const dataDir = DATA_DIR;
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
app.get('/api/games', requireAuth, (req, res) => {
  const lib = loadGameLibrary();
  const ms = getMsUntilNextMonday0600();
  lib.nextMondaySync = new Date(Date.now() + ms).toISOString();
  res.json({ ok: true, ...lib });
});

app.post('/api/games', requireAuth, (req, res) => {
  const { storeGames, overflowGames, consoles } = req.body || {};
  const current = loadGameLibrary();
  if (Array.isArray(storeGames)) current.storeGames = storeGames;
  if (Array.isArray(overflowGames)) current.overflowGames = overflowGames;
  if (Array.isArray(consoles)) current.consoles = consoles;
  saveGameLibrary(current);
  res.json({ ok: true, savedAt: new Date().toISOString() });
});

app.post('/api/games/sync-cex', requireAuth, async (req, res) => {
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

if (require.main === module) {
  // Background auto-refresh every 30 minutes
  setInterval(() => {
    fetchLoisBullion(true).catch(() => {});
  }, 30 * 60 * 1000);
}

app.get('/api/bullion-rates', requireAuth, async (req, res) => {
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
const BETA_PROJECTS_FILE = path.join(DATA_DIR, 'beta-projects.json');

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
    const dataDir = DATA_DIR;
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
if (require.main === module) {
  (async () => {
    const mode = await store.init();
    initSetupState();
    loadSettings();
    scheduleMondaySync();
    logActivity('system', 'server-start', `SOS Tools Web v${APP_VERSION} started (store: ${mode}${isSetupRequired() ? ', setup-required' : ''})`);

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`SOS Tools Web v${APP_VERSION} running on http://0.0.0.0:${PORT}`);
    });
  })();
} else {
  module.exports = {
    app,
    store,
    SETUP_TOKEN_FILE,
    RATE_LIMIT_CONFIG,
    initSetupState,
    isSetupRequired,
    normalizeIp,
    isLoopbackIp,
    getConfiguredTrustedProxies,
    isTrustedProxySocket,
    isRequestHttps,
    isSetupHttps,
    isSetupTransportAllowed,
    cookieOptions,
    csrfProtection,
    clientIp,
    revokeUserSessions,
    clearAllRateLimitsForTest: () => rateLimitBuckets.clear(),
    getSetupInProgress: () => setupInProgress,
    setSetupInProgressForTest: (val) => { setupInProgress = Boolean(val); },
  };
}
