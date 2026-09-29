/* SOS Tools — renderer logic */
const IDLE_DEFAULT_MS = 5 * 60 * 1000;
const TAB_LABELS = {
  'phone-tablets': 'Phone and Tablets',
  'gamepad-tester': 'Gamepad Tester',
  'game-library': 'Game Library',
  'product-search': 'Product Search',
};
const VALID_THEMES = ['yellow', 'light', 'dark', 'blue'];

/* CSS injected into module pages (srcdoc) so they follow the user's theme.
   Module HTML should use var(--frame-bg), var(--text), var(--muted),
   var(--accent), var(--border) with fallbacks. */
const THEME_CSS = {
  yellow: ':root{--bg:#f7efcf;--frame-bg:#fffdf2;--panel:#fffdf2;--panel-2:#f3e5ae;--border:#ddc87c;--text:#3b2f0b;--muted:#8a7a45;--accent:#b45309;}',
  light: ':root{--bg:#f1f5f9;--frame-bg:#f8fafc;--panel:#ffffff;--panel-2:#e8edf3;--border:#cbd5e1;--text:#1e293b;--muted:#64748b;--accent:#2563eb;}',
  dark: ':root{--bg:#0b1220;--frame-bg:#0f172a;--panel:#111c2e;--panel-2:#16233a;--border:#24344e;--text:#e2e8f0;--muted:#8fa3bf;--accent:#2f81f7;}',
  blue: ':root{--bg:#eaf2fe;--frame-bg:#f5f9ff;--panel:#ffffff;--panel-2:#dbeafe;--border:#b6ccf5;--text:#17325c;--muted:#5b7bb5;--accent:#1d4ed8;}',
};

const ADMIN_TABS = [
  { id: 'users', label: 'Users' },
  { id: 'settings', label: 'Settings' },
  { id: 'activity', label: 'Activity Log' },
];

const $ = (sel) => document.querySelector(sel);

const state = {
  user: null,
  idleMs: IDLE_DEFAULT_MS,
  idleTimer: null,
  pinBuffer: '',
  pinFails: 0,
  activeTab: 'phone-tablets',
  lastRefresh: 0,
};

/* ---------------- Screens ---------------- */
function show(screen) {
  for (const id of ['screen-login', 'screen-lock', 'screen-main']) {
    $('#' + id).classList.toggle('hidden', id !== screen);
  }
}

/* ---------------- Login ---------------- */
$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#login-error').textContent = '';
  const username = $('#login-username').value.trim();
  const password = $('#login-password').value;
  const res = await window.sos.login(username, password);
  if (!res.ok) {
    $('#login-error').textContent = res.error || 'Sign-in failed.';
    return;
  }
  $('#login-password').value = '';
  await enterApp(res.user, { via: 'password' });
});

/* ---------------- Enter app / refresh ---------------- */
function applyTheme(theme) {
  document.body.dataset.theme = VALID_THEMES.includes(theme) ? theme : 'yellow';
}

async function enterApp(user, { via }) {
  state.user = user;
  state.pinFails = 0;
  applyTheme(user.theme);
  $('#theme-select').value = applyThemeToValid(user.theme);

  // Fetch settings (idle timeout) and refresh ALL content from disk/URLs.
  const settingsRes = await window.sos.getSettings();
  if (settingsRes.ok && settingsRes.settings && settingsRes.settings.idleLockMinutes) {
    state.idleMs = settingsRes.settings.idleLockMinutes * 60 * 1000;
  }
  if (settingsRes.ok && settingsRes.appVersion) $('#app-version').textContent = 'v' + settingsRes.appVersion;

  await refreshModules();
  await buildTabNav();
  await runUpdateCheck(true);
  resetIdleTimer();

  show('screen-main');
  $('#whoami').textContent = user.username;
  $('#must-change').classList.toggle('hidden', !user.mustChangePassword);
  selectTab('phone-tablets');

  if (via === 'pin') flashBanner('Session unlocked — content refreshed.');
}

async function refreshModules() {
  state.lastRefresh = Date.now();
  const res = await window.sos.getModules();
  if (!res.ok) return;
  for (const [tabId, mod] of Object.entries(res.modules)) {
    const frame = document.querySelector(`.tab-pane[data-pane="${tabId}"] iframe`);
    if (!frame) continue;
    if (mod.type === 'url') {
      // Cache-bust so re-login always pulls the latest page.
      frame.src = mod.url + (mod.url.includes('?') ? '&' : '?') + '_rt=' + Date.now();
    } else {
      frame.srcdoc = injectThemeCss(mod.content);
    }
  }
}

async function buildTabNav() {
  const nav = $('#tab-nav');
  nav.innerHTML = '';
  const tabs = Object.keys(TAB_LABELS);
  if (state.user.role === 'admin') tabs.push(...ADMIN_TABS.map((t) => t.id), 'account');
  else tabs.push('account');

  for (const id of tabs) {
    const btn = document.createElement('button');
    btn.dataset.tab = id;
    btn.textContent = TAB_LABELS[id] || (id === 'account' ? 'Account' : id.charAt(0).toUpperCase() + id.slice(1));
    if (ADMIN_TABS.some((t) => t.id === id)) btn.classList.add('admin-tab');
    btn.addEventListener('click', () => selectTab(id));
    nav.appendChild(btn);
  }
}

function selectTab(id) {
  state.activeTab = id;
  document.querySelectorAll('#tab-nav button').forEach((b) => b.classList.toggle('active', b.dataset.tab === id));
  document.querySelectorAll('.tab-pane').forEach((p) => p.classList.toggle('active', p.dataset.pane === id));
  if (id === 'users') loadUsersTable();
  if (id === 'settings') loadSettingsPane();
  if (id === 'activity') loadActivityTable();
  resetIdleTimer();
}

function flashBanner(text) {
  const banner = $('#banner');
  banner.textContent = text;
  banner.classList.remove('hidden');
  clearTimeout(flashBanner._t);
  flashBanner._t = setTimeout(() => banner.classList.add('hidden'), 5000);
}

function applyThemeToValid(theme) {
  return VALID_THEMES.includes(theme) ? theme : 'yellow';
}

function injectThemeCss(html) {
  const css = `<style data-sos-theme>${THEME_CSS[document.body.dataset.theme] || THEME_CSS.yellow}</style>`;
  if (/<head[^>]*>/i.test(html)) {
    return html.replace(/<head[^>]*>/i, (m) => m + css);
  }
  return css + html;
}

/* ---------------- Live module auto-refresh ---------------- */
window.sos.onModulesChanged(() => {
  if (!state.user) return;
  // Throttle: ignore bursts of file-change events within 2 seconds of a refresh.
  if (Date.now() - (state.lastRefresh || 0) < 2000) return;
  refreshModules();
  flashBanner('Modules updated — latest version loaded automatically.');
});

/* ---------------- Update check ---------------- */
async function runUpdateCheck(quiet) {
  const res = await window.sos.checkUpdates();
  if (res.checked && !res.upToDate) {
    flashBanner(`${res.message} — restart the app after updating files. ${res.notes || ''}`.trim());
  } else if (!quiet && res.message) {
    flashBanner(res.message);
  }
}

/* ---------------- Idle lock (PIN) ---------------- */
function resetIdleTimer() {
  clearTimeout(state.idleTimer);
  state.idleTimer = setTimeout(lockSession, state.idleMs);
}

function lockSession() {
  if (!state.user) return;
  state.pinBuffer = '';
  updatePinDisplay();
  $('#lock-error').textContent = '';
  $('#lock-user').textContent = 'Signed in as ' + state.user.username;
  show('screen-lock');
  logClientEvent('lock-shown', 'Idle timeout reached');
}

function updatePinDisplay() {
  $('#pin-display').textContent = '\u25CF'.repeat(state.pinBuffer.length).padEnd(4, '\u25CB');
}

function buildKeypad() {
  const keypad = $('#keypad');
  const keys = ['1', '2', '3', '4', '5', '6', '7', '8', '9', 'C', '0', '\u232B'];
  keypad.innerHTML = '';
  for (const key of keys) {
    const btn = document.createElement('button');
    btn.textContent = key;
    btn.addEventListener('click', () => handlePinKey(key));
    keypad.appendChild(btn);
  }
}

async function handlePinKey(key) {
  if (key === 'C') {
    state.pinBuffer = '';
  } else if (key === '\u232B') {
    state.pinBuffer = state.pinBuffer.slice(0, -1);
  } else if (state.pinBuffer.length < 4) {
    state.pinBuffer += key;
  }
  updatePinDisplay();
  if (state.pinBuffer.length === 4) {
    const res = await window.sos.verifyPin(state.pinBuffer);
    state.pinBuffer = '';
    updatePinDisplay();
    if (res.ok) {
      state.pinFails = 0;
      $('#lock-error').textContent = '';
      await enterApp(state.user, { via: 'pin' });
    } else {
      state.pinFails++;
      $('#lock-error').textContent = `${res.error || 'Incorrect PIN.'} (${state.pinFails}/3)`;
      if (state.pinFails >= 3) {
        await signOut();
        $('#login-error').textContent = 'Too many incorrect PIN attempts — please sign in again.';
      }
    }
  }
}

$('#lock-logout').addEventListener('click', () => signOut());

/* Activity resets the idle timer */
['mousemove', 'mousedown', 'keydown', 'wheel', 'touchstart'].forEach((evt) =>
  document.addEventListener(evt, () => {
    if (state.user && $('#screen-main').classList.contains('hidden') === false) resetIdleTimer();
  }, { passive: true })
);

/* ---------------- Sign out ---------------- */
async function signOut() {
  clearTimeout(state.idleTimer);
  await window.sos.logout();
  state.user = null;
  show('screen-login');
  $('#login-username').focus();
}

$('#btn-logout').addEventListener('click', signOut);

$('#btn-reload').addEventListener('click', async () => {
  await refreshModules();
  flashBanner('Modules reloaded.');
});

/* ---------------- Users pane (admin) ---------------- */
async function loadUsersTable() {
  const res = await window.sos.listUsers();
  if (!res.ok) {
    $('#user-form-error').textContent = res.error || '';
    return;
  }
  const tbody = $('#users-table tbody');
  tbody.innerHTML = '';
  for (const u of res.users) {
    const tr = document.createElement('tr');
    const created = new Date(u.createdAt).toLocaleString();
    tr.innerHTML = `
      <td>${escapeHtml(u.username)}</td>
      <td>${u.role}</td>
      <td>${created}</td>
      <td class="row-form" style="margin:0">
        <input type="password" placeholder="New password" data-pw="${u.username}" style="flex:0 1 150px" />
        <input inputmode="numeric" maxlength="4" placeholder="New PIN" data-pin="${u.username}" style="flex:0 1 110px" />
        <button class="btn" data-reset="${u.username}">Reset</button>
        <button class="btn danger" data-del="${u.username}">Delete</button>
      </td>`;
    tbody.appendChild(tr);
  }
  tbody.querySelectorAll('button[data-reset]').forEach((b) =>
    b.addEventListener('click', async () => {
      const name = b.dataset.reset;
      const pw = tbody.querySelector(`input[data-pw="${name}"]`).value;
      const pin = tbody.querySelector(`input[data-pin="${name}"]`).value;
      const r = await window.sos.resetCredentials(name, pw || undefined, pin || undefined);
      $('#user-form-error').textContent = r.ok ? 'Credentials updated.' : r.error;
      if (r.ok) loadUsersTable();
    })
  );
  tbody.querySelectorAll('button[data-del]').forEach((b) =>
    b.addEventListener('click', async () => {
      const r = await window.sos.deleteUser(b.dataset.del);
      $('#user-form-error').textContent = r.ok ? 'User deleted.' : r.error;
      if (r.ok) loadUsersTable();
    })
  );
}

$('#user-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#user-form-error').textContent = '';
  const res = await window.sos.createUser(
    $('#new-username').value,
    $('#new-password').value,
    $('#new-pin').value,
    $('#new-role').value
  );
  if (!res.ok) {
    $('#user-form-error').textContent = res.error;
    return;
  }
  $('#new-username').value = $('#new-password').value = $('#new-pin').value = '';
  loadUsersTable();
});

/* ---------------- Settings pane (admin) ---------------- */
async function loadSettingsPane() {
  const res = await window.sos.getSettings();
  if (!res.ok) return;
  $('#app-version').textContent = 'v' + (res.appVersion || '');
  $('#set-idle').value = res.settings.idleLockMinutes;
  if ($('#set-update-mode')) $('#set-update-mode').value = res.settings.moduleUpdateMode === 'instant' ? 'instant' : 'login';
  $('#set-update-url').value = res.settings.updateCheckUrl || '';
  if ($('#set-accounts-path')) $('#set-accounts-path').value = res.settings.accountsFilePath || '';
  if ($('#set-autoupdate-url')) $('#set-autoupdate-url').value = res.settings.autoUpdateUrl || '';
  const tbody = $('#module-table tbody');
  tbody.innerHTML = '';
  for (const tabId of Object.keys(TAB_LABELS)) {
    const mod = res.settings.modules[tabId] || { type: 'builtin', source: '' };
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${TAB_LABELS[tabId]}</td>
      <td><select data-type="${tabId}">
        <option value="builtin"${mod.type === 'builtin' ? ' selected' : ''}>Built-in placeholder</option>
        <option value="file"${mod.type === 'file' ? ' selected' : ''}>Local HTML file</option>
        <option value="url"${mod.type === 'url' ? ' selected' : ''}>Web URL</option>
      </select></td>
      <td><input data-source="${tabId}" placeholder="e.g. C:\\projects\\gamepad-tester\\index.html or https://..." value="${escapeAttr(mod.source || '')}" style="width:100%" /></td>`;
    tbody.appendChild(tr);
  }
}

$('#btn-save-settings').addEventListener('click', async () => {
  const modules = {};
  for (const tabId of Object.keys(TAB_LABELS)) {
    modules[tabId] = {
      type: document.querySelector(`select[data-type="${tabId}"]`).value,
      source: document.querySelector(`input[data-source="${tabId}"]`).value.trim(),
    };
  }
  const payload = {
    idleLockMinutes: parseInt($('#set-idle').value, 10) || 5,
    moduleUpdateMode: $('#set-update-mode') ? $('#set-update-mode').value : undefined,
    updateCheckUrl: $('#set-update-url').value.trim(),
    modules,
  };
  if ($('#set-accounts-path')) payload.accountsFilePath = $('#set-accounts-path').value.trim();
  if ($('#set-autoupdate-url')) payload.autoUpdateUrl = $('#set-autoupdate-url').value.trim();
  const res = await window.sos.saveSettings(payload);
  if (res.ok) {
    state.idleMs = res.settings.idleLockMinutes * 60 * 1000;
    $('#settings-msg').textContent = 'Saved. New sources load on next sign-in (or press F5 in a tab).';
    await refreshModules();
  } else {
    $('#settings-msg').textContent = res.error || 'Save failed.';
  }
});

$('#btn-check-updates').addEventListener('click', () => runUpdateCheck(false));
if ($('#btn-open-data')) $('#btn-open-data').addEventListener('click', () => window.sos.openDataFolder());

if ($('#btn-export-accounts')) $('#btn-export-accounts').addEventListener('click', async () => {
  const res = await window.sos.exportAccounts();
  if (res.ok) {
    $('#settings-msg').textContent = `Exported ${res.count} accounts — copy that file to your other PCs.`;
  } else if (res.error !== 'Cancelled.') {
    $('#settings-msg').textContent = res.error || 'Export failed.';
  }
});

if ($('#btn-import-accounts')) $('#btn-import-accounts').addEventListener('click', async () => {
  const res = await window.sos.importAccounts();
  if (res.ok) {
    if (res.needsRelogin) {
      await signOut();
      $('#login-error').textContent = 'Accounts were replaced from file — please sign in again.';
    } else {
      $('#settings-msg').textContent = `Imported ${res.count} accounts. Everyone now signs in with the cloned credentials.`;
      loadUsersTable();
    }
  } else if (res.error && res.error !== 'Cancelled.') {
    $('#settings-msg').textContent = res.error;
  }
});

/* ---------------- Activity pane (admin) ---------------- */
async function loadActivityTable() {
  const res = await window.sos.getActivityLog();
  if (!res.ok) return;
  const tbody = $('#log-table tbody');
  tbody.innerHTML = '';
  for (const entry of [...res.entries].reverse()) {
    const tr = document.createElement('tr');
    const time = entry.ts ? new Date(entry.ts).toLocaleString() : '';
    tr.innerHTML = `<td>${time}</td><td>${escapeHtml(entry.user)}</td><td>${escapeHtml(entry.action)}</td><td>${escapeHtml(entry.details)}</td>`;
    tbody.appendChild(tr);
  }
}

/* ---------------- Account pane ---------------- */
$('#btn-account').addEventListener('click', () => selectTab('account'));

$('#theme-select').addEventListener('change', async (e) => {
  const theme = applyThemeToValid(e.target.value);
  applyTheme(theme);
  const res = await window.sos.setTheme(theme);
  $('#theme-msg').textContent = res.ok ? 'Saved — this profile now loads whenever you sign in.' : res.error;
  if (res.ok) {
    state.user.theme = theme;
    await refreshModules();
  }
});

$('#change-password-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const res = await window.sos.changeOwnPassword($('#cur-password').value, $('#new-self-password').value);
  $('#change-password-msg').textContent = res.ok ? 'Password changed.' : res.error;
  if (res.ok) {
    $('#cur-password').value = $('#new-self-password').value = '';
    state.user = await window.sos.getCurrentUser();
    $('#must-change').classList.add('hidden');
  }
});

/* ---------------- Helpers ---------------- */
function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );
}
function escapeAttr(s) {
  return escapeHtml(s);
}

/* ---------------- Boot ---------------- */
buildKeypad();

/* Always land on the login screen. If a valid session exists, offer a
   one-click continue instead of silently re-entering the app. */
(async () => {
  show('screen-login');
  const res = await window.sos.getCurrentUser();
  if (res && res.ok && res.user) {
    window._validSession = res.user;
    $('#continue-name').textContent = res.user.username;
    $('#btn-continue').classList.remove('hidden');
  }
})();

$('#btn-continue').addEventListener('click', () => {
  if (window._validSession) enterApp(window._validSession, { via: 'restore' });
});
