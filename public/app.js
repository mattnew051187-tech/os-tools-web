/* SOS Tools — renderer logic */
const IDLE_DEFAULT_MS = 5 * 60 * 1000;
const TAB_LABELS = {
  'phone-tablets': 'Phone and Tablets',
  'gamepad-tester': 'Gamepad Tester',
  'game-library': 'Game Library',
  'repair-book-in': 'Repair Book In',
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
  pinVerifying: false,
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
  document.querySelectorAll('.module-frame').forEach(updateFrameTheme);
}

function updateFrameTheme(frame) {
  try {
    const doc = frame.contentDocument;
    if (doc) {
      const themeCss = THEME_CSS[document.body.dataset.theme] || THEME_CSS.yellow;
      let styleTag = doc.querySelector('style[data-sos-theme]');
      if (!styleTag) {
        styleTag = doc.createElement('style');
        styleTag.setAttribute('data-sos-theme', '');
        if (doc.head) doc.head.appendChild(styleTag);
        else doc.documentElement.appendChild(styleTag);
      }
      styleTag.textContent = themeCss;
    }
  } catch (e) {}
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

  // Beta placeholder is strictly exclusive to Matt
  const isMatt = user && user.username && user.username.toLowerCase() === 'matt';
  const betaTile = $('#tile-beta');
  if (betaTile) {
    betaTile.classList.toggle('hidden', !isMatt);
  }

  selectTab('home');
  loadBullionRates();
  startBullionTimer();

  if (via === 'pin') flashBanner('Session unlocked — content refreshed.');
}

/* ---------------- Lois Bullion Live Rates (30m auto-refresh) ---------------- */
let bullionInterval = null;

async function loadBullionRates(force = false) {
  const refreshBtn = document.getElementById('btn-refresh-bullion');
  const updatedEl = document.getElementById('bullion-updated');
  if (refreshBtn) refreshBtn.classList.add('spinning');
  if (updatedEl && force) updatedEl.textContent = 'Updating...';

  try {
    const res = await fetch(`/api/bullion-rates${force ? '?force=1' : ''}`);
    if (res.ok) {
      const data = await res.json();
      if (data && data.ok && data.rates) {
        const r = data.rates;
        const b9 = document.getElementById('bullion-9ct');
        const b14 = document.getElementById('bullion-14ct');
        const b18 = document.getElementById('bullion-18ct');
        const b24 = document.getElementById('bullion-24ct');
        const bSil = document.getElementById('bullion-silver');

        if (r.gold9ct !== undefined && b9) {
          b9.innerHTML = `&pound;${Number(r.gold9ct).toFixed(2)}<small>/g</small>`;
        }
        if (r.gold14ct !== undefined && b14) {
          b14.innerHTML = `&pound;${Number(r.gold14ct).toFixed(2)}<small>/g</small>`;
        }
        if (r.gold18ct !== undefined && b18) {
          b18.innerHTML = `&pound;${Number(r.gold18ct).toFixed(2)}<small>/g</small>`;
        }
        if (r.gold24ct !== undefined && b24) {
          b24.innerHTML = `&pound;${Number(r.gold24ct).toFixed(2)}<small>/g</small>`;
        }
        if (r.silver925 !== undefined && bSil) {
          bSil.innerHTML = `&pound;${Number(r.silver925).toFixed(2)}<small>/g</small>`;
        }

        // Keep compact workspace bar mini-rates in sync
        const mg24 = document.getElementById('mini-gold-24ct');
        const mg18 = document.getElementById('mini-gold-18ct');
        const mg9 = document.getElementById('mini-gold-9ct');
        if (r.gold24ct !== undefined && mg24) mg24.innerHTML = `&pound;${Number(r.gold24ct).toFixed(2)}`;
        if (r.gold18ct !== undefined && mg18) mg18.innerHTML = `&pound;${Number(r.gold18ct).toFixed(2)}`;
        if (r.gold9ct !== undefined && mg9) mg9.innerHTML = `&pound;${Number(r.gold9ct).toFixed(2)}`;

        if (updatedEl) {
          const fetchDate = data.lastFetched ? new Date(data.lastFetched) : new Date();
          const timeStr = fetchDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
          updatedEl.textContent = `${timeStr} (30m auto-refresh)`;
          updatedEl.title = data.sourceDate ? `Source: Lois Bullion (${data.sourceDate})` : 'Source: Lois Bullion';
        }
      }
    }
  } catch (err) {
    if (updatedEl) updatedEl.textContent = 'Offline (cached)';
  } finally {
    if (refreshBtn) {
      setTimeout(() => refreshBtn.classList.remove('spinning'), 400);
    }
  }
}

function startBullionTimer() {
  if (bullionInterval) clearInterval(bullionInterval);
  bullionInterval = setInterval(() => {
    if (state.user && !document.getElementById('screen-main').classList.contains('hidden')) {
      loadBullionRates();
    }
  }, 30 * 60 * 1000); // 30 minutes
}

const refreshBullionBtn = document.getElementById('btn-refresh-bullion');
if (refreshBullionBtn) {
  refreshBullionBtn.addEventListener('click', () => loadBullionRates(true));
}

async function refreshModules() {
  state.lastRefresh = Date.now();
  const res = await window.sos.getModules();
  if (!res.ok) return;
  for (const [tabId, mod] of Object.entries(res.modules)) {
    const frame = document.querySelector(`.tab-pane[data-pane="${tabId}"] iframe`);
    if (!frame) continue;
    if (mod.url) {
      // Load real URL with cache-busting so browser grants full same-origin privileges
      frame.removeAttribute('srcdoc');
      frame.src = mod.url + (mod.url.includes('?') ? '&' : '?') + '_rt=' + Date.now();
      frame.onload = () => updateFrameTheme(frame);
    } else {
      frame.removeAttribute('src');
      frame.srcdoc = injectThemeCss(mod.content);
    }
  }
}

async function buildTabNav() {
  const nav = $('#tab-nav');
  nav.innerHTML = '';
  const isMatt = state.user && state.user.username && state.user.username.toLowerCase() === 'matt';
  const tabs = ['home', ...Object.keys(TAB_LABELS)];
  if (isMatt) tabs.push('beta');
  if (state.user.role === 'admin') tabs.push(...ADMIN_TABS.map((t) => t.id), 'account');
  else tabs.push('account');

  for (const id of tabs) {
    const btn = document.createElement('button');
    btn.dataset.tab = id;
    if (id === 'beta') {
      btn.textContent = '🧪 Beta';
      btn.classList.add('beta-tab');
    } else {
      btn.textContent = TAB_LABELS[id] || (id === 'account' ? 'Account' : id.charAt(0).toUpperCase() + id.slice(1));
    }
    if (ADMIN_TABS.some((t) => t.id === id)) btn.classList.add('admin-tab');
    btn.addEventListener('click', () => selectTab(id));
    nav.appendChild(btn);
  }
}

function selectTab(id) {
  const isMatt = state.user && state.user.username && state.user.username.toLowerCase() === 'matt';
  if (id === 'beta' && !isMatt) {
    id = 'home';
  }
  state.activeTab = id;
  document.querySelectorAll('#tab-nav button').forEach((b) => b.classList.toggle('active', b.dataset.tab === id));
  document.querySelectorAll('.tab-pane').forEach((p) => p.classList.toggle('active', p.dataset.pane === id));

  const mainScreen = $('#screen-main');
  const wsBar = $('#workspace-bar');
  const wsTitle = $('#workspace-module-title');
  const wsToggleText = $('#workspace-toggle-text');
  const wsToggleIcon = $('#workspace-toggle-icon');

  // Collapse header and Lois Bullion bar for all modules to maximize working window
  const isModuleTab = id !== 'home';
  if (isModuleTab && mainScreen) {
    mainScreen.classList.add('header-collapsed');
    mainScreen.classList.remove('peek-headers');
    if (wsBar) wsBar.classList.remove('hidden');
    if (wsTitle) {
      const label = id === 'beta' ? '🧪 Beta Dev Lab' : (TAB_LABELS[id] || (id.charAt(0).toUpperCase() + id.slice(1)));
      wsTitle.textContent = label;
    }
    if (wsToggleText) wsToggleText.textContent = 'Show Header & Bullion';
    if (wsToggleIcon) wsToggleIcon.innerHTML = '&#9660;';

    // Ensure module iframe has a valid src loaded so it never displays a blank white screen
    const frame = document.querySelector(`.tab-pane[data-pane="${id}"] iframe`);
    if (frame) {
      if (!frame.src && !frame.srcdoc && id !== 'home' && !ADMIN_TABS.some((t) => t.id === id) && id !== 'account') {
        frame.src = `/modules/${id}.html`;
      }
      if (frame.contentWindow) {
        setTimeout(() => {
          try { frame.contentWindow.focus(); } catch (e) {}
        }, 50);
      }
    }
  } else if (mainScreen) {
    mainScreen.classList.remove('header-collapsed');
    mainScreen.classList.remove('peek-headers');
    if (wsBar) wsBar.classList.add('hidden');
  }

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
  clearTimeout(state.idleTimer);
  state.pinBuffer = '';
  state.pinVerifying = false;
  updatePinDisplay();
  $('#lock-error').textContent = '';
  $('#lock-user').textContent = 'Signed in as ' + state.user.username;
  show('screen-lock');
  if (document.activeElement && typeof document.activeElement.blur === 'function') {
    document.activeElement.blur();
  }
  const screenLock = $('#screen-lock');
  if (screenLock && typeof screenLock.focus === 'function') {
    screenLock.focus();
  }
  window.focus();
  logClientEvent('lock-shown', 'Session locked');
}

function updatePinDisplay() {
  $('#pin-display').textContent = '\u25CF'.repeat(state.pinBuffer.length).padEnd(4, '\u25CB');
}

function highlightKey(key) {
  let selectorKey = key;
  if (key === 'Backspace') selectorKey = '\u232B';
  if (key === 'Escape' || key === 'Clear' || key === 'c' || key === 'C') selectorKey = 'C';
  const btn = document.querySelector(`#keypad button[data-key="${selectorKey}"]`);
  if (!btn) return;
  btn.classList.add('key-pressed');
  setTimeout(() => btn.classList.remove('key-pressed'), 120);
}

function buildKeypad() {
  const keypad = $('#keypad');
  const keys = ['1', '2', '3', '4', '5', '6', '7', '8', '9', 'C', '0', '\u232B'];
  keypad.innerHTML = '';
  for (const key of keys) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = key;
    btn.dataset.key = key;
    if (key === 'C') btn.title = 'Clear (Escape, C)';
    else if (key === '\u232B') btn.title = 'Backspace (Backspace, Delete)';
    else btn.title = `Number ${key}`;
    btn.addEventListener('click', () => {
      highlightKey(key);
      handlePinKey(key);
    });
    keypad.appendChild(btn);
  }
}

async function handlePinKey(key) {
  if (state.pinVerifying) return;
  if (key === 'C') {
    state.pinBuffer = '';
  } else if (key === '\u232B' || key === 'Backspace') {
    state.pinBuffer = state.pinBuffer.slice(0, -1);
  } else if (/^[0-9]$/.test(key) && state.pinBuffer.length < 4) {
    state.pinBuffer += key;
  }
  updatePinDisplay();
  if (state.pinBuffer.length === 4) {
    state.pinVerifying = true;
    const pin = state.pinBuffer;
    const res = await window.sos.verifyPin(pin);
    state.pinBuffer = '';
    updatePinDisplay();
    state.pinVerifying = false;
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

/* Physical keyboard / numpad support for lock screen */
window.addEventListener('keydown', (e) => {
  const lockScreen = $('#screen-lock');
  if (!lockScreen || lockScreen.classList.contains('hidden')) return;

  const activeEl = document.activeElement;
  const isInput = activeEl && (activeEl.tagName === 'INPUT' || activeEl.tagName === 'TEXTAREA');
  if (isInput) return;

  // Physical numpad or top-row number keys
  let digit = null;
  if (e.key >= '0' && e.key <= '9') {
    digit = e.key;
  } else if (e.code && /^Numpad[0-9]$/.test(e.code)) {
    digit = e.code.replace('Numpad', '');
  }

  if (digit !== null) {
    e.preventDefault();
    highlightKey(digit);
    handlePinKey(digit);
    return;
  }

  // Backspace / Delete
  if (e.key === 'Backspace' || e.key === 'Delete') {
    e.preventDefault();
    highlightKey('\u232B');
    handlePinKey('\u232B');
    return;
  }

  // Clear (Escape, 'c', 'C', Clear)
  if (e.key === 'Escape' || e.key === 'c' || e.key === 'C' || e.key === 'Clear') {
    e.preventDefault();
    highlightKey('C');
    handlePinKey('C');
    return;
  }

  // Enter / NumpadEnter
  if (e.key === 'Enter') {
    if (activeEl && activeEl.id === 'lock-logout') {
      return;
    }
    e.preventDefault();
    if (state.pinBuffer.length === 4 && !state.pinVerifying) {
      handlePinKey('');
    }
  }
});

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
  const betaTile = $('#tile-beta');
  if (betaTile) betaTile.classList.add('hidden');
  await window.sos.logout();
  state.user = null;
  show('screen-login');
  $('#login-username').focus();
}

$('#btn-logout').addEventListener('click', signOut);

const btnLock = $('#btn-lock');
if (btnLock) {
  btnLock.addEventListener('click', () => lockSession());
}

$('#btn-reload').addEventListener('click', async () => {
  await refreshModules();
  flashBanner('Modules reloaded.');
});

/* Home screen tiles + back buttons */
document.querySelectorAll('[data-open]').forEach((el) =>
  el.addEventListener('click', () => selectTab(el.dataset.open))
);
document.querySelectorAll('[data-back]').forEach((el) =>
  el.addEventListener('click', () => selectTab('home'))
);

/* Compact workspace bar controls */
const wsBackHome = $('#workspace-back-home');
if (wsBackHome) {
  wsBackHome.addEventListener('click', () => selectTab('home'));
}

const wsToggleHeader = $('#workspace-toggle-header');
if (wsToggleHeader) {
  wsToggleHeader.addEventListener('click', () => {
    const mainScreen = $('#screen-main');
    if (!mainScreen) return;
    const isPeek = mainScreen.classList.toggle('peek-headers');
    const wsToggleText = $('#workspace-toggle-text');
    const wsToggleIcon = $('#workspace-toggle-icon');
    if (wsToggleText) wsToggleText.textContent = isPeek ? 'Collapse Header' : 'Show Header & Bullion';
    if (wsToggleIcon) wsToggleIcon.innerHTML = isPeek ? '&#9650;' : '&#9660;';
  });
}

const btnToggleHeaders = $('#btn-toggle-headers');
if (btnToggleHeaders) {
  btnToggleHeaders.addEventListener('click', () => {
    const mainScreen = $('#screen-main');
    if (!mainScreen) return;
    if (state.activeTab === 'home') {
      flashBanner('Open any module from the home grid to enter full maximized workspace mode.');
      return;
    }
    const isCollapsed = mainScreen.classList.toggle('header-collapsed');
    mainScreen.classList.remove('peek-headers');
    const wsBar = $('#workspace-bar');
    if (wsBar) wsBar.classList.toggle('hidden', !isCollapsed);
  });
}

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
    const me = await window.sos.getCurrentUser();
    if (me && me.user) state.user = me.user;
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

/* Always land cleanly on the login screen requiring credentials */
show('screen-login');

// Forward parent window gamepad events to active iframe so gamepads are immediately detected
window.addEventListener('gamepadconnected', (e) => {
  try {
    const activeFrame = document.querySelector('.tab-pane.active iframe');
    if (activeFrame && activeFrame.contentWindow) {
      activeFrame.contentWindow.postMessage({ type: 'SOS_GAMEPAD_CONNECTED', id: e.gamepad.id, index: e.gamepad.index }, '*');
    }
  } catch (err) {}
});

