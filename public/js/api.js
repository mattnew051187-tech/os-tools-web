/* SOS Tools (web edition) — browser API shim.
   Implements the exact same window.sos interface as the Electron preload,
   backed by HTTP calls to the central server, so app.js runs unchanged. */
(function () {
  async function request(method, url, body) {
    try {
      const token = sessionStorage.getItem('sos_token');
      const headers = {};
      if (body) headers['Content-Type'] = 'application/json';
      if (token) headers['Authorization'] = `Bearer ${token}`;
      const res = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        credentials: 'include',
      });
      const data = await res.json();
      if (data && data.token) {
        sessionStorage.setItem('sos_token', data.token);
      }
      return data;
    } catch (err) {
      return { ok: false, error: 'Cannot reach the SOS Tools server. Check your connection.' };
    }
  }

  window.sos = {
    // Auth
    getCurrentUser: () => request('GET', '/api/me'),
    login: (username, password) => request('POST', '/api/login', { username, password }),
    verifyPin: (pin) => request('POST', '/api/verify-pin', { pin }),
    logout: async () => {
      sessionStorage.removeItem('sos_token');
      return request('POST', '/api/logout');
    },
    setTheme: (theme) => request('POST', '/api/set-theme', { theme }),
    changeOwnPassword: (currentPassword, newPassword) =>
      request('POST', '/api/change-own-password', { currentPassword, newPassword }),

    // Users (admin)
    listUsers: () => request('GET', '/api/users'),
    createUser: (username, password, pin, role) =>
      request('POST', '/api/users', { username, password, pin, role }),
    deleteUser: (username) => request('POST', '/api/users/delete', { username }),
    resetCredentials: (username, password, pin) =>
      request('POST', '/api/users/reset-credentials', { username, password, pin }),

    // Settings (admin)
    getSettings: () => request('GET', '/api/settings'),
    saveSettings: (settings) => request('POST', '/api/settings', settings),

    // Modules / updates
    getModules: () => request('GET', '/api/modules'),
    checkUpdates: () => request('GET', '/api/check-updates'),
    getActivityLog: () => request('GET', '/api/activity'),
    openDataFolder: () => Promise.resolve({ ok: false, error: 'Data lives on the central server in the web edition.' }),
    showMessage: (message) => {
      const banner = document.getElementById('banner');
      if (banner) {
        banner.textContent = String(message || '');
        banner.classList.remove('hidden');
        setTimeout(() => banner.classList.add('hidden'), 4000);
      }
      return Promise.resolve({ ok: true });
    },

    // The server serves fresh content on every request — no push events needed.
    onModulesChanged: () => {},
  };

  // Lock/unlock activity logging (server-side, attributed to the session user).
  window.logClientEvent = function (action, details) {
    if (action === 'lock-shown') {
      request('POST', '/api/lock-shown', {}).then((res) => {
        if (!res.ok) {
          // Session may have expired while idle — bounce to the login screen.
          const main = document.getElementById('screen-main');
          if (main && !main.classList.contains('hidden')) {
            window.location.reload();
          }
        }
      });
    }
  };

  // The "Open data folder" button has no meaning in the web edition.
  window.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('btn-open-data');
    if (btn) btn.style.display = 'none';
  });
})();
