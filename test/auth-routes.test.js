/**
 * SOS Tools — Authentication Security & First-Run Setup Verification Tests
 *
 * Tests (isolated in temporary SOS_DATA_DIR directories via spawned servers):
 * 1. First-run setup (empty store):
 *    - No silent default administrator account ("Matt" / "1234!") created at boot
 *    - Setup status reports setupRequired: true
 *    - Invalid/missing setup tokens and weak credentials rejected
 *    - Valid one-time setup token creates initial admin and permanently locks setup
 *    - Auto-generated random token when INITIAL_SETUP_TOKEN is unset cannot be guessed
 *    - Simultaneous POST /api/setup requests blocked by atomic setup lock
 *    - Setup token is never leaked in HTTP responses or activity logs
 * 2. Reverse-proxy trust restriction:
 *    - Untrusted private-network (RFC1918/link-local/ULA) X-Forwarded-Proto spoofing rejected
 *    - Only loopback and explicit TRUSTED_PROXIES entries are trusted
 * 3. Endpoint audit, removed hardcoded fallbacks & preserved existing accounts:
 *    - Unauthenticated requests to all protected routes return 401
 *    - Admin and Matt-only endpoints enforce role authorization (403)
 *    - Hardcoded Matt fallback passwords/PIN rejected
 *    - Admin & non-admin workflows verified cleanly
 * 4. CLI scripts hardening:
 *    - verify-admin-credential.js refuses SAFE verdict / JSON mirror fallback in MongoDB mode
 *    - set-admin-credential.js preserves 0600 permissions, aborts on TOCTOU changes, and
 *      refuses modification when running-server status cannot be reliably established
 */

const assert = require('assert');
const http = require('http');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const EventEmitter = require('events');
const { spawn } = require('child_process');

const ROOT_DIR = path.join(__dirname, '..');
const SERVER_PATH = path.join(ROOT_DIR, 'server.js');
const VERIFY_CLI_PATH = path.join(ROOT_DIR, 'scripts', 'verify-admin-credential.js');
const SET_CLI_PATH = path.join(ROOT_DIR, 'scripts', 'set-admin-credential.js');
const tempDirs = [];

function makeTempDir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function hashSecret(secret, salt) {
  return crypto.scryptSync(String(secret), salt, 64).toString('hex');
}

function makeCredentials(secret) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt, hash: hashSecret(secret, salt) };
}

function apiRequest(port, options, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method: options.method || 'GET',
      path: options.path,
      headers: options.headers || {},
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch (e) {}
        resolve({ status: res.statusCode, headers: res.headers, body: json || data });
      });
    });
    req.on('error', reject);
    if (body !== undefined) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

function runCli(scriptPath, args = [], stdinLines = [], extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env, ...extraEnv };
    if (!Object.prototype.hasOwnProperty.call(extraEnv, 'MONGODB_URI')) {
      delete env.MONGODB_URI;
    }
    if (!Object.prototype.hasOwnProperty.call(extraEnv, 'PORT')) {
      delete env.PORT;
    }

    const child = spawn(process.execPath, [scriptPath, ...args], {
      cwd: ROOT_DIR,
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`CLI timeout: ${scriptPath}\nSTDOUT:\n${stdout}\nSTDERR:\n${stderr}`));
    }, 10000);

    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('exit', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });

    if (stdinLines.length > 0) {
      child.stdin.write(stdinLines.join('\n') + '\n');
    }
    child.stdin.end();
  });
}

function startServer({ port, dataDir, extraEnv = {} }) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env, PORT: String(port), SOS_DATA_DIR: dataDir, ...extraEnv };
    delete env.DISABLE_AUTH_FALLBACK;
    delete env.MONGODB_URI;

    const child = spawn(process.execPath, [SERVER_PATH], {
      cwd: ROOT_DIR,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill('SIGTERM');
        reject(new Error(`Server startup timeout on port ${port}.\nSTDOUT:\n${stdout}\nSTDERR:\n${stderr}`));
      }
    }, 10000);

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
      if (!settled && stdout.includes(`running on http://0.0.0.0:${port}`)) {
        settled = true;
        clearTimeout(timer);
        resolve({ child, getLogs: () => ({ stdout, stderr }) });
      }
    });

    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    child.on('exit', (code) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(new Error(`Server exited prematurely (${code}).\nSTDOUT:\n${stdout}\nSTDERR:\n${stderr}`));
      }
    });
  });
}

function stopServer(child) {
  return new Promise((resolve) => {
    if (!child || child.killed) return resolve();
    child.once('exit', () => resolve());
    child.kill('SIGTERM');
    setTimeout(() => {
      try { child.kill('SIGKILL'); } catch (e) {}
      resolve();
    }, 2000);
  });
}

function invokeExpressApp(app, { method = 'GET', path: reqPath = '/', headers = {}, remoteAddress = '127.0.0.1', encrypted = false, body = undefined }) {
  return new Promise((resolve, reject) => {
    const req = new EventEmitter();
    req.method = method;
    req.url = reqPath;
    req.originalUrl = reqPath;
    req.headers = {};
    for (const [k, v] of Object.entries(headers)) {
      req.headers[k.toLowerCase()] = v;
    }
    req.socket = { remoteAddress, encrypted };
    req.connection = req.socket;
    if (body !== undefined) {
      req.body = body;
      req._body = true;
    }

    const resHeaders = {};
    const chunks = [];
    const res = new EventEmitter();
    res.statusCode = 200;
    res.locals = {};
    res.setHeader = (name, val) => { resHeaders[name.toLowerCase()] = val; };
    res.getHeader = (name) => resHeaders[name.toLowerCase()];
    res.removeHeader = (name) => { delete resHeaders[name.toLowerCase()]; };
    res.writeHead = (code, hdrs) => {
      res.statusCode = code;
      if (hdrs) {
        for (const [k, v] of Object.entries(hdrs)) res.setHeader(k, v);
      }
    };
    res.status = (code) => {
      res.statusCode = code;
      return res;
    };
    res.cookie = (name, val) => {
      resHeaders['set-cookie'] = `${name}=${encodeURIComponent(val)}`;
      return res;
    };
    res.clearCookie = () => res;
    res.json = (payload) => {
      res.setHeader('content-type', 'application/json');
      resolve({ status: res.statusCode, headers: resHeaders, body: payload });
      return res;
    };
    res.send = (payload) => {
      resolve({ status: res.statusCode, headers: resHeaders, body: payload });
      return res;
    };
    res.write = (chunk) => { chunks.push(Buffer.from(chunk)); return true; };
    res.end = (chunk) => {
      if (chunk) chunks.push(Buffer.from(chunk));
      const text = Buffer.concat(chunks).toString('utf8');
      let parsed = null;
      try { parsed = JSON.parse(text); } catch (e) {}
      resolve({ status: res.statusCode, headers: resHeaders, body: parsed || text });
    };

    app.handle(req, res, (err) => {
      if (err) return reject(err);
      resolve({ status: 404, headers: resHeaders, body: null });
    });
  });
}

async function testFirstRunRandomTokenAndHttpsSafeguard() {
  console.log('\n=== Test Suite 1A: First-Run Setup, HTTPS Safeguard & Random Token ===');
  const dataDir = makeTempDir('sos-setup-rand-');
  const port = 3997;
  const { child, getLogs } = await startServer({ port, dataDir });

  try {
    const usersFile = path.join(dataDir, 'users.json');
    assert.strictEqual(fs.existsSync(usersFile), false, 'users.json must NOT be silently created at boot');

    // Direct loopback HTTP allowed for local development
    const statusRes = await apiRequest(port, { path: '/api/setup/status' });
    assert.strictEqual(statusRes.status, 200);
    assert.strictEqual(statusRes.body.ok, true);
    assert.strictEqual(statusRes.body.setupRequired, true);
    assert.strictEqual(statusRes.body.setupAllowed, true);
    assert.strictEqual(statusRes.body.httpsRequired, false);

    // Public/plain-HTTP proxied traffic MUST be blocked from submitting setup credentials
    const httpProxyStatus = await apiRequest(port, {
      path: '/api/setup/status',
      headers: { 'X-Forwarded-Proto': 'http', 'X-Forwarded-For': '203.0.113.10' },
    });
    assert.strictEqual(httpProxyStatus.status, 200);
    assert.strictEqual(httpProxyStatus.body.setupRequired, true);
    assert.strictEqual(httpProxyStatus.body.setupAllowed, false);
    assert.strictEqual(httpProxyStatus.body.httpsRequired, true);

    const extFwdStatus = await apiRequest(port, {
      path: '/api/setup/status',
      headers: { 'X-Forwarded-For': '198.51.100.25' },
    });
    assert.strictEqual(extFwdStatus.body.setupAllowed, false);
    assert.strictEqual(extFwdStatus.body.httpsRequired, true);

    // Read auto-generated random setup token from data/.setup-token (0600) and verify it is NOT printed to logs
    const setupTokenPath = path.join(dataDir, '.setup-token');
    assert.strictEqual(fs.existsSync(setupTokenPath), true, 'Expected data/.setup-token file on uninitialized install');
    assert.strictEqual(fs.statSync(setupTokenPath).mode & 0o777, 0o600, 'Expected 0600 permissions on .setup-token');
    const generatedToken = fs.readFileSync(setupTokenPath, 'utf8').trim();
    assert.match(generatedToken, /^[a-f0-9]{48}$/i, 'Expected 48-char random hex setup token in data/.setup-token');

    const { stdout, stderr } = getLogs();
    assert.strictEqual(stdout.includes(generatedToken), false, 'Auto-generated setup token must NEVER be printed to stdout');
    assert.strictEqual(stderr.includes(generatedToken), false, 'Auto-generated setup token must NEVER be printed to stderr');

    // Even with the valid setup token, plain-HTTP proxied POST /api/setup MUST be rejected with 403
    const blockedHttpSetup = await apiRequest(port, {
      path: '/api/setup',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-Proto': 'http',
        'X-Forwarded-For': '203.0.113.10',
      },
    }, {
      setupToken: generatedToken,
      username: 'Matt',
      password: 'StrongAdminPassword9!',
      pin: '5678',
    });
    assert.strictEqual(blockedHttpSetup.status, 403);
    assert.strictEqual(blockedHttpSetup.body.ok, false);
    assert.ok(blockedHttpSetup.body.error.includes('HTTPS'));
    assert.strictEqual(fs.existsSync(usersFile), false, 'Blocked HTTP setup must not create users.json');

    // TLS-terminated reverse proxy (X-Forwarded-Proto: https from trusted loopback proxy) IS allowed
    const httpsProxyStatus = await apiRequest(port, {
      path: '/api/setup/status',
      headers: { 'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '203.0.113.10' },
    });
    assert.strictEqual(httpsProxyStatus.body.setupAllowed, true);
    assert.strictEqual(httpsProxyStatus.body.httpsRequired, false);

    const meRes = await apiRequest(port, { path: '/api/me' });
    assert.strictEqual(meRes.status, 200);
    assert.strictEqual(meRes.body.user, null);
    assert.strictEqual(meRes.body.setupRequired, true);

    // Confirm hardcoded defaults fail on fresh server
    for (const pw of ['1234!', '1234']) {
      const loginRes = await apiRequest(port, {
        path: '/api/login',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }, { username: 'Matt', password: pw });
      assert.strictEqual(loginRes.body.ok, false, `Default login (${pw}) must fail on fresh install`);
    }

    // Confirm guessed setup tokens fail
    for (const badToken of ['', '1234!', 'setup', 'wrong-token-value']) {
      const badSetup = await apiRequest(port, {
        path: '/api/setup',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }, { setupToken: badToken, username: 'Attacker', password: 'StrongPassword1!', pin: '9988' });
      assert.strictEqual(badSetup.status, 403);
      assert.strictEqual(badSetup.body.ok, false);
    }

    // Weak passwords (< 8 characters) rejected on setup
    for (const shortPw of ['short', '1234567']) {
      const weakPw = await apiRequest(port, {
        path: '/api/setup',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }, { setupToken: generatedToken, username: 'Matt', password: shortPw, pin: '5678' });
      assert.strictEqual(weakPw.status, 400, `Setup must reject <8 char password (${shortPw})`);
      assert.strictEqual(weakPw.body.ok, false);
    }

    // Invalid PIN rejected
    const badPin = await apiRequest(port, {
      path: '/api/setup',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, { setupToken: generatedToken, username: 'Matt', password: 'StrongAdminPassword9!', pin: 'abcd' });
    assert.strictEqual(badPin.status, 400);
    assert.strictEqual(badPin.body.ok, false);

    // Valid setup succeeds over simulated TLS reverse proxy
    const setupRes = await apiRequest(port, {
      path: '/api/setup',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-Proto': 'https',
        'X-Forwarded-For': '203.0.113.10',
      },
    }, {
      setupToken: generatedToken,
      username: 'WorkshopAdmin',
      password: 'StrongAdminPassword9!',
      pin: '5678',
    });
    assert.strictEqual(setupRes.status, 200);
    assert.strictEqual(setupRes.body.ok, true);
    assert.strictEqual(setupRes.body.user.username, 'WorkshopAdmin');
    assert.strictEqual(setupRes.body.user.role, 'admin');
    assert.ok(setupRes.body.token, 'Expected session token from setup');
    const adminToken = setupRes.body.token;

    // Setup is now permanently locked and .setup-token is deleted
    assert.strictEqual(fs.existsSync(setupTokenPath), false, '.setup-token must be deleted once initial setup completes');
    const postSetupStatus = await apiRequest(port, { path: '/api/setup/status' });
    assert.strictEqual(postSetupStatus.body.setupRequired, false);

    const replaySetup = await apiRequest(port, {
      path: '/api/setup',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, {
      setupToken: generatedToken,
      username: 'SecondAdmin',
      password: 'AnotherStrongPassword1!',
      pin: '1122',
    });
    assert.strictEqual(replaySetup.status, 403);
    assert.strictEqual(replaySetup.body.ok, false);

    // Newly created admin can verify PIN and access protected endpoints
    const pinRes = await apiRequest(port, {
      path: '/api/verify-pin',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    }, { pin: '5678' });
    assert.strictEqual(pinRes.body.ok, true);

    const usersList = await apiRequest(port, {
      path: '/api/users',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.strictEqual(usersList.status, 200);
    assert.strictEqual(usersList.body.users.length, 1);
    assert.strictEqual(usersList.body.users[0].username, 'WorkshopAdmin');

    // Setup token must never leak in HTTP responses or activity logs
    const activityRes = await apiRequest(port, {
      path: '/api/activity',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.strictEqual(activityRes.status, 200);
    const serializedActivity = JSON.stringify(activityRes.body);
    assert.strictEqual(serializedActivity.includes(generatedToken), false, 'Setup token must never appear in /api/activity');
    const logFile = path.join(dataDir, 'activity-log.jsonl');
    if (fs.existsSync(logFile)) {
      const logContent = fs.readFileSync(logFile, 'utf8');
      assert.strictEqual(logContent.includes(generatedToken), false, 'Setup token must never be written to activity-log.jsonl');
    }
    assert.strictEqual(JSON.stringify(statusRes.body).includes(generatedToken), false);
    assert.strictEqual(JSON.stringify(meRes.body).includes(generatedToken), false);
    assert.strictEqual(JSON.stringify(setupRes.body).includes(generatedToken), false);

    console.log('[PASS] First-run setup flow, HTTPS/proxy safeguard, min-8-char enforcement, and setup token isolation verified.');
  } finally {
    await stopServer(child);
  }
}

async function testFirstRunEnvToken() {
  console.log('\n=== Test Suite 1B: First-Run Setup (INITIAL_SETUP_TOKEN Env Var) ===');
  const dataDir = makeTempDir('sos-setup-env-');
  const port = 3998;
  const envSecret = 'custom-setup-secret-token-123456';
  const { child, getLogs } = await startServer({
    port,
    dataDir,
    extraEnv: { INITIAL_SETUP_TOKEN: envSecret },
  });

  try {
    const { stdout, stderr } = getLogs();
    assert.strictEqual(stdout.includes(envSecret), false, 'Env-provided setup token must not be printed to stdout');
    assert.strictEqual(stderr.includes(envSecret), false, 'Env-provided setup token must not be printed to stderr');

    const setupRes = await apiRequest(port, {
      path: '/api/setup',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, {
      setupToken: envSecret,
      username: 'Matt',
      password: 'MattStrongPassword88!',
      pin: '7391',
    });
    assert.strictEqual(setupRes.status, 200);
    assert.strictEqual(setupRes.body.ok, true);
    assert.strictEqual(setupRes.body.user.username, 'Matt');
    console.log('[PASS] INITIAL_SETUP_TOKEN works without printing secret to logs.');
  } finally {
    await stopServer(child);
  }
}

async function testReverseProxyTrustRestriction() {
  console.log('\n=== Test Suite 1C: Reverse-Proxy Trust Restriction & Spoofing Protection ===');
  const proxyDataDir = makeTempDir('sos-proxy-trust-');
  const prevDataDir = process.env.SOS_DATA_DIR;
  const prevTrusted = process.env.TRUSTED_PROXIES;
  const prevSetupTok = process.env.INITIAL_SETUP_TOKEN;

  const setupToken = 'proxy-trust-test-secret-token-123456';
  process.env.SOS_DATA_DIR = proxyDataDir;
  delete process.env.TRUSTED_PROXIES;
  process.env.INITIAL_SETUP_TOKEN = setupToken;

  delete require.cache[require.resolve(SERVER_PATH)];
  delete require.cache[require.resolve(path.join(ROOT_DIR, 'store.js'))];
  const serverMod = require(SERVER_PATH);
  await serverMod.store.init();
  serverMod.initSetupState();

  try {
    // 1. Untrusted private-network and public IPs MUST NOT be trusted proxies
    const untrustedPrivateIps = [
      '10.0.0.5',
      '172.16.0.10',
      '172.31.255.20',
      '192.168.1.50',
      '169.254.169.254',
      'fc00::1',
      'fd12:3456::1',
      'fe80::1',
      '203.0.113.10',
    ];
    for (const ip of untrustedPrivateIps) {
      assert.strictEqual(serverMod.isTrustedProxySocket(ip), false, `Untrusted IP ${ip} must NOT be trusted`);
      const fakeReq = {
        socket: { remoteAddress: ip, encrypted: false },
        headers: { 'x-forwarded-proto': 'https', 'x-forwarded-for': '127.0.0.1' },
      };
      assert.strictEqual(serverMod.isSetupHttps(fakeReq), false, `Spoofed X-Forwarded-Proto from ${ip} must fail`);
      assert.strictEqual(serverMod.isSetupTransportAllowed(fakeReq), false, `Spoofed setup transport from ${ip} must fail`);
      assert.strictEqual(serverMod.cookieOptions(fakeReq).sameSite, 'lax', `Spoofed proto from ${ip} must not elevate cookie`);
      assert.strictEqual(serverMod.clientIp(fakeReq), ip, `Untrusted ${ip} must not spoof X-Forwarded-For`);

      // Also verify real Express routes /api/setup/status & /api/setup reject forged private proxy headers
      const statusOut = await invokeExpressApp(serverMod.app, {
        method: 'GET',
        path: '/api/setup/status',
        remoteAddress: ip,
        headers: { 'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '127.0.0.1' },
      });
      assert.strictEqual(statusOut.status, 200);
      assert.strictEqual(statusOut.body.setupAllowed, false, `GET /api/setup/status must report setupAllowed=false for ${ip}`);
      assert.strictEqual(statusOut.body.httpsRequired, true);

      const setupOut = await invokeExpressApp(serverMod.app, {
        method: 'POST',
        path: '/api/setup',
        remoteAddress: ip,
        headers: {
          'Content-Type': 'application/json',
          'X-Forwarded-Proto': 'https',
          'X-Forwarded-For': '127.0.0.1',
        },
        body: {
          setupToken,
          username: 'AttackerAdmin',
          password: 'StrongPassword123!',
          pin: '1234',
        },
      });
      assert.strictEqual(setupOut.status, 403, `POST /api/setup must return 403 for spoofed X-Forwarded-Proto from ${ip}`);
      assert.strictEqual(setupOut.body.ok, false);
      assert.ok(setupOut.body.error.includes('HTTPS'));
    }

    // 2. Direct loopback requests (localhost dev/test) and local loopback TLS proxy work
    assert.strictEqual(serverMod.isTrustedProxySocket('127.0.0.1'), true);
    assert.strictEqual(serverMod.isTrustedProxySocket('::1'), true);
    assert.strictEqual(serverMod.isTrustedProxySocket('::ffff:127.0.0.1'), true);
    assert.strictEqual(
      serverMod.isSetupTransportAllowed({ socket: { remoteAddress: '127.0.0.1', encrypted: false }, headers: {} }),
      true
    );
    assert.strictEqual(
      serverMod.isSetupTransportAllowed({
        socket: { remoteAddress: '::ffff:127.0.0.1', encrypted: false },
        headers: { 'x-forwarded-proto': 'https', 'x-forwarded-for': '203.0.113.99' },
      }),
      true
    );

    // 3. Explicit TRUSTED_PROXIES only trusts listed IPs and still rejects unlisted private IPs
    process.env.TRUSTED_PROXIES = '192.168.1.50, 10.20.30.40';
    assert.strictEqual(serverMod.isTrustedProxySocket('192.168.1.50'), true);
    assert.strictEqual(serverMod.isTrustedProxySocket('::ffff:10.20.30.40'), true);
    assert.strictEqual(serverMod.isTrustedProxySocket('192.168.1.51'), false);
    assert.strictEqual(serverMod.isTrustedProxySocket('10.0.0.5'), false);

    const trustedReq = {
      socket: { remoteAddress: '::ffff:192.168.1.50', encrypted: false },
      headers: { 'x-forwarded-proto': 'https', 'x-forwarded-for': '203.0.113.55' },
    };
    assert.strictEqual(serverMod.isSetupHttps(trustedReq), true);
    assert.strictEqual(serverMod.isSetupTransportAllowed(trustedReq), true);
    assert.strictEqual(serverMod.clientIp(trustedReq), '203.0.113.55');

    const unlistedNeighborReq = {
      socket: { remoteAddress: '192.168.1.51', encrypted: false },
      headers: { 'x-forwarded-proto': 'https', 'x-forwarded-for': '203.0.113.55' },
    };
    assert.strictEqual(serverMod.isSetupTransportAllowed(unlistedNeighborReq), false);

    console.log('[PASS] Private network proxy trust removed; only loopback and explicit TRUSTED_PROXIES trusted.');
  } finally {
    delete require.cache[require.resolve(SERVER_PATH)];
    delete require.cache[require.resolve(path.join(ROOT_DIR, 'store.js'))];
    if (prevDataDir === undefined) delete process.env.SOS_DATA_DIR;
    else process.env.SOS_DATA_DIR = prevDataDir;
    if (prevTrusted === undefined) delete process.env.TRUSTED_PROXIES;
    else process.env.TRUSTED_PROXIES = prevTrusted;
    if (prevSetupTok === undefined) delete process.env.INITIAL_SETUP_TOKEN;
    else process.env.INITIAL_SETUP_TOKEN = prevSetupTok;
  }
}

async function testSimultaneousSetupLock() {
  console.log('\n=== Test Suite 1D: Simultaneous First-Run Setup Lock ===');
  const dataDir = makeTempDir('sos-setup-lock-');
  const port = 4000;
  const setupSecret = 'concurrent-setup-secret-token-7890';
  const { child } = await startServer({
    port,
    dataDir,
    extraEnv: { INITIAL_SETUP_TOKEN: setupSecret },
  });

  try {
    // 1. Validation error must release the lock cleanly so subsequent setup succeeds
    const invalidAttempt = await apiRequest(port, {
      path: '/api/setup',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, { setupToken: setupSecret, username: 'Admin1', password: 'short', pin: '1234' });
    assert.strictEqual(invalidAttempt.status, 400);

    // 2. Fire two valid simultaneous setup requests
    const payloadA = {
      setupToken: setupSecret,
      username: 'FirstAdmin',
      password: 'StrongPasswordA9!',
      pin: '1111',
    };
    const payloadB = {
      setupToken: setupSecret,
      username: 'SecondAdmin',
      password: 'StrongPasswordB9!',
      pin: '2222',
    };

    const [resA, resB] = await Promise.all([
      apiRequest(port, {
        path: '/api/setup',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }, payloadA),
      apiRequest(port, {
        path: '/api/setup',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }, payloadB),
    ]);

    const results = [resA, resB];
    const successes = results.filter((r) => r.status === 200 && r.body && r.body.ok === true);
    const rejections = results.filter((r) => r.status !== 200 && r.body && r.body.ok === false);
    assert.strictEqual(successes.length, 1, 'Exactly one simultaneous setup request must succeed');
    assert.strictEqual(rejections.length, 1, 'Second simultaneous setup request must be rejected');

    const savedUsers = JSON.parse(fs.readFileSync(path.join(dataDir, 'users.json'), 'utf8'));
    assert.strictEqual(savedUsers.length, 1, 'Only one initial administrator may be persisted');
    assert.strictEqual(savedUsers[0].username, successes[0].body.user.username);

    // 3. Also verify explicit in-progress lock unit guard returns 409 and safely blocks overlap
    const lockDataDir = makeTempDir('sos-lock-unit-');
    const prevDir = process.env.SOS_DATA_DIR;
    const prevTok = process.env.INITIAL_SETUP_TOKEN;
    process.env.SOS_DATA_DIR = lockDataDir;
    process.env.INITIAL_SETUP_TOKEN = setupSecret;
    delete require.cache[require.resolve(SERVER_PATH)];
    delete require.cache[require.resolve(path.join(ROOT_DIR, 'store.js'))];
    const serverMod = require(SERVER_PATH);
    await serverMod.store.init();
    serverMod.initSetupState();
    try {
      serverMod.setSetupInProgressForTest(true);
      const lockedRes = await invokeExpressApp(serverMod.app, {
        method: 'POST',
        path: '/api/setup',
        remoteAddress: '127.0.0.1',
        headers: { 'Content-Type': 'application/json' },
        body: payloadA,
      });
      assert.strictEqual(lockedRes.status, 409);
      assert.strictEqual(lockedRes.body.ok, false);
      assert.ok(lockedRes.body.error.includes('in progress'));
      serverMod.setSetupInProgressForTest(false);
    } finally {
      delete require.cache[require.resolve(SERVER_PATH)];
      delete require.cache[require.resolve(path.join(ROOT_DIR, 'store.js'))];
      if (prevDir === undefined) delete process.env.SOS_DATA_DIR;
      else process.env.SOS_DATA_DIR = prevDir;
      if (prevTok === undefined) delete process.env.INITIAL_SETUP_TOKEN;
      else process.env.INITIAL_SETUP_TOKEN = prevTok;
    }

    console.log('[PASS] Simultaneous setup lock allows exactly one admin creation and releases safely.');
  } finally {
    await stopServer(child);
  }
}

async function testExistingUsersFallbacksUsbAgentAndPasswordPolicy() {
  console.log('\n=== Test Suite 2: Fallbacks, /api/usb-agent/* Auth, Password Policy & Admin Flows ===');
  const dataDir = makeTempDir('sos-existing-');
  const port = 3999;

  const TEST_PASSWORD = 'TestPassword123!';
  const TEST_PIN = '8899';
  const TECH_PASSWORD = 'TechSecret456!';
  const TECH_PIN = '4455';

  const seededUsers = [
    {
      username: 'Matt',
      role: 'admin',
      createdAt: '2026-01-01T00:00:00.000Z',
      password: makeCredentials(TEST_PASSWORD),
      pin: makeCredentials(TEST_PIN),
      mustChangePassword: false,
      theme: 'yellow',
    },
    {
      username: 'Technician1',
      role: 'user',
      createdAt: '2026-01-02T00:00:00.000Z',
      password: makeCredentials(TECH_PASSWORD),
      pin: makeCredentials(TECH_PIN),
      mustChangePassword: false,
      theme: 'dark',
    },
  ];
  fs.writeFileSync(path.join(dataDir, 'users.json'), JSON.stringify(seededUsers, null, 2), 'utf8');

  const { child } = await startServer({ port, dataDir });

  try {
    // 1. Setup is disabled when users exist
    const statusRes = await apiRequest(port, { path: '/api/setup/status' });
    assert.strictEqual(statusRes.body.setupRequired, false);
    const setupBlocked = await apiRequest(port, {
      path: '/api/setup',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, { setupToken: 'anything', username: 'Rogue', password: 'Password123!', pin: '1111' });
    assert.strictEqual(setupBlocked.status, 403);

    // 2. Unauthenticated protected route rejection (including ALL 4 /api/usb-agent/* routes)
    const protectedGetRoutes = [
      '/api/users/list',
      '/api/repairs',
      '/api/phone-reports',
      '/api/gamepad-reports',
      '/api/games',
      '/api/usb-agent/status',
      '/api/usb-agent/device',
    ];
    for (const route of protectedGetRoutes) {
      const res = await apiRequest(port, { path: route });
      assert.strictEqual(res.status, 401, `Expected 401 for unauthenticated GET ${route}`);
      assert.strictEqual(res.body.ok, false);
    }

    const unauthUsbPost = await apiRequest(port, {
      path: '/api/usb-agent/device',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, { model: 'HijackedPhone', serial: 'HACKED' });
    assert.strictEqual(unauthUsbPost.status, 401, 'Unauthenticated POST /api/usb-agent/device must return 401');

    const unauthUsbDelete = await apiRequest(port, {
      path: '/api/usb-agent/device',
      method: 'DELETE',
    });
    assert.strictEqual(unauthUsbDelete.status, 401, 'Unauthenticated DELETE /api/usb-agent/device must return 401');
    console.log('[PASS] Protected routes and all 4 /api/usb-agent/* endpoints reject unauthenticated access (401).');

    // 3. Hardcoded fallback passwords for Matt MUST FAIL on /api/login
    for (const fallbackPw of ['1234!', '1234', 'WrongPassword999!']) {
      const res = await apiRequest(port, {
        path: '/api/login',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }, { username: 'Matt', password: fallbackPw });
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.ok, false, `Login must reject password "${fallbackPw}" for Matt`);
    }
    console.log('[PASS] Removed hardcoded fallback passwords ("1234!", "1234") rejected on /api/login.');

    // 4. Existing legitimate Matt and Technician1 accounts preserve hashes and log in
    const mattLogin = await apiRequest(port, {
      path: '/api/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, { username: 'Matt', password: TEST_PASSWORD });
    assert.strictEqual(mattLogin.body.ok, true);
    assert.strictEqual(mattLogin.body.authType, undefined);
    assert.ok(mattLogin.body.token);
    let mattToken = mattLogin.body.token;

    const techLogin = await apiRequest(port, {
      path: '/api/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, { username: 'Technician1', password: TECH_PASSWORD });
    assert.strictEqual(techLogin.body.ok, true);
    assert.ok(techLogin.body.token);
    console.log('[PASS] Existing Matt and Technician1 accounts preserved and authenticated via stored hashes.');

    // 5. Authenticated /api/usb-agent/* workflow and unauthenticated mutation tamper check
    const authStatusInitial = await apiRequest(port, {
      path: '/api/usb-agent/status',
      headers: { Authorization: `Bearer ${mattToken}` },
    });
    assert.strictEqual(authStatusInitial.status, 200);
    assert.strictEqual(authStatusInitial.body.ok, true);
    assert.strictEqual(authStatusInitial.body.activeDevice, null, 'Unauthenticated POST must not set activeDevice');

    const badUsbPayload = await apiRequest(port, {
      path: '/api/usb-agent/device',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mattToken}` },
    }, ['not-an-object']);
    assert.strictEqual(badUsbPayload.status, 400);

    const setUsbRes = await apiRequest(port, {
      path: '/api/usb-agent/device',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: `sos_session=${mattToken}` },
    }, { model: 'iPhone 15', serial: 'TEST-SERIAL-001' });
    assert.strictEqual(setUsbRes.status, 200);
    assert.strictEqual(setUsbRes.body.ok, true);
    assert.strictEqual(setUsbRes.body.activeDevice.model, 'iPhone 15');

    // Unauthenticated DELETE cannot clear the active device
    const unauthClearRes = await apiRequest(port, {
      path: '/api/usb-agent/device',
      method: 'DELETE',
    });
    assert.strictEqual(unauthClearRes.status, 401);

    const getUsbAfterUnauthDel = await apiRequest(port, {
      path: '/api/usb-agent/device',
      headers: { Authorization: `Bearer ${mattToken}` },
    });
    assert.strictEqual(getUsbAfterUnauthDel.status, 200);
    assert.strictEqual(getUsbAfterUnauthDel.body.device.model, 'iPhone 15', 'Unauthenticated DELETE must not clear activeDevice');

    const authClearRes = await apiRequest(port, {
      path: '/api/usb-agent/device',
      method: 'DELETE',
      headers: { Authorization: `Bearer ${mattToken}` },
    });
    assert.strictEqual(authClearRes.status, 200);
    assert.strictEqual(authClearRes.body.ok, true);

    const getUsbAfterAuthDel = await apiRequest(port, {
      path: '/api/usb-agent/device',
      headers: { Authorization: `Bearer ${mattToken}` },
    });
    assert.strictEqual(getUsbAfterAuthDel.body.device, null);
    console.log('[PASS] Authenticated /api/usb-agent/* GET/POST/DELETE work and stay protected from unauthenticated mutation.');

    // 6. Authenticated access (Bearer & Cookie)
    for (const route of protectedGetRoutes) {
      const authRes = await apiRequest(port, {
        path: route,
        headers: { Authorization: `Bearer ${mattToken}` },
      });
      assert.strictEqual(authRes.status, 200);
      assert.strictEqual(authRes.body.ok, true);
    }
    const cookieRes = await apiRequest(port, {
      path: '/api/repairs',
      headers: { Cookie: `sos_session=${mattToken}` },
    });
    assert.strictEqual(cookieRes.status, 200);
    assert.strictEqual(cookieRes.body.ok, true);
    console.log('[PASS] Bearer token and Cookie session authentication verified.');

    // 7. Hardcoded fallback PIN "1234" for Matt MUST FAIL on /api/verify-pin
    const fallbackPinRes = await apiRequest(port, {
      path: '/api/verify-pin',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mattToken}` },
    }, { pin: '1234' });
    assert.strictEqual(fallbackPinRes.body.ok, false, 'Fallback PIN "1234" must be rejected for Matt');

    const validPinRes = await apiRequest(port, {
      path: '/api/verify-pin',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mattToken}` },
    }, { pin: TEST_PIN });
    assert.strictEqual(validPinRes.body.ok, true);
    console.log('[PASS] Removed hardcoded PIN fallback ("1234") rejected; stored PIN hash verified.');

    // 8. Hardcoded fallback passwords for Matt MUST FAIL on /api/change-own-password
    for (const fallbackPw of ['1234!', '1234']) {
      const res = await apiRequest(port, {
        path: '/api/change-own-password',
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mattToken}` },
      }, { currentPassword: fallbackPw, newPassword: 'HijackedPassword1!' });
      assert.strictEqual(res.body.ok, false, `/api/change-own-password must reject fallback "${fallbackPw}"`);
    }

    // 9. Consistent minimum 8-character password policy across self-change, create user, and reset credentials
    const shortSelfPw = await apiRequest(port, {
      path: '/api/change-own-password',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mattToken}` },
    }, { currentPassword: TEST_PASSWORD, newPassword: '1234567' });
    assert.strictEqual(shortSelfPw.body.ok, false, '/api/change-own-password must reject < 8 char passwords');

    const shortCreatePw = await apiRequest(port, {
      path: '/api/users',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mattToken}` },
    }, { username: 'Technician2', password: '1234567', pin: '3344', role: 'user' });
    assert.strictEqual(shortCreatePw.body.ok, false, 'POST /api/users must reject < 8 char passwords');

    const validCreatePw = await apiRequest(port, {
      path: '/api/users',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mattToken}` },
    }, { username: 'Technician2', password: 'ValidTechPassword8!', pin: '3344', role: 'user' });
    assert.strictEqual(validCreatePw.body.ok, true, 'POST /api/users must accept >= 8 char passwords');

    const shortResetPw = await apiRequest(port, {
      path: '/api/users/reset-credentials',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mattToken}` },
    }, { username: 'Technician1', password: '1234567' });
    assert.strictEqual(shortResetPw.body.ok, false, '/api/users/reset-credentials must reject < 8 char passwords');
    console.log('[PASS] Consistent >= 8 character password policy enforced on self-change, create, and admin reset.');

    // 10. Admin can securely change own password (which invalidates active sessions), re-auth, change PIN, and reset user credentials
    const NEW_PASSWORD = 'UpdatedMattPassword99!';
    const changePwRes = await apiRequest(port, {
      path: '/api/change-own-password',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mattToken}` },
    }, { currentPassword: TEST_PASSWORD, newPassword: NEW_PASSWORD });
    assert.strictEqual(changePwRes.body.ok, true);
    assert.strictEqual(changePwRes.body.reauthRequired, true);

    // Performing session token must now be revoked
    const revokedCheck = await apiRequest(port, {
      path: '/api/users',
      headers: { Authorization: `Bearer ${mattToken}` },
    });
    assert.strictEqual(revokedCheck.status, 401, 'Session performing password change must be invalidated immediately');

    const oldPwLogin = await apiRequest(port, {
      path: '/api/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, { username: 'Matt', password: TEST_PASSWORD });
    assert.strictEqual(oldPwLogin.body.ok, false);

    const newPwLogin = await apiRequest(port, {
      path: '/api/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, { username: 'Matt', password: NEW_PASSWORD });
    assert.strictEqual(newPwLogin.body.ok, true);
    mattToken = newPwLogin.body.token;

    const badChangePin = await apiRequest(port, {
      path: '/api/change-own-pin',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mattToken}` },
    }, { currentPassword: '1234!', newPin: '2468' });
    assert.strictEqual(badChangePin.body.ok, false);

    const NEW_PIN = '2468';
    const goodChangePin = await apiRequest(port, {
      path: '/api/change-own-pin',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mattToken}` },
    }, { currentPassword: NEW_PASSWORD, newPin: NEW_PIN });
    assert.strictEqual(goodChangePin.body.ok, true);

    const oldPinCheck = await apiRequest(port, {
      path: '/api/verify-pin',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mattToken}` },
    }, { pin: TEST_PIN });
    assert.strictEqual(oldPinCheck.body.ok, false);

    const newPinCheck = await apiRequest(port, {
      path: '/api/verify-pin',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mattToken}` },
    }, { pin: NEW_PIN });
    assert.strictEqual(newPinCheck.body.ok, true);

    const resetRes = await apiRequest(port, {
      path: '/api/users/reset-credentials',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mattToken}` },
    }, { username: 'Technician1', password: 'NewTechPassword7!', pin: '9012' });
    assert.strictEqual(resetRes.body.ok, true);

    const techNewLogin = await apiRequest(port, {
      path: '/api/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, { username: 'Technician1', password: 'NewTechPassword7!' });
    assert.strictEqual(techNewLogin.body.ok, true);
    const techToken = techNewLogin.body.token;

    console.log('[PASS] Admin self-service password/PIN changes and user credential reset verified.');

    // 11. Full endpoint audit coverage: remaining unauthenticated (401), role authz (403), and CRUD routes
    const extraUnauthChecks = [
      { method: 'POST', path: '/api/verify-pin', body: { pin: '1234' } },
      { method: 'POST', path: '/api/change-own-password', body: { currentPassword: 'x', newPassword: 'LongPassword1!' } },
      { method: 'POST', path: '/api/change-own-pin', body: { currentPassword: 'x', newPin: '4321' } },
      { method: 'POST', path: '/api/set-theme', body: { theme: 'dark' } },
      { method: 'POST', path: '/api/lock-shown', body: {} },
      { method: 'GET', path: '/api/users' },
      { method: 'POST', path: '/api/users', body: { username: 'X', password: 'Password123!', pin: '1234' } },
      { method: 'POST', path: '/api/users/delete', body: { username: 'Technician1' } },
      { method: 'POST', path: '/api/users/reset-credentials', body: { username: 'Technician1', pin: '1111' } },
      { method: 'GET', path: '/api/settings' },
      { method: 'POST', path: '/api/settings', body: { idleLockMinutes: 10 } },
      { method: 'GET', path: '/api/modules' },
      { method: 'GET', path: '/api/check-updates' },
      { method: 'GET', path: '/api/activity' },
      { method: 'POST', path: '/api/gamepad-reports', body: { id: 'gp-1' } },
      { method: 'PATCH', path: '/api/gamepad-reports/gp-1/sku', body: { sku: 'SKU1' } },
      { method: 'DELETE', path: '/api/gamepad-reports/gp-1' },
      { method: 'POST', path: '/api/phone-reports', body: { id: 'ph-1' } },
      { method: 'PATCH', path: '/api/phone-reports/ph-1/sku', body: { sku: 'SKU2' } },
      { method: 'DELETE', path: '/api/phone-reports/ph-1' },
      { method: 'POST', path: '/api/repairs', body: { id: 'rep-1' } },
      { method: 'PATCH', path: '/api/repairs/rep-1/status', body: { status: 'Done' } },
      { method: 'DELETE', path: '/api/repairs/rep-1' },
      { method: 'POST', path: '/api/games', body: { storeGames: [] } },
      { method: 'POST', path: '/api/games/sync-cex', body: {} },
      { method: 'GET', path: '/api/cex-lookup?barcode=711719548231' },
      { method: 'GET', path: '/api/bullion-rates' },
      { method: 'GET', path: '/modules/beta.html' },
      { method: 'GET', path: '/api/beta/projects' },
      { method: 'POST', path: '/api/beta/projects', body: { id: 'beta-1' } },
      { method: 'DELETE', path: '/api/beta/projects/beta-1' },
      { method: 'POST', path: '/api/beta/integrate', body: { slug: 'test', htmlContent: '<p>x</p>' } },
    ];
    for (const chk of extraUnauthChecks) {
      const r = await apiRequest(port, {
        path: chk.path,
        method: chk.method,
        headers: chk.body ? { 'Content-Type': 'application/json' } : {},
      }, chk.body);
      assert.strictEqual(r.status, 401, `Expected 401 for unauthenticated ${chk.method} ${chk.path}, got ${r.status}`);
    }

    // Non-admin (Technician1) MUST get 403 on all admin & Matt-only endpoints
    const nonAdminForbiddenChecks = [
      { method: 'GET', path: '/api/users' },
      { method: 'POST', path: '/api/users', body: { username: 'Escalated', password: 'Password123!', pin: '1234', role: 'admin' } },
      { method: 'POST', path: '/api/users/delete', body: { username: 'Technician2' } },
      { method: 'POST', path: '/api/users/reset-credentials', body: { username: 'Matt', password: 'Password123!' } },
      { method: 'POST', path: '/api/settings', body: { idleLockMinutes: 99 } },
      { method: 'GET', path: '/api/activity' },
      { method: 'GET', path: '/modules/beta.html' },
      { method: 'GET', path: '/api/beta/projects' },
      { method: 'POST', path: '/api/beta/projects', body: { id: 'beta-1' } },
      { method: 'DELETE', path: '/api/beta/projects/beta-1' },
      { method: 'POST', path: '/api/beta/integrate', body: { slug: 'evil', htmlContent: '<p>x</p>' } },
    ];
    for (const chk of nonAdminForbiddenChecks) {
      const r = await apiRequest(port, {
        path: chk.path,
        method: chk.method,
        headers: {
          Authorization: `Bearer ${techToken}`,
          ...(chk.body ? { 'Content-Type': 'application/json' } : {}),
        },
      }, chk.body);
      assert.strictEqual(r.status, 403, `Expected 403 for non-admin ${chk.method} ${chk.path}, got ${r.status}`);
    }

    // SecondAdmin (role admin, not Matt) can access admin routes, but gets 403 on Matt-only beta routes
    const createAdmin2 = await apiRequest(port, {
      path: '/api/users',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mattToken}` },
    }, { username: 'SecondAdmin', password: 'SecondAdminPass9!', pin: '1357', role: 'admin' });
    assert.strictEqual(createAdmin2.body.ok, true);

    const admin2Login = await apiRequest(port, {
      path: '/api/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, { username: 'SecondAdmin', password: 'SecondAdminPass9!' });
    const admin2Token = admin2Login.body.token;

    const admin2Users = await apiRequest(port, {
      path: '/api/users',
      headers: { Authorization: `Bearer ${admin2Token}` },
    });
    assert.strictEqual(admin2Users.status, 200);

    const admin2Beta = await apiRequest(port, {
      path: '/api/beta/projects',
      headers: { Authorization: `Bearer ${admin2Token}` },
    });
    assert.strictEqual(admin2Beta.status, 403, 'Non-Matt admin must get 403 on Matt-only beta routes');

    const admin2BetaHtml = await apiRequest(port, {
      path: '/modules/beta.html',
      headers: { Authorization: `Bearer ${admin2Token}` },
    });
    assert.strictEqual(admin2BetaHtml.status, 403);

    // Authenticated functional smoke checks for remaining covered routes
    const techSettings = await apiRequest(port, {
      path: '/api/settings',
      headers: { Authorization: `Bearer ${techToken}` },
    });
    assert.strictEqual(techSettings.status, 200);
    assert.strictEqual(techSettings.body.readOnly, true);
    assert.strictEqual(techSettings.body.settings.modules, undefined, 'Non-admin /api/settings must omit admin module config');

    const techModules = await apiRequest(port, {
      path: '/api/modules',
      headers: { Authorization: `Bearer ${techToken}` },
    });
    assert.strictEqual(techModules.status, 200);
    assert.strictEqual(techModules.body.modules.beta, undefined, 'Non-Matt /api/modules must omit beta module');

    const adminSettingsSave = await apiRequest(port, {
      path: '/api/settings',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mattToken}` },
    }, { idleLockMinutes: 7 });
    assert.strictEqual(adminSettingsSave.status, 200);
    assert.strictEqual(adminSettingsSave.body.settings.idleLockMinutes, 7);

    const updatesRes = await apiRequest(port, {
      path: '/api/check-updates',
      headers: { Authorization: `Bearer ${techToken}` },
    });
    assert.strictEqual(updatesRes.status, 200);

    const cexAuthRes = await apiRequest(port, {
      path: '/api/cex-lookup?barcode=711719548231',
      headers: { Authorization: `Bearer ${techToken}` },
    });
    assert.strictEqual(cexAuthRes.status, 200);
    assert.strictEqual(cexAuthRes.body.ok, true);

    const setThemeRes = await apiRequest(port, {
      path: '/api/set-theme',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${techToken}` },
    }, { theme: 'blue' });
    assert.strictEqual(setThemeRes.body.ok, true);

    const lockShownRes = await apiRequest(port, {
      path: '/api/lock-shown',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${techToken}` },
    }, {});
    assert.strictEqual(lockShownRes.body.ok, true);

    // Matt beta endpoints work for Matt
    const mattBetaHtml = await apiRequest(port, {
      path: '/modules/beta.html',
      headers: { Authorization: `Bearer ${mattToken}` },
    });
    assert.strictEqual(mattBetaHtml.status, 200);

    const healthRes = await apiRequest(port, { path: '/healthz' });
    assert.strictEqual(healthRes.status, 200);
    assert.strictEqual(healthRes.body.ok, true);

    console.log('[PASS] Full API endpoint authentication, RBAC (admin vs user vs Matt), and CRUD protections verified.');
  } finally {
    await stopServer(child);
  }
}

async function testAdminCliScripts() {
  console.log('\n=== Test Suite 3: verify-admin-credential & set-admin-credential CLI Safeguards ===');
  const cliDataDir = makeTempDir('sos-cli-');
  const usersFile = path.join(cliDataDir, 'users.json');

  const MATT_PW = 'CliInitialPass9!';
  const MATT_PIN = '7410';
  const TECH_PW = 'TechUntouched8!';
  const TECH_PIN = '3690';
  const techCreds = makeCredentials(TECH_PW);
  const techPinCreds = makeCredentials(TECH_PIN);

  const initialUsers = [
    {
      username: 'Matt',
      role: 'admin',
      createdAt: '2026-01-01T00:00:00.000Z',
      password: makeCredentials(MATT_PW),
      pin: makeCredentials(MATT_PIN),
      mustChangePassword: false,
      theme: 'yellow',
    },
    {
      username: 'Technician1',
      role: 'user',
      createdAt: '2026-01-02T00:00:00.000Z',
      password: techCreds,
      pin: techPinCreds,
      mustChangePassword: false,
      theme: 'dark',
    },
  ];
  const initialJson = JSON.stringify(initialUsers, null, 2);
  fs.writeFileSync(usersFile, initialJson, { encoding: 'utf8', mode: 0o600 });
  fs.chmodSync(usersFile, 0o600);

  // 1. verify-admin-credential.js checks BOTH password and PIN independently
  const verifyBothOk = await runCli(VERIFY_CLI_PATH, [], ['Matt', MATT_PW, MATT_PIN], { SOS_DATA_DIR: cliDataDir });
  assert.strictEqual(verifyBothOk.code, 0, 'verify-admin-credential must exit 0 only when BOTH password and PIN match');
  assert.ok(verifyBothOk.stdout.includes('[PASSWORD] MATCH'));
  assert.ok(verifyBothOk.stdout.includes('[PIN]      MATCH'));
  assert.ok(verifyBothOk.stdout.includes('[VERDICT] SAFE'));

  const verifyPinBad = await runCli(VERIFY_CLI_PATH, [], ['Matt', MATT_PW, '0000'], { SOS_DATA_DIR: cliDataDir });
  assert.strictEqual(verifyPinBad.code, 1, 'verify-admin-credential must exit 1 when password matches but PIN mismatches');
  assert.ok(verifyPinBad.stdout.includes('[PASSWORD] MATCH'));
  assert.ok(verifyPinBad.stdout.includes('[PIN]      MISMATCH'));
  assert.strictEqual(verifyPinBad.stdout.includes('[VERDICT] SAFE'), false, 'Must NEVER report SAFE on PIN mismatch');

  const verifyPinSkipped = await runCli(VERIFY_CLI_PATH, [], ['Matt', MATT_PW, ''], { SOS_DATA_DIR: cliDataDir });
  assert.strictEqual(verifyPinSkipped.code, 1, 'verify-admin-credential must exit 1 when PIN is skipped');
  assert.ok(verifyPinSkipped.stdout.includes('[PASSWORD] MATCH'));
  assert.ok(verifyPinSkipped.stdout.includes('[PIN]      SKIPPED'));
  assert.strictEqual(verifyPinSkipped.stdout.includes('[VERDICT] SAFE'), false, 'Must NEVER report SAFE when PIN is skipped');

  const verifyPwBadPinOk = await runCli(VERIFY_CLI_PATH, [], ['Matt', 'WrongPass1!', MATT_PIN], { SOS_DATA_DIR: cliDataDir });
  assert.strictEqual(verifyPwBadPinOk.code, 1);
  assert.ok(verifyPwBadPinOk.stdout.includes('[PASSWORD] MISMATCH'));
  assert.ok(verifyPwBadPinOk.stdout.includes('[PIN]      MATCH'));

  // 1b. verify-admin-credential.js MUST NOT trust local JSON mirror or report SAFE in MongoDB mode
  const verifyMongoUnreachable = await runCli(VERIFY_CLI_PATH, [], ['Matt', MATT_PW, MATT_PIN], {
    SOS_DATA_DIR: cliDataDir,
    MONGODB_URI: 'mongodb://127.0.0.1:27999/sos-tools-test',
  });
  assert.strictEqual(verifyMongoUnreachable.code, 1, 'verify-admin-credential must exit 1 when MongoDB is unreachable');
  const mongoOut = verifyMongoUnreachable.stdout + verifyMongoUnreachable.stderr;
  assert.strictEqual(mongoOut.includes('[VERDICT] SAFE'), false, 'Must NEVER report SAFE in MongoDB mode from local JSON mirror');
  assert.ok(mongoOut.includes('MongoDB') && mongoOut.includes('NOT SAFE'));

  // 1c. Positive-path and negative-path MongoDB verification using controlled MongoClient preload mock
  const MONGO_MATT_PW = 'MongoLiveSecret99!';
  const MONGO_MATT_PIN = '2580';
  const mockDocs = [
    {
      username: 'Matt',
      role: 'admin',
      password: makeCredentials(MONGO_MATT_PW),
      pin: makeCredentials(MONGO_MATT_PIN),
    },
  ];
  const mockTraceFile = path.join(cliDataDir, 'mongo-trace.json');
  const mockDocsFile = path.join(cliDataDir, 'mongo-docs.json');
  const mockPreloadFile = path.join(cliDataDir, 'mock-mongo-preload.js');
  fs.writeFileSync(mockDocsFile, JSON.stringify(mockDocs), 'utf8');
  fs.writeFileSync(mockPreloadFile, `
    const fs = require('fs');
    const Module = require('module');
    const origLoad = Module._load;
    const docs = JSON.parse(fs.readFileSync(process.env.MOCK_MONGO_DOCS_FILE, 'utf8'));
    const trace = { connects: 0, closes: 0, queries: [] };
    class MockMongoClient {
      constructor(uri) { this.uri = uri; }
      async connect() { trace.connects++; }
      db(dbName) {
        return {
          collection: (colName) => ({
            find: (filter) => ({
              toArray: async () => {
                trace.queries.push({ uri: this.uri, dbName, colName, filter });
                return docs;
              },
            }),
          }),
        };
      }
      async close() {
        trace.closes++;
        fs.writeFileSync(process.env.MOCK_MONGO_TRACE_FILE, JSON.stringify(trace), 'utf8');
      }
    }
    Module._load = function (request, parent, isMain) {
      if (request === 'mongodb') return { MongoClient: MockMongoClient };
      return origLoad.call(this, request, parent, isMain);
    };
  `, 'utf8');

  const runMongoMockVerify = (pw, pin) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-r', mockPreloadFile, VERIFY_CLI_PATH, 'Matt'], {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        SOS_DATA_DIR: cliDataDir,
        MONGODB_URI: 'mongodb://127.0.0.1:27017/sos-tools-verify-db?authSource=admin',
        MOCK_MONGO_DOCS_FILE: mockDocsFile,
        MOCK_MONGO_TRACE_FILE: mockTraceFile,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const t = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('Mongo mock verify timed out')); }, 10000);
    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('exit', (code) => { clearTimeout(t); resolve({ code, stdout, stderr }); });
    child.stdin.write(['Matt', pw, pin].join('\n') + '\n');
    child.stdin.end();
  });

  // Positive path: valid Mongo password + PIN -> SAFE & exit 0 (even though local users.json has DIFFERENT hashes!)
  const mongoOk = await runMongoMockVerify(MONGO_MATT_PW, MONGO_MATT_PIN);
  assert.strictEqual(mongoOk.code, 0, `MongoDB valid credentials must exit 0.\nOUT:\n${mongoOk.stdout}\nERR:\n${mongoOk.stderr}`);
  assert.ok(mongoOk.stdout.includes('[PASSWORD] MATCH'));
  assert.ok(mongoOk.stdout.includes('[PIN]      MATCH'));
  assert.ok(mongoOk.stdout.includes('[VERDICT] SAFE'));
  assert.ok(mongoOk.stdout.includes('sos-tools-verify-db'));
  const traceData = JSON.parse(fs.readFileSync(mockTraceFile, 'utf8'));
  assert.strictEqual(traceData.connects, 1);
  assert.strictEqual(traceData.closes, 1);
  assert.strictEqual(traceData.queries[0].dbName, 'sos-tools-verify-db');
  assert.strictEqual(traceData.queries[0].colName, 'users');

  // Conflicting local JSON credentials MUST FAIL in MongoDB mode (proving local mirror is never checked)
  const mongoStaleLocal = await runMongoMockVerify(MATT_PW, MATT_PIN);
  assert.strictEqual(mongoStaleLocal.code, 1, 'Stale local users.json credentials must fail in MongoDB mode');
  assert.ok(mongoStaleLocal.stdout.includes('[PASSWORD] MISMATCH'));
  assert.ok(mongoStaleLocal.stdout.includes('[PIN]      MISMATCH'));
  assert.strictEqual(mongoStaleLocal.stdout.includes('[VERDICT] SAFE'), false);

  // Wrong PIN in MongoDB mode -> exit 1 & UNSAFE
  const mongoBadPin = await runMongoMockVerify(MONGO_MATT_PW, '9999');
  assert.strictEqual(mongoBadPin.code, 1, 'Wrong PIN in MongoDB mode must exit 1');
  assert.ok(mongoBadPin.stdout.includes('[PASSWORD] MATCH'));
  assert.ok(mongoBadPin.stdout.includes('[PIN]      MISMATCH'));
  assert.strictEqual(mongoBadPin.stdout.includes('[VERDICT] SAFE'), false);
  try { fs.unlinkSync(mockTraceFile); fs.unlinkSync(mockDocsFile); fs.unlinkSync(mockPreloadFile); } catch (e) {}

  console.log('[PASS] verify-admin-credential.js verifies password & PIN independently (JSON & MongoDB) and refuses local JSON fallback in MongoDB mode.');

  // 2. set-admin-credential.js MUST refuse MongoDB mode and leave users.json untouched
  const mongoRefused = await runCli(SET_CLI_PATH, ['Matt'], [], {
    SOS_DATA_DIR: cliDataDir,
    MONGODB_URI: 'mongodb://127.0.0.1:27017/sos-tools-test',
  });
  assert.strictEqual(mongoRefused.code, 1, 'set-admin-credential must refuse when MONGODB_URI is configured');
  assert.ok((mongoRefused.stdout + mongoRefused.stderr).includes('MongoDB'));
  assert.strictEqual(fs.readFileSync(usersFile, 'utf8'), initialJson, 'MongoDB refusal must leave users.json untouched');

  // 3. set-admin-credential.js MUST refuse while server is running against cliDataDir
  const cliServerPort = 4001;
  const { child: runningChild } = await startServer({ port: cliServerPort, dataDir: cliDataDir });
  try {
    const liveRefused = await runCli(SET_CLI_PATH, ['Matt'], ['Matt', 'ShouldNotWrite1!', 'ShouldNotWrite1!', '1234'], {
      SOS_DATA_DIR: cliDataDir,
      PORT: String(cliServerPort),
    });
    assert.strictEqual(liveRefused.code, 1, 'set-admin-credential must refuse while live server is running');
    const combinedLiveOut = liveRefused.stdout + liveRefused.stderr;
    assert.ok(combinedLiveOut.includes('Target data directory:'));
    assert.ok(combinedLiveOut.includes('Target user file:'));
    assert.ok(combinedLiveOut.includes('[REFUSED]'));
    assert.ok(combinedLiveOut.includes('Safe Offline Recovery Procedure'));
    assert.strictEqual(fs.readFileSync(usersFile, 'utf8'), initialJson, 'Live-server refusal must leave users.json untouched');
  } finally {
    await stopServer(runningChild);
  }

  // 3b. Unsafe recovery conditions: unreadable /proc, inaccessible server env, and non-Linux must fail closed
  const setCliMod = require(SET_CLI_PATH);
  const nonLinuxState = await setCliMod.resolveServerSafetyState(usersFile, { platform: 'darwin', env: {} });
  assert.strictEqual(nonLinuxState.safe, false);
  assert.strictEqual(nonLinuxState.uncertain, true);

  const eaccesProcFs = {
    readdirSync: () => ['9999'],
    readFileSync: (p) => {
      if (String(p).endsWith('cmdline')) return Buffer.from('node\0server.js\0');
      const err = new Error('permission denied');
      err.code = 'EACCES';
      throw err;
    },
    readlinkSync: () => ROOT_DIR,
    existsSync: () => true,
  };
  const uncertainEnvState = await setCliMod.resolveServerSafetyState(usersFile, {
    platform: 'linux',
    procDir: '/mock-proc',
    fs: eaccesProcFs,
    env: {},
  });
  assert.strictEqual(uncertainEnvState.safe, false, 'Unreadable /proc environ for server.js must fail closed');
  assert.strictEqual(uncertainEnvState.uncertain, true);

  // 3c. Concurrent file modification (TOCTOU protection) aborts cleanly without overwriting external changes
  const toctouResult = await new Promise((resolve, reject) => {
    const env = { ...process.env, SOS_DATA_DIR: cliDataDir };
    delete env.MONGODB_URI;
    delete env.PORT;
    const cliChild = spawn(process.execPath, [SET_CLI_PATH, 'Matt'], {
      cwd: ROOT_DIR,
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    let modified = false;
    const t = setTimeout(() => {
      cliChild.kill('SIGKILL');
      reject(new Error('TOCTOU CLI test timed out'));
    }, 10000);

    cliChild.stdout.on('data', (d) => {
      out += d.toString();
      if (!modified && out.includes('Enter NEW password')) {
        modified = true;
        // Externally modify users.json while CLI is paused at prompt
        const current = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
        current[1].theme = 'blue';
        fs.writeFileSync(usersFile, JSON.stringify(current, null, 2), { encoding: 'utf8', mode: 0o600 });
        fs.chmodSync(usersFile, 0o600);
        cliChild.stdin.write('ConcurrentShouldFail9!\nConcurrentShouldFail9!\n4444\n');
        cliChild.stdin.end();
      }
    });
    cliChild.stderr.on('data', (d) => { err += d.toString(); });
    cliChild.on('exit', (code) => {
      clearTimeout(t);
      resolve({ code, stdout: out, stderr: err });
    });
    cliChild.stdin.write('Matt\n');
  });
  assert.strictEqual(toctouResult.code, 1, 'CLI must abort when users.json changes between read and write');
  assert.ok((toctouResult.stdout + toctouResult.stderr).includes('modified on disk between reading and writing'));
  const afterToctou = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
  assert.strictEqual(afterToctou[1].theme, 'blue', 'External modification must not be overwritten');
  // Restore initialUsers with 0o600 permissions before step 4
  fs.writeFileSync(usersFile, initialJson, { encoding: 'utf8', mode: 0o600 });
  fs.chmodSync(usersFile, 0o600);

  console.log('[PASS] set-admin-credential.js refuses MongoDB, live servers, uncertain /proc states, and concurrent file edits.');

  // 4. set-admin-credential.js succeeds offline, rejects < 8 char passwords, preserves 0600 permissions, updates Matt only
  const shortPwCli = await runCli(SET_CLI_PATH, ['Matt'], ['Matt', 'short77', 'short77', ''], {
    SOS_DATA_DIR: cliDataDir,
  });
  assert.strictEqual(shortPwCli.code, 1);
  assert.strictEqual(fs.readFileSync(usersFile, 'utf8'), initialJson, 'Rejected short password must leave users.json untouched');

  const NEW_CLI_PW = 'RecoveredOfflinePass9!';
  const NEW_CLI_PIN = '6543';
  const offlineUpdate = await runCli(SET_CLI_PATH, ['Matt'], ['Matt', NEW_CLI_PW, NEW_CLI_PW, NEW_CLI_PIN], {
    SOS_DATA_DIR: cliDataDir,
  });
  assert.strictEqual(offlineUpdate.code, 0, `Offline CLI update should succeed.\nSTDERR:\n${offlineUpdate.stderr}`);
  assert.ok(offlineUpdate.stdout.includes('[SUCCESS]'));
  assert.ok(offlineUpdate.stdout.includes('Target data directory: ' + cliDataDir));
  assert.ok(offlineUpdate.stdout.includes('Target user file:      ' + usersFile));

  // Verify restrictive 0o600 permissions were preserved on users.json and backup file
  const updatedMode = fs.statSync(usersFile).mode & 0o777;
  assert.strictEqual(updatedMode, 0o600, `Expected users.json permissions 0600 preserved, got 0${updatedMode.toString(8)}`);
  const backupFiles = fs.readdirSync(cliDataDir).filter((f) => f.startsWith('users.json.bak.'));
  assert.strictEqual(backupFiles.length, 1, 'Expected pre-update backup file');
  const backupMode = fs.statSync(path.join(cliDataDir, backupFiles[0])).mode & 0o777;
  assert.strictEqual(backupMode, 0o600, `Expected backup file permissions 0600, got 0${backupMode.toString(8)}`);

  const updatedUsers = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
  assert.strictEqual(updatedUsers.length, 2, 'Existing accounts must be preserved');
  const updatedTech = updatedUsers.find((u) => u.username === 'Technician1');
  assert.deepStrictEqual(updatedTech.password, techCreds, 'Other account password hash must be untouched');
  assert.deepStrictEqual(updatedTech.pin, techPinCreds, 'Other account PIN hash must be untouched');

  // Verify updated credentials pass verify-admin-credential.js and real server login
  const verifyUpdated = await runCli(VERIFY_CLI_PATH, [], ['Matt', NEW_CLI_PW, NEW_CLI_PIN], {
    SOS_DATA_DIR: cliDataDir,
  });
  assert.strictEqual(verifyUpdated.code, 0, 'Updated credentials must verify clean with exit 0');

  const { child: postRecoveryChild } = await startServer({ port: 4002, dataDir: cliDataDir });
  try {
    const recoveredLogin = await apiRequest(4002, {
      path: '/api/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, { username: 'Matt', password: NEW_CLI_PW });
    assert.strictEqual(recoveredLogin.body.ok, true);

    const recoveredPin = await apiRequest(4002, {
      path: '/api/verify-pin',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${recoveredLogin.body.token}` },
    }, { pin: NEW_CLI_PIN });
    assert.strictEqual(recoveredPin.body.ok, true);
  } finally {
    await stopServer(postRecoveryChild);
  }
  console.log('[PASS] Offline set-admin-credential.js preserves 0600 permissions, updates target hashes cleanly, and boots cleanly.');

  // 5. Hardening checks for 0644 -> 0600 tightening, ownership preservation under sudo/root, and EPERM abort
  const permDir = makeTempDir('sos-cli-perm-');
  const permUsersFile = path.join(permDir, 'users.json');
  const unrelatedFile = path.join(permDir, 'settings.json');
  const permUsers = [
    {
      username: 'Matt',
      role: 'admin',
      createdAt: '2026-01-01T00:00:00.000Z',
      password: makeCredentials('BeforeTighten1!'),
      pin: makeCredentials('1111'),
      mustChangePassword: false,
      theme: 'yellow',
    },
  ];
  fs.writeFileSync(permUsersFile, JSON.stringify(permUsers, null, 2), { encoding: 'utf8', mode: 0o644 });
  fs.chmodSync(permUsersFile, 0o644);
  fs.writeFileSync(unrelatedFile, JSON.stringify({ idleLockMinutes: 5 }), { encoding: 'utf8', mode: 0o644 });
  fs.chmodSync(unrelatedFile, 0o644);

  // Check if running as root with a non-root user available (uid 1000) to test real elevated-privilege recovery
  const runningAsRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  let targetUid = runningAsRoot ? 1000 : process.getuid();
  let targetGid = runningAsRoot ? 1000 : process.getgid();
  if (runningAsRoot) {
    fs.chmodSync(permDir, 0o755);
    fs.chownSync(permDir, targetUid, targetGid);
    fs.chownSync(permUsersFile, targetUid, targetGid);
    fs.chownSync(unrelatedFile, targetUid, targetGid);
  }

  const statBefore = fs.statSync(permUsersFile);
  assert.strictEqual(statBefore.mode & 0o777, 0o644);
  assert.strictEqual(statBefore.uid, targetUid);
  assert.strictEqual(statBefore.gid, targetGid);

  const tightenedRes = await runCli(SET_CLI_PATH, ['Matt'], ['Matt', 'TightenedPass9!', 'TightenedPass9!', '2222'], {
    SOS_DATA_DIR: permDir,
  });
  assert.strictEqual(tightenedRes.code, 0, `Offline CLI recovery must succeed on 0644 file.\nSTDERR:\n${tightenedRes.stderr}`);

  const statAfter = fs.statSync(permUsersFile);
  assert.strictEqual(statAfter.mode & 0o777, 0o600, 'World-readable 0644 users.json MUST be tightened to 0600');
  assert.strictEqual(statAfter.uid, targetUid, 'Original file UID must be preserved (even when run by root)');
  assert.strictEqual(statAfter.gid, targetGid, 'Original file GID must be preserved');

  const permBackups = fs.readdirSync(permDir).filter((f) => f.startsWith('users.json.bak.'));
  assert.strictEqual(permBackups.length, 1);
  const bakStat = fs.statSync(path.join(permDir, permBackups[0]));
  assert.strictEqual(bakStat.mode & 0o777, 0o600, 'Backup file must have restrictive 0600 mode');
  assert.strictEqual(bakStat.uid, targetUid, 'Backup file UID must preserve original owner');
  assert.strictEqual(bakStat.gid, targetGid, 'Backup file GID must preserve original group');

  // Unrelated file permissions/ownership must remain untouched
  const unrelatedStatAfter = fs.statSync(unrelatedFile);
  assert.strictEqual(unrelatedStatAfter.mode & 0o777, 0o644, 'Unrelated file mode must NOT be changed');
  assert.strictEqual(unrelatedStatAfter.uid, targetUid, 'Unrelated file UID must NOT be changed');
  assert.strictEqual(unrelatedStatAfter.gid, targetGid, 'Unrelated file GID must NOT be changed');

  // Confirm app user (uid 1000) can read the resulting 0600 file when recovered via root/elevated privilege
  if (runningAsRoot) {
    const appReadOk = await new Promise((resolve, reject) => {
      const child = spawn(
        process.execPath,
        ['-e', `const u = JSON.parse(require('fs').readFileSync(${JSON.stringify(permUsersFile)}, 'utf8')); console.log(u[0].username);`],
        { uid: targetUid, gid: targetGid, stdio: ['ignore', 'pipe', 'pipe'] }
      );
      let out = '';
      let err = '';
      child.stdout.on('data', (d) => { out += d.toString(); });
      child.stderr.on('data', (d) => { err += d.toString(); });
      child.on('exit', (code) => resolve({ code, out: out.trim(), err }));
      child.on('error', reject);
    });
    assert.strictEqual(appReadOk.code, 0, `Service user (uid ${targetUid}) must still read resulting users.json: ${appReadOk.err}`);
    assert.strictEqual(appReadOk.out, 'Matt');
  }

  // 5b. Ownership-preservation failure (EPERM) must abort BEFORE replacing users.json and leave original untouched
  const failDir = makeTempDir('sos-cli-chown-fail-');
  const failUsersFile = path.join(failDir, 'users.json');
  const failOriginal = JSON.stringify(permUsers, null, 2);
  fs.writeFileSync(failUsersFile, failOriginal, { encoding: 'utf8', mode: 0o644 });
  fs.chmodSync(failUsersFile, 0o644);
  const failStat = fs.statSync(failUsersFile);
  const failingFs = {
    writeFileSync: (...args) => fs.writeFileSync(...args),
    chmodSync: (...args) => fs.chmodSync(...args),
    statSync: (...args) => fs.statSync(...args),
    existsSync: (...args) => fs.existsSync(...args),
    unlinkSync: (...args) => fs.unlinkSync(...args),
    renameSync: (...args) => fs.renameSync(...args),
    chownSync: (targetPath) => {
      if (String(targetPath).includes('.tmp.')) {
        const err = new Error('operation not permitted');
        err.code = 'EPERM';
        throw err;
      }
      return fs.chownSync(targetPath, failStat.uid, failStat.gid);
    },
  };
  assert.throws(
    () => setCliMod.atomicReplaceUsersFile({
      usersFile: failUsersFile,
      rawOriginal: failOriginal,
      updatedJson: JSON.stringify([{ username: 'Overwritten' }]),
      initialStat: failStat,
      backupFile: failUsersFile + '.bak.fail',
      tmpFile: failUsersFile + '.tmp.fail',
    }, failingFs),
    /Aborting before modifying.*operation not permitted/i
  );
  assert.strictEqual(fs.readFileSync(failUsersFile, 'utf8'), failOriginal, 'Original users.json must remain unchanged on ownership error');
  assert.strictEqual(fs.statSync(failUsersFile).mode & 0o777, 0o644);
  assert.strictEqual(fs.existsSync(failUsersFile + '.tmp.fail'), false, 'Temp file must be cleaned up on failure');
  assert.strictEqual(fs.existsSync(failUsersFile + '.bak.fail'), false, 'Uncommitted backup file must be cleaned up on failure');

  console.log('[PASS] 0644->0600 tightening, uid/gid ownership preservation under elevated privileges, and ownership-error abort verified.');
}

async function testSessionRevocationOnPasswordChanges() {
  console.log('\n=== Test Suite 4: Session Revocation on Password Change & Admin Reset ===');
  const dataDir = makeTempDir('sos-sess-revoke-');
  const port = 4003;

  const MATT_PW = 'MattAdminPass9!';
  const ALICE_PW = 'AliceInitialPass9!';
  const BOB_PW = 'BobInitialPass9!';
  const users = [
    {
      username: 'Matt',
      role: 'admin',
      createdAt: '2026-01-01T00:00:00.000Z',
      password: makeCredentials(MATT_PW),
      pin: makeCredentials('1111'),
      mustChangePassword: false,
      theme: 'yellow',
    },
    {
      username: 'Alice',
      role: 'user',
      createdAt: '2026-01-02T00:00:00.000Z',
      password: makeCredentials(ALICE_PW),
      pin: makeCredentials('2222'),
      mustChangePassword: false,
      theme: 'light',
    },
    {
      username: 'Bob',
      role: 'user',
      createdAt: '2026-01-03T00:00:00.000Z',
      password: makeCredentials(BOB_PW),
      pin: makeCredentials('3333'),
      mustChangePassword: false,
      theme: 'dark',
    },
  ];
  fs.writeFileSync(path.join(dataDir, 'users.json'), JSON.stringify(users, null, 2), 'utf8');

  const { child } = await startServer({ port, dataDir });
  try {
    const login = (u, p) => apiRequest(port, {
      path: '/api/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, { username: u, password: p });

    const aliceLoginA = await login('Alice', ALICE_PW);
    const aliceLoginB = await login('Alice', ALICE_PW);
    const bobLogin = await login('Bob', BOB_PW);
    const mattLogin = await login('Matt', MATT_PW);
    assert.strictEqual(aliceLoginA.body.ok, true);
    assert.strictEqual(aliceLoginB.body.ok, true);
    assert.strictEqual(bobLogin.body.ok, true);
    assert.strictEqual(mattLogin.body.ok, true);

    const aliceTokA = aliceLoginA.body.token;
    const aliceTokB = aliceLoginB.body.token;
    const bobTok = bobLogin.body.token;
    const mattTok = mattLogin.body.token;

    // 1. Failed password change MUST NOT invalidate existing sessions
    const wrongCurPw = await apiRequest(port, {
      path: '/api/change-own-password',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${aliceTokA}` },
    }, { currentPassword: 'WrongPassword!', newPassword: 'AliceNewStrongPassword1!' });
    assert.strictEqual(wrongCurPw.body.ok, false);

    const shortNewPw = await apiRequest(port, {
      path: '/api/change-own-password',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${aliceTokA}` },
    }, { currentPassword: ALICE_PW, newPassword: '123' });
    assert.strictEqual(shortNewPw.body.ok, false);

    for (const tok of [aliceTokA, aliceTokB, bobTok, mattTok]) {
      const okRes = await apiRequest(port, { path: '/api/repairs', headers: { Authorization: `Bearer ${tok}` } });
      assert.strictEqual(okRes.status, 200, 'Failed password change must not revoke any session');
    }

    // 2. Successful own password change invalidates ALL sessions for Alice (including performing session) & clears cookie
    const ALICE_NEW_PW = 'AliceChangedStrong9!';
    const aliceChangeRes = await apiRequest(port, {
      path: '/api/change-own-password',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: `sos_session=${aliceTokA}` },
    }, { currentPassword: ALICE_PW, newPassword: ALICE_NEW_PW });
    assert.strictEqual(aliceChangeRes.status, 200);
    assert.strictEqual(aliceChangeRes.body.ok, true);
    assert.strictEqual(aliceChangeRes.body.reauthRequired, true);
    assert.strictEqual(aliceChangeRes.body.sessionsRevoked, 2);
    const setCookieHeader = String(aliceChangeRes.headers['set-cookie'] || '');
    assert.ok(setCookieHeader.includes('sos_session=;'), 'Response must clear sos_session cookie');

    // Both Alice sessions stop working immediately
    assert.strictEqual((await apiRequest(port, { path: '/api/repairs', headers: { Cookie: `sos_session=${aliceTokA}` } })).status, 401);
    assert.strictEqual((await apiRequest(port, { path: '/api/repairs', headers: { Authorization: `Bearer ${aliceTokB}` } })).status, 401);

    // Other users' sessions remain completely valid
    assert.strictEqual((await apiRequest(port, { path: '/api/repairs', headers: { Authorization: `Bearer ${bobTok}` } })).status, 200);
    assert.strictEqual((await apiRequest(port, { path: '/api/repairs', headers: { Authorization: `Bearer ${mattTok}` } })).status, 200);

    // Alice cannot log in with old password, MUST authenticate with new password
    assert.strictEqual((await login('Alice', ALICE_PW)).body.ok, false);
    const aliceReauth = await login('Alice', ALICE_NEW_PW);
    assert.strictEqual(aliceReauth.body.ok, true);
    assert.strictEqual((await apiRequest(port, { path: '/api/repairs', headers: { Authorization: `Bearer ${aliceReauth.body.token}` } })).status, 200);

    // 3. Failed admin reset (<8 chars) must NOT invalidate Bob's session
    const failedReset = await apiRequest(port, {
      path: '/api/users/reset-credentials',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mattTok}` },
    }, { username: 'Bob', password: 'short' });
    assert.strictEqual(failedReset.body.ok, false);
    assert.strictEqual((await apiRequest(port, { path: '/api/repairs', headers: { Authorization: `Bearer ${bobTok}` } })).status, 200);

    // 4. Successful admin password reset invalidates Bob's session without affecting Alice or Matt
    const BOB_NEW_PW = 'BobResetByAdmin9!';
    const resetBob = await apiRequest(port, {
      path: '/api/users/reset-credentials',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mattTok}` },
    }, { username: 'Bob', password: BOB_NEW_PW });
    assert.strictEqual(resetBob.body.ok, true);
    assert.strictEqual(resetBob.body.sessionsRevoked, 1);

    assert.strictEqual((await apiRequest(port, { path: '/api/repairs', headers: { Authorization: `Bearer ${bobTok}` } })).status, 401, 'Bob session must be revoked after admin reset');
    assert.strictEqual((await apiRequest(port, { path: '/api/repairs', headers: { Authorization: `Bearer ${aliceReauth.body.token}` } })).status, 200);
    assert.strictEqual((await apiRequest(port, { path: '/api/repairs', headers: { Authorization: `Bearer ${mattTok}` } })).status, 200);

    // Bob old password fails, new password works
    assert.strictEqual((await login('Bob', BOB_PW)).body.ok, false);
    const bobReauth = await login('Bob', BOB_NEW_PW);
    assert.strictEqual(bobReauth.body.ok, true);

    // 5. Admin resetting their own password also invalidates their own active session and clears cookie
    const MATT_NEW_PW = 'MattResetSelfPass9!';
    const resetSelf = await apiRequest(port, {
      path: '/api/users/reset-credentials',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: `sos_session=${mattTok}` },
    }, { username: 'Matt', password: MATT_NEW_PW });
    assert.strictEqual(resetSelf.body.ok, true);
    assert.strictEqual(resetSelf.body.reauthRequired, true);
    assert.ok(String(resetSelf.headers['set-cookie'] || '').includes('sos_session=;'));
    assert.strictEqual((await apiRequest(port, { path: '/api/users', headers: { Cookie: `sos_session=${mattTok}` } })).status, 401);
    assert.strictEqual((await login('Matt', MATT_NEW_PW)).body.ok, true);

    console.log('[PASS] Password changes and admin resets revoke affected sessions, preserve unrelated sessions, and require re-auth.');
  } finally {
    await stopServer(child);
  }
}

async function testServerRateLimiting() {
  console.log('\n=== Test Suite 5: Server-Side Rate Limiting (/login, /verify-pin, /setup) ===');
  const dataDir = makeTempDir('sos-ratelimit-');
  const port = 4004;

  const MATT_PW = 'RateLimitMattPass9!';
  const MATT_PIN = '6142';
  const TECH_PW = 'RateLimitTechPass9!';
  const TECH_PIN = '7351';
  const users = [
    {
      username: 'Matt',
      role: 'admin',
      createdAt: '2026-01-01T00:00:00.000Z',
      password: makeCredentials(MATT_PW),
      pin: makeCredentials(MATT_PIN),
      mustChangePassword: false,
      theme: 'yellow',
    },
    {
      username: 'PinUser',
      role: 'user',
      createdAt: '2026-01-02T00:00:00.000Z',
      password: makeCredentials(TECH_PW),
      pin: makeCredentials(TECH_PIN),
      mustChangePassword: false,
      theme: 'dark',
    },
  ];
  fs.writeFileSync(path.join(dataDir, 'users.json'), JSON.stringify(users, null, 2), 'utf8');

  const { child } = await startServer({ port, dataDir });
  try {
    // 1. Valid login clears per-(ip, username) failure counter before lockout
    for (let i = 0; i < 3; i++) {
      const r = await apiRequest(port, {
        path: '/api/login',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }, { username: 'Matt', password: 'WrongPassword!' });
      assert.strictEqual(r.status, 200);
      assert.strictEqual(r.body.ok, false);
    }
    const validClearLogin = await apiRequest(port, {
      path: '/api/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, { username: 'Matt', password: MATT_PW });
    assert.strictEqual(validClearLogin.body.ok, true);

    // 2. 5 repeated failed logins for Matt -> 429 + Retry-After + generic non-enumerating message
    let mattRateLimitedRes = null;
    for (let i = 0; i < 5; i++) {
      mattRateLimitedRes = await apiRequest(port, {
        path: '/api/login',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }, { username: 'Matt', password: 'BadPasswordAttempt!' });
    }
    assert.strictEqual(mattRateLimitedRes.status, 429, '5th failed login must trigger 429 rate limit');
    assert.ok(Number(mattRateLimitedRes.headers['retry-after']) >= 1, 'Retry-After header must be present');

    // Non-existent account returns identical 429 rate-limit shape & message (anti-enumeration)
    let unknownRateLimitedRes = null;
    for (let i = 0; i < 5; i++) {
      unknownRateLimitedRes = await apiRequest(port, {
        path: '/api/login',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }, { username: 'NonExistentAccount99', password: 'BadPasswordAttempt!' });
    }
    assert.strictEqual(unknownRateLimitedRes.status, 429);
    assert.strictEqual(unknownRateLimitedRes.body.error, mattRateLimitedRes.body.error);

    // 3. Repeated bad PIN attempts invalidate active session at threshold (3) and return 429
    const pinLogin = await apiRequest(port, {
      path: '/api/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, { username: 'PinUser', password: TECH_PW });
    assert.strictEqual(pinLogin.body.ok, true);
    const pinToken = pinLogin.body.token;

    const pinFail1 = await apiRequest(port, {
      path: '/api/verify-pin',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${pinToken}` },
    }, { pin: '0000' });
    assert.strictEqual(pinFail1.status, 200);
    assert.strictEqual(pinFail1.body.ok, false);

    const pinFail2 = await apiRequest(port, {
      path: '/api/verify-pin',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${pinToken}` },
    }, { pin: '0001' });
    assert.strictEqual(pinFail2.status, 200);
    assert.strictEqual(pinFail2.body.ok, false);

    const pinFail3 = await apiRequest(port, {
      path: '/api/verify-pin',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: `sos_session=${pinToken}` },
    }, { pin: '0002' });
    assert.strictEqual(pinFail3.status, 429, '3rd incorrect PIN must return 429');
    assert.ok(Number(pinFail3.headers['retry-after']) >= 1);
    assert.strictEqual(pinFail3.body.sessionRevoked, true);

    // Old session token is NOW invalidated even when submitting the REAL PIN or calling protected routes
    const pinAfterLock = await apiRequest(port, {
      path: '/api/verify-pin',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${pinToken}` },
    }, { pin: TECH_PIN });
    assert.strictEqual(pinAfterLock.status, 401, 'Invalidated PIN-locked session must fail even with correct PIN');

    // Fresh password sign-in grants a clean session whose valid PIN unlocks normally
    const freshPinLogin = await apiRequest(port, {
      path: '/api/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, { username: 'PinUser', password: TECH_PW });
    assert.strictEqual(freshPinLogin.body.ok, true);
    const freshPinUnlock = await apiRequest(port, {
      path: '/api/verify-pin',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${freshPinLogin.body.token}` },
    }, { pin: TECH_PIN });
    assert.strictEqual(freshPinUnlock.body.ok, true);
  } finally {
    await stopServer(child);
  }

  // 4. POST /api/setup rate limiting on fresh server + spoofed X-Forwarded-For bypass check
  const setupRateDir = makeTempDir('sos-setup-ratelimit-');
  const setupPort = 4005;
  const setupSecret = 'setup-rate-limit-secret-123456';
  const { child: setupChild } = await startServer({
    port: setupPort,
    dataDir: setupRateDir,
    extraEnv: { INITIAL_SETUP_TOKEN: setupSecret },
  });
  try {
    let lastSetupRes = null;
    for (let i = 0; i < 5; i++) {
      lastSetupRes = await apiRequest(setupPort, {
        path: '/api/setup',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }, { setupToken: 'bad-token-' + i, username: 'Admin', password: 'StrongPassword9!', pin: '1234' });
    }
    assert.strictEqual(lastSetupRes.status, 429, '5th failed setup token attempt must return 429');
    assert.ok(Number(lastSetupRes.headers['retry-after']) >= 1);

    // Subsequent request even with the VALID setup token is blocked while rate-limited
    const blockedValidSetup = await apiRequest(setupPort, {
      path: '/api/setup',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, { setupToken: setupSecret, username: 'Admin', password: 'StrongPassword9!', pin: '1234' });
    assert.strictEqual(blockedValidSetup.status, 429);
    assert.strictEqual(fs.existsSync(path.join(setupRateDir, 'users.json')), false);
  } finally {
    await stopServer(setupChild);
  }

  // 5. Verify spoofed X-Forwarded-For headers from untrusted clients CANNOT bypass login or setup rate limits
  const spoofDir = makeTempDir('sos-spoof-rl-');
  const prevDir = process.env.SOS_DATA_DIR;
  const prevTok = process.env.INITIAL_SETUP_TOKEN;
  const prevTrusted = process.env.TRUSTED_PROXIES;
  process.env.SOS_DATA_DIR = spoofDir;
  process.env.INITIAL_SETUP_TOKEN = setupSecret;
  delete process.env.TRUSTED_PROXIES;
  delete require.cache[require.resolve(SERVER_PATH)];
  delete require.cache[require.resolve(path.join(ROOT_DIR, 'store.js'))];
  const serverMod = require(SERVER_PATH);
  await serverMod.store.init();
  serverMod.initSetupState();
  try {
    // Untrusted HTTPS-Terminated (or direct TLS) client rotating X-Forwarded-For on every setup attempt
    for (let i = 0; i < 4; i++) {
      const r = await invokeExpressApp(serverMod.app, {
        method: 'POST',
        path: '/api/setup',
        remoteAddress: '203.0.113.88',
        encrypted: true,
        headers: {
          'Content-Type': 'application/json',
          'X-Forwarded-For': `198.51.100.${i + 1}`,
        },
        body: { setupToken: 'wrong-' + i, username: 'Admin', password: 'StrongPassword9!', pin: '1234' },
      });
      assert.strictEqual(r.status, 403);
    }
    const r5 = await invokeExpressApp(serverMod.app, {
      method: 'POST',
      path: '/api/setup',
      remoteAddress: '203.0.113.88',
      encrypted: true,
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '198.51.100.250',
      },
      body: { setupToken: 'wrong-final', username: 'Admin', password: 'StrongPassword9!', pin: '1234' },
    });
    assert.strictEqual(r5.status, 429, 'Spoofed X-Forwarded-For from untrusted socket must NOT bypass setup rate limit');

    // Trusted proxy (127.0.0.1) appending real client IP after spoofed leftmost IP also cannot bypass login rate limit
    serverMod.store.setUsers([
      {
        username: 'Matt',
        role: 'admin',
        createdAt: '2026-01-01T00:00:00.000Z',
        password: makeCredentials(MATT_PW),
        pin: makeCredentials(MATT_PIN),
        mustChangePassword: false,
        theme: 'yellow',
      },
    ]);
    for (let i = 0; i < 4; i++) {
      await invokeExpressApp(serverMod.app, {
        method: 'POST',
        path: '/api/login',
        remoteAddress: '127.0.0.1',
        headers: {
          'Content-Type': 'application/json',
          'X-Forwarded-For': `10.99.99.${i + 1}, 198.51.100.77`,
        },
        body: { username: 'Matt', password: 'WrongPassword!' },
      });
    }
    const login5 = await invokeExpressApp(serverMod.app, {
      method: 'POST',
      path: '/api/login',
      remoteAddress: '127.0.0.1',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '127.0.0.1, 198.51.100.77',
      },
      body: { username: 'Matt', password: 'WrongPassword!' },
    });
    assert.strictEqual(login5.status, 429, 'Rotating spoofed leftmost XFF entries must still bucket to real client 198.51.100.77');
  } finally {
    delete require.cache[require.resolve(SERVER_PATH)];
    delete require.cache[require.resolve(path.join(ROOT_DIR, 'store.js'))];
    if (prevDir === undefined) delete process.env.SOS_DATA_DIR;
    else process.env.SOS_DATA_DIR = prevDir;
    if (prevTok === undefined) delete process.env.INITIAL_SETUP_TOKEN;
    else process.env.INITIAL_SETUP_TOKEN = prevTok;
    if (prevTrusted === undefined) delete process.env.TRUSTED_PROXIES;
    else process.env.TRUSTED_PROXIES = prevTrusted;
  }

  console.log('[PASS] Server-side rate limiting verified on /api/login, /api/verify-pin (with session revocation), and /api/setup.');
}

async function testClientIpResolution() {
  console.log('\n=== Test Suite 6: Proxy-Chain Right-to-Left clientIp(req) & Express req.ip ===');
  const ipDir = makeTempDir('sos-clientip-');
  const prevDir = process.env.SOS_DATA_DIR;
  const prevTrusted = process.env.TRUSTED_PROXIES;
  process.env.SOS_DATA_DIR = ipDir;
  process.env.TRUSTED_PROXIES = '192.168.1.50';

  delete require.cache[require.resolve(SERVER_PATH)];
  delete require.cache[require.resolve(path.join(ROOT_DIR, 'store.js'))];
  const serverMod = require(SERVER_PATH);
  await serverMod.store.init();
  serverMod.store.setUsers([
    {
      username: 'Matt',
      role: 'admin',
      createdAt: '2026-01-01T00:00:00.000Z',
      password: makeCredentials('ValidIpTestPass9!'),
      pin: makeCredentials('4321'),
      mustChangePassword: false,
      theme: 'yellow',
    },
  ]);

  try {
    // 1. Direct untrusted client spoofing X-Forwarded-For -> ignores header completely
    assert.strictEqual(
      serverMod.clientIp({
        socket: { remoteAddress: '::ffff:198.51.100.77' },
        headers: { 'x-forwarded-for': '127.0.0.1, 10.0.0.1' },
      }),
      '198.51.100.77'
    );

    // 2. Trusted loopback proxy appending real client IP after client-supplied spoofed leftmost IP
    assert.strictEqual(
      serverMod.clientIp({
        socket: { remoteAddress: '127.0.0.1' },
        headers: { 'x-forwarded-for': '127.0.0.1, 198.51.100.77' },
      }),
      '198.51.100.77'
    );

    // 3. Multi-hop trusted proxy chain with spoofed leftmost IP (8.8.8.8 -> real client 203.0.113.44 -> trusted proxy 192.168.1.50 -> local proxy 127.0.0.1)
    assert.strictEqual(
      serverMod.clientIp({
        socket: { remoteAddress: '::ffff:127.0.0.1' },
        headers: { 'x-forwarded-for': '8.8.8.8, 203.0.113.44, 192.168.1.50' },
      }),
      '203.0.113.44'
    );

    // 4. Untrusted intermediate proxy (10.0.0.5) must stop right-to-left traversal before spoofed 203.0.113.44
    assert.strictEqual(
      serverMod.clientIp({
        socket: { remoteAddress: '127.0.0.1' },
        headers: { 'x-forwarded-for': '203.0.113.44, 10.0.0.5, 192.168.1.50' },
      }),
      '10.0.0.5'
    );

    // 5. Malformed rightmost XFF hop falls back safely to rightmost verified hop
    assert.strictEqual(
      serverMod.clientIp({
        socket: { remoteAddress: '127.0.0.1' },
        headers: { 'x-forwarded-for': '8.8.8.8, not-an-ip, 192.168.1.50' },
      }),
      '192.168.1.50'
    );

    // 6. Verify Express app route (login-failed activity log + Express req.ip consistency) records rightmost untrusted IP
    serverMod.clearAllRateLimitsForTest();
    let seenExpressReqIp = '';
    serverMod.app.get('/__test-req-ip', (req, res) => {
      seenExpressReqIp = serverMod.normalizeIp(req.ip);
      res.json({ reqIp: seenExpressReqIp, clientIp: serverMod.clientIp(req) });
    });

    const ipCheck = await invokeExpressApp(serverMod.app, {
      method: 'GET',
      path: '/__test-req-ip',
      remoteAddress: '::ffff:127.0.0.1',
      headers: { 'X-Forwarded-For': '127.0.0.1, 203.0.113.44, 192.168.1.50' },
    });
    assert.strictEqual(ipCheck.body.reqIp, '203.0.113.44');
    assert.strictEqual(ipCheck.body.clientIp, '203.0.113.44');

    const failLogin = await invokeExpressApp(serverMod.app, {
      method: 'POST',
      path: '/api/login',
      remoteAddress: '127.0.0.1',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '127.0.0.1, 198.51.100.77',
      },
      body: { username: 'Matt', password: 'WrongPassword!' },
    });
    assert.strictEqual(failLogin.body.ok, false);
    const logs = serverMod.store.getActivity(20);
    const lastLog = logs[logs.length - 1];
    assert.strictEqual(lastLog.action, 'login-failed');
    assert.ok(lastLog.details.includes('198.51.100.77'), 'Activity log must attribute real client 198.51.100.77');
    assert.strictEqual(lastLog.details.includes('127.0.0.1'), false, 'Activity log must NOT attribute spoofed leftmost 127.0.0.1');

    console.log('[PASS] Right-to-left proxy-chain clientIp(req) matches Express req.ip across trusted/untrusted chains.');
  } finally {
    delete require.cache[require.resolve(SERVER_PATH)];
    delete require.cache[require.resolve(path.join(ROOT_DIR, 'store.js'))];
    if (prevDir === undefined) delete process.env.SOS_DATA_DIR;
    else process.env.SOS_DATA_DIR = prevDir;
    if (prevTrusted === undefined) delete process.env.TRUSTED_PROXIES;
    else process.env.TRUSTED_PROXIES = prevTrusted;
  }
}

async function testCsrfLogoutAndCookieSecurity() {
  console.log('\n=== Test Suite 7: Logout Invalidation, CSRF Protection & Cookie Flags ===');
  const dataDir = makeTempDir('sos-csrf-cookie-');
  const port = 4006;

  const MATT_PW = 'CsrfTestMattPass9!';
  const users = [
    {
      username: 'Matt',
      role: 'admin',
      createdAt: '2026-01-01T00:00:00.000Z',
      password: makeCredentials(MATT_PW),
      pin: makeCredentials('4242'),
      mustChangePassword: false,
      theme: 'yellow',
    },
  ];
  fs.writeFileSync(path.join(dataDir, 'users.json'), JSON.stringify(users, null, 2), 'utf8');

  // Start server with NODE_ENV=production over plain HTTP to confirm module cookies are NOT broken
  const { child } = await startServer({
    port,
    dataDir,
    extraEnv: { NODE_ENV: 'production' },
  });

  try {
    // 1. Login over plain HTTP with NODE_ENV=production sets HttpOnly SameSite=Lax without Secure flag
    const loginRes = await apiRequest(port, {
      path: '/api/login',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Host: `127.0.0.1:${port}`,
        Origin: `http://127.0.0.1:${port}`,
        'Sec-Fetch-Site': 'same-origin',
      },
    }, { username: 'Matt', password: MATT_PW });
    assert.strictEqual(loginRes.body.ok, true);
    const token = loginRes.body.token;
    const setCookie = String(loginRes.headers['set-cookie'] || '');
    assert.ok(setCookie.includes(`sos_session=${token}`), 'Login must set sos_session cookie');
    assert.ok(/HttpOnly/i.test(setCookie), 'Session cookie must include HttpOnly');
    assert.ok(/SameSite=Lax/i.test(setCookie), 'Plain HTTP session cookie must use SameSite=Lax');
    assert.strictEqual(/;\s*Secure/i.test(setCookie), false, 'NODE_ENV=production must NOT set Secure cookie over plain HTTP');

    // 2. Trusted HTTPS proxy login DOES emit Secure cookie
    const httpsLoginRes = await apiRequest(port, {
      path: '/api/login',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Host: 'sos.example.com',
        Origin: 'https://sos.example.com',
        'Sec-Fetch-Site': 'same-origin',
        'X-Forwarded-Proto': 'https',
      },
    }, { username: 'Matt', password: MATT_PW });
    assert.strictEqual(httpsLoginRes.body.ok, true);
    const httpsToken = httpsLoginRes.body.token;
    const httpsCookie = String(httpsLoginRes.headers['set-cookie'] || '');
    assert.ok(/;\s*Secure/i.test(httpsCookie), 'HTTPS session cookie must include Secure');
    assert.ok(/SameSite=None/i.test(httpsCookie), 'HTTPS session cookie preserves SameSite=None for iframe modules');

    // 3. Cookie-authenticated CSRF attacks MUST be blocked with 403
    const csrfAttacks = [
      {
        label: 'mismatched Origin header',
        headers: {
          'Content-Type': 'application/json',
          Host: `127.0.0.1:${port}`,
          Origin: 'https://evil.example',
          Cookie: `sos_session=${token}`,
        },
        body: { id: 'csrf-rep-1', device: { model: 'Blocked' } },
      },
      {
        label: 'null Origin header (sandboxed iframe)',
        headers: {
          'Content-Type': 'application/json',
          Host: `127.0.0.1:${port}`,
          Origin: 'null',
          Cookie: `sos_session=${token}`,
        },
        body: { id: 'csrf-rep-2', device: { model: 'Blocked' } },
      },
      {
        label: 'Sec-Fetch-Site: cross-site',
        headers: {
          'Content-Type': 'application/json',
          Host: `127.0.0.1:${port}`,
          Origin: `http://127.0.0.1:${port}`,
          'Sec-Fetch-Site': 'cross-site',
          Cookie: `sos_session=${token}`,
        },
        body: { id: 'csrf-rep-3', device: { model: 'Blocked' } },
      },
      {
        label: 'mismatched Referer header without Origin',
        headers: {
          'Content-Type': 'application/json',
          Host: `127.0.0.1:${port}`,
          Referer: 'https://evil.example/form.html',
          Cookie: `sos_session=${token}`,
        },
        body: { id: 'csrf-rep-4', device: { model: 'Blocked' } },
      },
      {
        label: 'simple HTML form Content-Type: application/x-www-form-urlencoded',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Host: `127.0.0.1:${port}`,
          Cookie: `sos_session=${token}`,
        },
        body: 'id=csrf-rep-5',
      },
      {
        label: 'simple Content-Type: text/plain',
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          Host: `127.0.0.1:${port}`,
          Cookie: `sos_session=${token}`,
        },
        body: '{"id":"csrf-rep-6"}',
      },
    ];

    for (const attack of csrfAttacks) {
      const res = await apiRequest(port, {
        path: '/api/repairs',
        method: 'POST',
        headers: attack.headers,
      }, attack.body);
      assert.strictEqual(res.status, 403, `Expected 403 CSRF rejection for ${attack.label}`);
      assert.strictEqual(res.body.ok, false);
    }

    // Confirm none of the CSRF attempts persisted any ticket
    const afterAttackRepairs = await apiRequest(port, {
      path: '/api/repairs',
      headers: { Cookie: `sos_session=${token}` },
    });
    assert.strictEqual(afterAttackRepairs.body.tickets.length, 0);

    // 4. Legitimate same-origin cookie requests (matching Origin + Sec-Fetch-Site: same-origin) succeed
    const sameOriginCreate = await apiRequest(port, {
      path: '/api/repairs',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Host: `127.0.0.1:${port}`,
        Origin: `http://127.0.0.1:${port}`,
        'Sec-Fetch-Site': 'same-origin',
        Cookie: `sos_session=${token}`,
      },
    }, { id: 'valid-rep-1', device: { model: 'iPhone 14' }, status: 'Booked In' });
    assert.strictEqual(sameOriginCreate.status, 200);
    assert.strictEqual(sameOriginCreate.body.ok, true);

    const sameOriginDelete = await apiRequest(port, {
      path: '/api/repairs/valid-rep-1',
      method: 'DELETE',
      headers: {
        Host: `127.0.0.1:${port}`,
        Origin: `http://127.0.0.1:${port}`,
        'Sec-Fetch-Site': 'same-origin',
        Cookie: `sos_session=${token}`,
      },
    });
    assert.strictEqual(sameOriginDelete.status, 200);
    assert.strictEqual(sameOriginDelete.body.ok, true);

    // 5. Logout immediately invalidates server-side session & clears cookie
    const logoutRes = await apiRequest(port, {
      path: '/api/logout',
      method: 'POST',
      headers: {
        Host: `127.0.0.1:${port}`,
        Origin: `http://127.0.0.1:${port}`,
        'Sec-Fetch-Site': 'same-origin',
        Cookie: `sos_session=${token}`,
      },
    });
    assert.strictEqual(logoutRes.status, 200);
    assert.strictEqual(logoutRes.body.ok, true);
    assert.ok(String(logoutRes.headers['set-cookie'] || '').includes('sos_session=;'), 'Logout must clear sos_session cookie');

    // Old token must now be rejected everywhere
    const afterLogoutRepairs = await apiRequest(port, {
      path: '/api/repairs',
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.strictEqual(afterLogoutRepairs.status, 401, 'Logged-out session must return 401');

    const afterLogoutMe = await apiRequest(port, {
      path: '/api/me',
      headers: { Cookie: `sos_session=${token}` },
    });
    assert.strictEqual(afterLogoutMe.body.user, null);

    // Log out second session via Bearer too
    const bearerLogout = await apiRequest(port, {
      path: '/api/logout',
      method: 'POST',
      headers: { Authorization: `Bearer ${httpsToken}` },
    });
    assert.strictEqual(bearerLogout.status, 200);
    assert.strictEqual(
      (await apiRequest(port, { path: '/api/repairs', headers: { Authorization: `Bearer ${httpsToken}` } })).status,
      401
    );
  } finally {
    await stopServer(child);
  }

  // 6. Verify FORCE_SECURE_COOKIES=1 sets Secure even on HTTP, and X-Forwarded-Host spoofing is blocked from untrusted IPs
  const unitDir = makeTempDir('sos-cookie-unit-');
  const prevDir = process.env.SOS_DATA_DIR;
  const prevForce = process.env.FORCE_SECURE_COOKIES;
  const prevNodeEnv = process.env.NODE_ENV;
  process.env.SOS_DATA_DIR = unitDir;
  process.env.NODE_ENV = 'production';
  delete process.env.FORCE_SECURE_COOKIES;

  delete require.cache[require.resolve(SERVER_PATH)];
  delete require.cache[require.resolve(path.join(ROOT_DIR, 'store.js'))];
  const serverMod = require(SERVER_PATH);
  await serverMod.store.init();
  try {
    const httpProdOpts = serverMod.cookieOptions({
      socket: { remoteAddress: '127.0.0.1', encrypted: false },
      headers: {},
    });
    assert.strictEqual(httpProdOpts.httpOnly, true);
    assert.strictEqual(httpProdOpts.secure, false, 'NODE_ENV=production on HTTP must leave secure=false');

    process.env.FORCE_SECURE_COOKIES = '1';
    const forcedOpts = serverMod.cookieOptions({
      socket: { remoteAddress: '127.0.0.1', encrypted: false },
      headers: {},
    });
    assert.strictEqual(forcedOpts.secure, true, 'FORCE_SECURE_COOKIES=1 must set secure=true');

    // Spoofed X-Forwarded-Host from untrusted client must NOT satisfy CSRF host matching
    const spoofedFwdHostRes = await invokeExpressApp(serverMod.app, {
      method: 'POST',
      path: '/api/logout',
      remoteAddress: '203.0.113.55',
      headers: {
        Host: 'workshop.local',
        'X-Forwarded-Host': 'evil.example',
        Origin: 'https://evil.example',
      },
    });
    assert.strictEqual(spoofedFwdHostRes.status, 403);
  } finally {
    delete require.cache[require.resolve(SERVER_PATH)];
    delete require.cache[require.resolve(path.join(ROOT_DIR, 'store.js'))];
    if (prevDir === undefined) delete process.env.SOS_DATA_DIR;
    else process.env.SOS_DATA_DIR = prevDir;
    if (prevForce === undefined) delete process.env.FORCE_SECURE_COOKIES;
    else process.env.FORCE_SECURE_COOKIES = prevForce;
    if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prevNodeEnv;
  }

  console.log('[PASS] Logout invalidation, CSRF protection, and HTTP/HTTPS cookie flags verified.');
}

async function main() {
  try {
    await testFirstRunRandomTokenAndHttpsSafeguard();
    await testFirstRunEnvToken();
    await testReverseProxyTrustRestriction();
    await testSimultaneousSetupLock();
    await testExistingUsersFallbacksUsbAgentAndPasswordPolicy();
    await testAdminCliScripts();
    await testSessionRevocationOnPasswordChanges();
    await testServerRateLimiting();
    await testClientIpResolution();
    await testCsrfLogoutAndCookieSecurity();
    console.log('\n========================================');
    console.log('ALL AUTH SECURITY & SETUP TESTS PASSED!');
    console.log('========================================\n');
  } finally {
    for (const dir of tempDirs) {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) {}
    }
  }
}

main().catch((err) => {
  console.error('\n[TEST FAILURE]', err);
  for (const dir of tempDirs) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) {}
  }
  process.exit(1);
});