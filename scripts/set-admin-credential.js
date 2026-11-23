#!/usr/bin/env node
/**
 * SOS Tools — Administrator Offline Credential Recovery Tool
 *
 * Runs locally on the server console (via SSH) ONLY while the SOS Tools server
 * is stopped, in Local JSON file storage mode.
 *
 * Refuses to run when:
 *  - MongoDB storage mode is configured (MONGODB_URI present)
 *  - A live SOS Tools server process serving the target data directory is detected
 *  - users.json is missing, unreadable, or contains no accounts
 *
 * Usage:
 *   node scripts/set-admin-credential.js [username]
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const readline = require('readline');

function readEnvFileVar(name) {
  const candidates = [
    path.join(__dirname, '..', '.env'),
    path.join(process.cwd(), '.env'),
  ];
  for (let i = 0; i < candidates.length; i++) {
    try {
      if (!fs.existsSync(candidates[i])) continue;
      const lines = fs.readFileSync(candidates[i], 'utf8').split(/\r?\n/);
      for (let j = 0; j < lines.length; j++) {
        const line = lines[j].trim();
        if (!line || line.startsWith('#')) continue;
        const idx = line.indexOf('=');
        if (idx === -1) continue;
        const key = line.slice(0, idx).trim();
        if (key === name) {
          let val = line.slice(idx + 1).trim();
          if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
            val = val.slice(1, -1);
          }
          return val;
        }
      }
    } catch (e) {}
  }
  return '';
}

function detectStorageMode() {
  const mongoEnv = String(process.env.MONGODB_URI || '').trim();
  const mongoDotEnv = String(readEnvFileVar('MONGODB_URI') || '').trim();
  return (mongoEnv || mongoDotEnv) ? 'mongo' : 'file';
}

function resolveUsersFile() {
  const candidates = [];
  if (process.env.SOS_DATA_DIR) {
    candidates.push(path.join(path.resolve(process.env.SOS_DATA_DIR), 'users.json'));
  }
  candidates.push(
    path.join(__dirname, '..', 'data', 'users.json'),
    '/opt/sos-tools/data/users.json',
    path.join(process.cwd(), 'data', 'users.json')
  );
  for (let i = 0; i < candidates.length; i++) {
    if (fs.existsSync(candidates[i])) {
      return { file: candidates[i], searched: candidates };
    }
  }
  return { file: null, searched: candidates };
}

function findRunningServerState(targetDataDir, deps = {}) {
  const platform = deps.platform || process.platform;
  const procDir = deps.procDir || '/proc';
  const fsMod = deps.fs || fs;
  const selfPid = deps.selfPid !== undefined ? deps.selfPid : process.pid;
  const parentPid = deps.parentPid !== undefined ? deps.parentPid : process.ppid;

  if (platform !== 'linux') {
    return {
      running: false,
      uncertain: true,
      pid: null,
      reason: 'Platform "' + platform + '" does not support /proc process inspection; cannot reliably confirm no SOS Tools server is running.',
    };
  }

  const resolvedTarget = path.resolve(targetDataDir);
  let entries = [];
  try {
    entries = fsMod.readdirSync(procDir);
  } catch (e) {
    return {
      running: false,
      uncertain: true,
      pid: null,
      reason: 'Could not read process directory ' + procDir + ' (' + (e.code || e.message) + '); cannot reliably confirm the server is stopped.',
    };
  }

  let unreadableCmdlineCount = 0;
  for (let i = 0; i < entries.length; i++) {
    const pid = entries[i];
    if (!/^\d+$/.test(pid)) continue;
    const pidNum = Number(pid);
    if (pidNum === selfPid || pidNum === parentPid) continue;

    let cmdRaw;
    try {
      cmdRaw = fsMod.readFileSync(path.join(procDir, pid, 'cmdline'));
    } catch (e) {
      if (e && (e.code === 'EACCES' || e.code === 'EPERM')) {
        unreadableCmdlineCount++;
      }
      continue;
    }

    const args = cmdRaw.toString('utf8').split('\0').filter(Boolean);
    if (args.length < 2) continue;

    const serverArg = args.find((a) => path.basename(a) === 'server.js');
    const isDotNode = path.basename(args[0]) === 'node' && args.includes('.');
    if (!serverArg && !isDotNode) continue;

    let procCwd = '';
    let cwdBlocked = false;
    try {
      procCwd = fsMod.readlinkSync(path.join(procDir, pid, 'cwd'));
    } catch (e) {
      if (e && (e.code === 'EACCES' || e.code === 'EPERM')) {
        cwdBlocked = true;
      }
      procCwd = serverArg ? path.dirname(serverArg) : '';
    }

    if (isDotNode && !serverArg) {
      if (cwdBlocked || !procCwd) {
        return {
          running: false,
          uncertain: true,
          pid: pidNum,
          reason: 'Running Node process (PID ' + pidNum + ') cwd could not be inspected; cannot confirm whether it serves ' + resolvedTarget + '.',
        };
      }
      if (!fsMod.existsSync(path.join(procCwd, 'server.js'))) continue;
    }

    let procDataDir = '';
    let envBlocked = false;
    try {
      const envRaw = fsMod.readFileSync(path.join(procDir, pid, 'environ')).toString('utf8').split('\0');
      const sosDirEntry = envRaw.find((entry) => entry.startsWith('SOS_DATA_DIR='));
      if (sosDirEntry) {
        const val = sosDirEntry.slice('SOS_DATA_DIR='.length).trim();
        if (val) procDataDir = path.resolve(procCwd || process.cwd(), val);
      }
    } catch (e) {
      if (e && (e.code === 'EACCES' || e.code === 'EPERM')) {
        envBlocked = true;
      }
    }

    if (envBlocked) {
      return {
        running: false,
        uncertain: true,
        pid: pidNum,
        reason: 'Detected running server.js process (PID ' + pidNum + '), but permission was denied reading its environment to verify its data directory.',
      };
    }

    if (!procDataDir) {
      const entryScript = serverArg || path.join(procCwd, 'server.js');
      if (cwdBlocked && !path.isAbsolute(entryScript)) {
        return {
          running: false,
          uncertain: true,
          pid: pidNum,
          reason: 'Detected running server.js process (PID ' + pidNum + '), but permission was denied reading its working directory.',
        };
      }
      const serverAbs = path.isAbsolute(entryScript) ? entryScript : path.resolve(procCwd, entryScript);
      procDataDir = path.join(path.dirname(serverAbs), 'data');
    }

    if (path.resolve(procDataDir) === resolvedTarget) {
      return {
        running: true,
        uncertain: false,
        pid: pidNum,
        reason: 'Live server process detected serving ' + resolvedTarget + ' (PID ' + pidNum + ')',
      };
    }
  }

  if (unreadableCmdlineCount > 0) {
    return {
      running: false,
      uncertain: true,
      pid: null,
      reason: 'Permission denied inspecting ' + unreadableCmdlineCount + ' running process(es) in ' + procDir + '; run as the service user or root to reliably confirm the server is stopped.',
    };
  }

  return { running: false, uncertain: false, pid: null, reason: '' };
}

function probeHealthzPort(port) {
  return new Promise((resolve) => {
    if (!port) return resolve(false);
    const req = http.get({
      hostname: '127.0.0.1',
      port: Number(port),
      path: '/healthz',
      timeout: 600,
    }, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          resolve(Boolean(parsed && parsed.ok === true));
        } catch (e) {
          resolve(false);
        }
      });
    });
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    req.on('error', () => resolve(false));
  });
}

async function resolveServerSafetyState(usersFile, deps = {}) {
  const targetDataDir = path.dirname(path.resolve(usersFile));
  const procState = findRunningServerState(targetDataDir, deps);
  if (procState.running) {
    return { safe: false, running: true, uncertain: false, reason: procState.reason };
  }
  if (procState.uncertain) {
    return { safe: false, running: false, uncertain: true, reason: procState.reason };
  }

  const probePortFn = deps.probeHealthzPort || probeHealthzPort;
  const envObj = deps.env || process.env;
  const explicitPort = envObj.PORT ? Number(envObj.PORT) : null;
  const dotEnvPort = !envObj.SOS_DATA_DIR ? Number(readEnvFileVar('PORT')) || 3000 : null;
  const probePort = explicitPort || dotEnvPort;
  if (probePort) {
    const alive = await probePortFn(probePort);
    if (alive) {
      return {
        safe: false,
        running: true,
        uncertain: false,
        reason: 'Live SOS Tools HTTP server responded on 127.0.0.1:' + probePort + '/healthz',
      };
    }
  }
  return { safe: true, running: false, uncertain: false, reason: '' };
}

function printSafeRecoveryProcedure(usersFile, username) {
  console.error('\nSafe Offline Recovery Procedure (Local JSON File Mode):');
  console.error('  1. Stop the SOS Tools server cleanly (e.g. `sudo systemctl stop sos-tools`).');
  console.error('  2. Back up the account database (e.g. `cp "' + usersFile + '" "' + usersFile + '.bak"`).');
  console.error('  3. Run `node scripts/set-admin-credential.js ' + (username || '<username>') + '` while offline.');
  console.error('  4. Start the SOS Tools server (`sudo systemctl start sos-tools`).');
  console.error('  5. Verify BOTH password and PIN with `node scripts/verify-admin-credential.js ' + (username || '<username>') + '`.');
}

function hashSecret(secret, salt) {
  return crypto.scryptSync(String(secret), salt, 64).toString('hex');
}

function makeCredentials(secret) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt: salt, hash: hashSecret(secret, salt) };
}

// Persistent non-TTY line reader so piped multi-line input never drops buffered lines
let nonTtyRl = null;
const nonTtyQueue = [];
const nonTtyWaiters = [];
let nonTtyEnded = false;

function initNonTtyReader() {
  if (nonTtyRl) return;
  nonTtyRl = readline.createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
  });
  nonTtyRl.on('line', (line) => {
    if (nonTtyWaiters.length > 0) {
      const resolve = nonTtyWaiters.shift();
      resolve(line);
    } else {
      nonTtyQueue.push(line);
    }
  });
  nonTtyRl.on('close', () => {
    nonTtyEnded = true;
    while (nonTtyWaiters.length > 0) {
      const resolve = nonTtyWaiters.shift();
      resolve('');
    }
  });
}

function readNextLine(query) {
  if (query) process.stdout.write(query);
  if (process.stdin.isTTY) {
    return new Promise((resolve) => {
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
      });
      rl.question('', (ans) => {
        rl.close();
        resolve(ans);
      });
    });
  }
  initNonTtyReader();
  return new Promise((resolve) => {
    if (nonTtyQueue.length > 0) {
      resolve(nonTtyQueue.shift());
    } else if (nonTtyEnded) {
      resolve('');
    } else {
      nonTtyWaiters.push(resolve);
    }
  });
}

function readHidden(query) {
  if (!process.stdin.isTTY) {
    return readNextLine(query).then((ans) => {
      console.log('');
      return ans;
    });
  }

  return new Promise((resolve) => {
    process.stdout.write(query);
    const stdin = process.stdin;
    const wasRaw = !!stdin.isRaw;
    let input = '';

    function cleanup() {
      stdin.removeListener('data', onData);
      try { stdin.setRawMode(wasRaw); } catch (e) {}
      stdin.pause();
    }

    function onData(chunk) {
      const str = chunk.toString('utf8');
      for (let i = 0; i < str.length; i++) {
        const ch = str[i];
        if (ch === '\u0003') {
          cleanup();
          console.log('\nAborted.');
          process.exit(130);
        } else if (ch === '\r' || ch === '\n' || ch === '\u0004') {
          cleanup();
          console.log('');
          resolve(input);
          return;
        } else if (ch === '\u007f' || ch === '\b') {
          if (input.length > 0) {
            input = input.slice(0, -1);
            process.stdout.write('\b \b');
          }
        } else {
          input += ch;
          process.stdout.write('*');
        }
      }
    }

    stdin.resume();
    try { stdin.setRawMode(true); } catch (e) {}
    stdin.on('data', onData);
  });
}

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function closeNonTty() {
  if (nonTtyRl) {
    try { nonTtyRl.close(); } catch (e) {}
  }
}

async function main() {
  console.log('========================================================');
  console.log('  SOS Tools — Administrator Credential Recovery Tool');
  console.log('  (Offline local JSON mode only — stops stale writes)');
  console.log('========================================================\n');

  const storageMode = detectStorageMode();
  console.log('Detected storage mode: ' + (storageMode === 'mongo' ? 'MongoDB (MONGODB_URI configured)' : 'Local JSON file'));

  if (storageMode === 'mongo') {
    console.error('\n[REFUSED] MongoDB storage mode is active (MONGODB_URI is configured).');
    console.error('This script ONLY edits local users.json and does NOT support MongoDB.');
    console.error('Editing local users.json in MongoDB mode will NOT update active MongoDB accounts');
    console.error('and will be overwritten on the next write from MongoDB.');
    console.error('\nSafe recovery options in MongoDB mode:');
    console.error('  - Sign in as another admin and use Admin Panel -> Reset Credentials, OR');
    console.error('  - Stop the application and update the user document directly in MongoDB.');
    closeNonTty();
    process.exit(1);
  }

  const resolved = resolveUsersFile();
  if (!resolved.file) {
    console.error('\n[REFUSED] Could not find an existing data/users.json file.');
    console.error('Refusing to create a new file to avoid overwriting or bypassing existing setup.');
    console.error('Searched in:');
    resolved.searched.forEach((p) => console.error('  - ' + p));
    closeNonTty();
    process.exit(1);
  }

  const usersFile = path.resolve(resolved.file);
  const targetDataDir = path.dirname(usersFile);
  console.log('Target data directory: ' + targetDataDir);
  console.log('Target user file:      ' + usersFile);

  const serverCheck = await resolveServerSafetyState(usersFile);
  if (!serverCheck.safe) {
    console.error('\n[REFUSED] Cannot modify users.json unless the SOS Tools server is confirmed stopped.');
    console.error('Reason: ' + serverCheck.reason);
    console.error('Because SOS Tools caches users.json in memory at startup, editing the file while');
    console.error('running or uncertain leaves stale hashes in memory and risks overwriting your edits.');
    printSafeRecoveryProcedure(usersFile, process.argv[2]);
    closeNonTty();
    process.exit(1);
  }

  let initialStat;
  let origMode;
  let usersData = [];
  let rawOriginal = '';
  let initialDigest = '';
  try {
    initialStat = fs.statSync(usersFile);
    origMode = initialStat.mode & 0o777;
    rawOriginal = fs.readFileSync(usersFile, 'utf8');
    initialDigest = sha256Hex(rawOriginal);
    usersData = JSON.parse(rawOriginal);
  } catch (e) {
    console.error('\n[REFUSED] Failed to read or parse users.json safely: ' + e.message);
    console.error('Refusing to modify or overwrite a corrupted or unreadable users.json file.');
    closeNonTty();
    process.exit(1);
  }

  console.log(
    'Current file owner/mode: uid=' + initialStat.uid + ' gid=' + initialStat.gid +
    ' mode=0' + origMode.toString(8).padStart(3, '0')
  );

  if (!Array.isArray(usersData) || usersData.length === 0) {
    console.error('\n[REFUSED] users.json is empty or does not contain a valid user array.');
    console.error('Refusing to overwrite existing file contents.');
    closeNonTty();
    process.exit(1);
  }

  const defaultUser = process.argv[2] || 'Matt';
  const uInput = await readNextLine('\nUsername to update [' + defaultUser + ']: ');
  if (!process.stdin.isTTY) console.log('');
  const targetName = (uInput && uInput.trim()) || defaultUser;

  const user = usersData.find((u) => u && u.username && u.username.toLowerCase() === targetName.toLowerCase());
  if (!user) {
    console.error('\n[FAIL] User "' + targetName + '" not found in ' + usersFile);
    console.error('Available usernames: ' + usersData.map((u) => u && u.username).filter(Boolean).join(', '));
    closeNonTty();
    process.exit(1);
  }

  console.log('Found account: ' + user.username + ' (Role: ' + user.role + ', Total accounts preserved: ' + usersData.length + ')');

  const pw1 = await readHidden('Enter NEW password (minimum 8 characters): ');
  if (!pw1 || pw1.length < 8) {
    console.error('\n[ERROR] Password must be at least 8 characters long.');
    closeNonTty();
    process.exit(1);
  }

  const pw2 = await readHidden('Confirm NEW password: ');
  if (pw1 !== pw2) {
    console.error('\n[ERROR] Passwords do not match.');
    closeNonTty();
    process.exit(1);
  }

  const pin1 = await readHidden('Enter NEW 4-digit PIN [Press Enter to keep current PIN]: ');
  let updatedPin = null;
  if (pin1 && pin1.trim()) {
    const pinStr = pin1.trim();
    if (!/^\d{4}$/.test(pinStr)) {
      console.error('\n[ERROR] PIN must be exactly 4 digits.');
      closeNonTty();
      process.exit(1);
    }
    updatedPin = makeCredentials(pinStr);
  }

  // Re-verify server is still stopped and users.json has NOT changed since initial read (TOCTOU protection)
  const postPromptServerCheck = await resolveServerSafetyState(usersFile);
  if (!postPromptServerCheck.safe) {
    console.error('\n[REFUSED] Server state changed during recovery session; aborting before writing.');
    console.error('Reason: ' + postPromptServerCheck.reason);
    closeNonTty();
    process.exit(1);
  }

  try {
    const currentStat = fs.statSync(usersFile);
    const currentRaw = fs.readFileSync(usersFile, 'utf8');
    const currentDigest = sha256Hex(currentRaw);
    if (
      currentDigest !== initialDigest ||
      currentStat.size !== initialStat.size ||
      currentStat.mtimeMs !== initialStat.mtimeMs ||
      currentStat.ino !== initialStat.ino ||
      currentStat.uid !== initialStat.uid ||
      currentStat.gid !== initialStat.gid
    ) {
      console.error('\n[REFUSED] ' + usersFile + ' was modified on disk between reading and writing.');
      console.error('Aborting cleanly to avoid overwriting external changes. Please re-run once the file is idle.');
      closeNonTty();
      process.exit(1);
    }
  } catch (err) {
    console.error('\n[REFUSED] Could not re-verify ' + usersFile + ' before writing: ' + err.message);
    closeNonTty();
    process.exit(1);
  }

  // Update only the matched user's password (and PIN if supplied)
  user.password = makeCredentials(pw1);
  if (updatedPin) {
    user.pin = updatedPin;
  }
  user.mustChangePassword = false;

  // Create pre-change backup before atomic replace, preserving owner/group and enforcing 0600
  const backupFile = usersFile + '.bak.' + Date.now();
  const tmpFile = usersFile + '.tmp.' + process.pid + '.' + Date.now();
  let replaceResult;
  try {
    replaceResult = atomicReplaceUsersFile({
      usersFile,
      rawOriginal,
      updatedJson: JSON.stringify(usersData, null, 2),
      initialStat,
      backupFile,
      tmpFile,
    });
  } catch (err) {
    console.error('[ERROR] Failed to save users.json safely: ' + err.message);
    closeNonTty();
    process.exit(1);
  }

  // Audit log (never modify ownership/permissions of an existing activity-log.jsonl)
  try {
    const logFile = path.join(targetDataDir, 'activity-log.jsonl');
    const logExisted = fs.existsSync(logFile);
    const logEntry = {
      ts: new Date().toISOString(),
      user: user.username,
      action: 'console-credential-recovery',
      details: 'Credentials updated offline via console recovery CLI (' + (updatedPin ? 'password+pin' : 'password-only') + ')',
    };
    fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n', { encoding: 'utf8', mode: 0o600 });
    if (!logExisted && initialStat && typeof initialStat.uid === 'number' && typeof initialStat.gid === 'number') {
      try { fs.chownSync(logFile, initialStat.uid, initialStat.gid); } catch (e) {}
    }
  } catch (e) {}

  console.log('\n[SUCCESS] Credentials updated offline for "' + user.username + '".');
  console.log('Pre-update backup saved to: ' + backupFile + ' (uid=' + replaceResult.uid + ' gid=' + replaceResult.gid + ' mode=0600)');
  console.log('Updated database written to: ' + usersFile + ' (uid=' + replaceResult.uid + ' gid=' + replaceResult.gid + ' mode=0600)');
  console.log('Next steps:');
  console.log('  1. Start the SOS Tools server again.');
  console.log('  2. Run `node scripts/verify-admin-credential.js ' + user.username + '` and verify BOTH password and PIN.');
  closeNonTty();
  process.exit(0);
}

function applyOwnershipAndMode(filePath, targetUid, targetGid, targetMode, fsMod) {
  fsMod.chmodSync(filePath, targetMode);
  if (typeof targetUid === 'number' && typeof targetGid === 'number') {
    fsMod.chownSync(filePath, targetUid, targetGid);
    const st = fsMod.statSync(filePath);
    if (st.uid !== targetUid || st.gid !== targetGid) {
      throw new Error(
        'Ownership verification failed for ' + filePath +
        ' (expected uid=' + targetUid + ' gid=' + targetGid +
        ', got uid=' + st.uid + ' gid=' + st.gid + ')'
      );
    }
  }
  const finalModeCheck = fsMod.statSync(filePath).mode & 0o777;
  if (finalModeCheck !== targetMode) {
    fsMod.chmodSync(filePath, targetMode);
  }
}

function atomicReplaceUsersFile({
  usersFile,
  rawOriginal,
  updatedJson,
  initialStat,
  backupFile,
  tmpFile,
}, fsMod = fs) {
  const targetMode = 0o600;
  const backupMode = 0o600;
  const targetUid = initialStat && typeof initialStat.uid === 'number' ? initialStat.uid : undefined;
  const targetGid = initialStat && typeof initialStat.gid === 'number' ? initialStat.gid : undefined;

  let backupCreated = false;
  let tmpCreated = false;
  try {
    fsMod.writeFileSync(backupFile, rawOriginal, { encoding: 'utf8', mode: backupMode });
    backupCreated = true;
    applyOwnershipAndMode(backupFile, targetUid, targetGid, backupMode, fsMod);

    fsMod.writeFileSync(tmpFile, updatedJson, { encoding: 'utf8', mode: targetMode });
    tmpCreated = true;
    applyOwnershipAndMode(tmpFile, targetUid, targetGid, targetMode, fsMod);

    fsMod.renameSync(tmpFile, usersFile);
    tmpCreated = false;

    const finalStat = fsMod.statSync(usersFile);
    if (
      (typeof targetUid === 'number' && finalStat.uid !== targetUid) ||
      (typeof targetGid === 'number' && finalStat.gid !== targetGid)
    ) {
      throw new Error(
        'Final ownership mismatch on ' + usersFile +
        ' (expected uid=' + targetUid + ' gid=' + targetGid +
        ', got uid=' + finalStat.uid + ' gid=' + finalStat.gid + ')'
      );
    }
    if ((finalStat.mode & 0o777) !== targetMode) {
      fsMod.chmodSync(usersFile, targetMode);
    }
    return {
      uid: finalStat.uid,
      gid: finalStat.gid,
      mode: fsMod.statSync(usersFile).mode & 0o777,
    };
  } catch (err) {
    if (tmpCreated) {
      try { if (fsMod.existsSync(tmpFile)) fsMod.unlinkSync(tmpFile); } catch (e) {}
    }
    if (backupCreated) {
      try { if (fsMod.existsSync(backupFile)) fsMod.unlinkSync(backupFile); } catch (e) {}
    }
    throw new Error('Aborting before modifying ' + usersFile + ': ' + err.message);
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error('[ERROR] Unexpected failure: ' + err.message);
    closeNonTty();
    process.exit(1);
  });
} else {
  module.exports = {
    detectStorageMode,
    resolveUsersFile,
    findRunningServerState,
    resolveServerSafetyState,
    atomicReplaceUsersFile,
  };
}