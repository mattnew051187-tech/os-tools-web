#!/usr/bin/env node
/**
 * SOS Tools — Administrator Credential Verification Tool
 *
 * Read-only diagnostic tool run locally on the server console.
 * Verifies BOTH password and 4-digit PIN independently against the cryptographic
 * scrypt hashes stored in data/users.json WITHOUT modifying files or revealing
 * any credentials.
 *
 * Usage:
 *   node scripts/verify-admin-credential.js [username]
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
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

function hashSecret(secret, salt) {
  return crypto.scryptSync(String(secret), salt, 64).toString('hex');
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

function parseDbName(uri) {
  const m = String(uri || '').match(/\/([^/?]+)(\?|$)/);
  return m && m[1] ? m[1] : null;
}

function getMongoUri() {
  return String(process.env.MONGODB_URI || readEnvFileVar('MONGODB_URI') || '').trim();
}

function closeNonTty() {
  if (nonTtyRl) {
    try { nonTtyRl.close(); } catch (e) {}
  }
}

async function loadUsersFromMongo(mongoUri) {
  let MongoClient;
  try {
    ({ MongoClient } = require('mongodb'));
  } catch (e) {
    throw new Error('MongoDB driver package is not available: ' + e.message);
  }
  const client = new MongoClient(mongoUri, {
    serverSelectionTimeoutMS: 1500,
    connectTimeoutMS: 1500,
  });
  try {
    await client.connect();
    const dbName = parseDbName(mongoUri) || 'sos-tools';
    const db = client.db(dbName);
    const docs = await db.collection('users').find({}).toArray();
    return { dbName, users: docs };
  } finally {
    await client.close().catch(() => {});
  }
}

async function main() {
  console.log('========================================================');
  console.log('  SOS Tools — Administrator Credential Verification Tool');
  console.log('  (Read-only: verifies password and PIN independently)');
  console.log('========================================================\n');

  const storageMode = detectStorageMode();
  console.log('Detected storage mode: ' + (storageMode === 'mongo' ? 'MongoDB (MONGODB_URI configured)' : 'Local JSON file'));

  let usersData = [];
  let sourceLabel = '';

  if (storageMode === 'mongo') {
    const mongoUri = getMongoUri();
    console.log('Live store target:     MongoDB users collection (ignoring local data/users.json mirror)\n');
    try {
      const result = await loadUsersFromMongo(mongoUri);
      usersData = result.users;
      sourceLabel = 'MongoDB database "' + result.dbName + '" (users collection)';
    } catch (err) {
      console.error('[ERROR] Could not connect to MongoDB to verify live credentials: ' + err.message);
      console.error('[VERDICT] UNVERIFIED / NOT SAFE: Live MongoDB accounts could not be checked.');
      console.error('          Refusing to fall back to data/users.json because it may be a stale local mirror.');
      closeNonTty();
      process.exit(1);
    }
  } else {
    const resolved = resolveUsersFile();
    if (!resolved.file) {
      console.error('\n[ERROR] Could not find data/users.json.');
      console.error('Searched in:');
      resolved.searched.forEach((p) => console.error('  - ' + p));
      closeNonTty();
      process.exit(1);
    }
    sourceLabel = resolved.file;
    console.log('Inspecting file:       ' + resolved.file + '\n');

    try {
      usersData = JSON.parse(fs.readFileSync(resolved.file, 'utf8'));
    } catch (e) {
      console.error('[ERROR] Failed to read users.json: ' + e.message);
      closeNonTty();
      process.exit(1);
    }
  }

  if (!Array.isArray(usersData) || usersData.length === 0) {
    console.error('[ERROR] ' + sourceLabel + ' contains no user accounts (or is invalid).');
    closeNonTty();
    process.exit(1);
  }

  const defaultUser = process.argv[2] || 'Matt';
  const usernameInput = await readNextLine('Enter username to verify [' + defaultUser + ']: ');
  if (!process.stdin.isTTY) console.log('');
  const targetName = (usernameInput && usernameInput.trim()) || defaultUser;

  const user = usersData.find((u) => u && u.username && u.username.toLowerCase() === targetName.toLowerCase());
  if (!user) {
    console.error('\n[FAIL] User "' + targetName + '" not found in ' + sourceLabel);
    console.error('Available usernames: ' + usersData.map((u) => u && u.username).filter(Boolean).join(', '));
    closeNonTty();
    process.exit(1);
  }

  const passwordInput = await readHidden('Enter live password to verify against stored hash: ');
  const pinInput = await readHidden('Enter 4-digit PIN to verify against stored hash [Enter to skip]: ');

  const hasPasswordRecord = !!(user.password && user.password.salt && user.password.hash);
  const pwMatchesHash = hasPasswordRecord && verifySecretAny(passwordInput, user.password);

  const pinTrimmed = String(pinInput || '').trim();
  const pinProvided = pinTrimmed.length > 0;
  const hasPinRecord = !!(user.pin && user.pin.salt && user.pin.hash);
  const pinMatchesHash = pinProvided && hasPinRecord && verifySecretAny(pinInput, user.pin);

  console.log('\n---------------- Verification Results ----------------');
  console.log('Account checked: ' + user.username + ' (Role: ' + user.role + ')');
  console.log('Live source:     ' + sourceLabel);

  if (!hasPasswordRecord) {
    console.log('[PASSWORD] MISSING: No cryptographic password hash is stored for this user.');
  } else if (pwMatchesHash) {
    console.log('[PASSWORD] MATCH: Password matches the stored cryptographic scrypt hash.');
  } else {
    console.log('[PASSWORD] MISMATCH: Entered password does NOT match the stored cryptographic hash.');
  }

  if (!pinProvided) {
    console.log('[PIN]      SKIPPED: PIN verification was skipped.');
  } else if (!hasPinRecord) {
    console.log('[PIN]      MISSING: No cryptographic PIN hash is stored for this user.');
  } else if (pinMatchesHash) {
    console.log('[PIN]      MATCH: PIN matches the stored cryptographic scrypt hash.');
  } else {
    console.log('[PIN]      MISMATCH: Entered PIN does NOT match the stored cryptographic hash.');
  }

  console.log('------------------------------------------------------');

  if (pwMatchesHash && pinProvided && pinMatchesHash) {
    console.log('\n[VERDICT] SAFE: Both password and PIN match the live stored cryptographic hashes.');
    console.log('Your account credentials in ' + sourceLabel + ' are verified for production use without fallback authentication.');
    closeNonTty();
    process.exit(0);
  } else if (pwMatchesHash && !pinProvided) {
    console.log('\n[VERDICT] INCOMPLETE — NOT SAFE TO CONFIRM FULL ACCESS:');
    console.log('Password matched, but PIN verification was SKIPPED.');
    console.log('A mismatched PIN will still fail idle lock-screen unlock when fallback authentication is disabled.');
    console.log('Re-run `node scripts/verify-admin-credential.js ' + user.username + '` and verify your 4-digit PIN as well.');
    closeNonTty();
    process.exit(1);
  } else {
    const failures = [];
    if (!pwMatchesHash) failures.push('Password');
    if (pinProvided && !pinMatchesHash) failures.push('PIN');
    if (!pinProvided) failures.push('PIN (skipped)');

    console.log('\n[VERDICT] UNSAFE / ACTION REQUIRED (' + failures.join(' & ') + ' failed):');
    console.log('The stored cryptographic hash(es) in ' + sourceLabel + ' could not be verified.');
    if (storageMode === 'mongo') {
      console.log('To recover: sign in as another administrator and reset credentials in the Users panel,');
      console.log('or stop the application and update the user document directly in MongoDB.');
    } else {
      console.log('To recover offline: stop the SOS Tools service, back up users.json,');
      console.log('run `node scripts/set-admin-credential.js ' + user.username + '`, restart the service,');
      console.log('and re-verify both password and PIN with this tool.');
    }
    closeNonTty();
    process.exit(1);
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
    parseDbName,
    loadUsersFromMongo,
  };
}