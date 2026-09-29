/**
 * SOS Tools Web — data store.
 *
 * Two modes:
 *  - "mongo": when MONGODB_URI is set (used on cloud hosts so accounts survive
 *    restarts/redeploys). Memory is the working copy; writes go through to Mongo.
 *  - "file":  default local mode — JSON files in ./data (identical schema to the
 *    desktop edition, so users.json can be migrated by copying the file).
 *
 * All reads are synchronous from memory for simplicity; this app is a single
 * small instance. Writes are write-through (memory updated immediately, Mongo
 * persisted asynchronously).
 */
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const AUDIT_FILE = path.join(DATA_DIR, 'activity-log.jsonl');
const ACTIVITY_MEMORY_LIMIT = 1000;

let mode = 'file';
let mongo = null; // { users, settings, activity } collections
let users = null;
let settings = null;
let activity = [];

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJson(file, value) {
  ensureDataDir();
  fs.writeFileSync(file, JSON.stringify(value, null, 2), 'utf8');
}

async function init() {
  ensureDataDir();
  const uri = process.env.MONGODB_URI;
  if (uri) {
    try {
      const { MongoClient } = require('mongodb');
      const client = new MongoClient(uri, { serverSelectionTimeoutMS: 15000 });
      await client.connect();
      const dbName = parseDbName(uri) || 'sos-tools';
      const db = client.db(dbName);
      mongo = {
        users: db.collection('users'),
        settings: db.collection('settings'),
        activity: db.collection('activity'),
        client,
      };
      users = await mongo.users.find({}).toArray();
      const sdoc = await mongo.settings.findOne({ _id: 'app' });
      settings = sdoc ? sdoc.value : null;
      activity = (await mongo.activity.find({}).sort({ ts: -1 }).limit(ACTIVITY_MEMORY_LIMIT).toArray()).reverse();
      mode = 'mongo';
      console.log(`Data store: MongoDB (${dbName}) — ${users.length} users loaded`);
      return mode;
    } catch (err) {
      console.error('MongoDB connection failed — falling back to local file store:', err.message);
      mongo = null;
    }
  }
  users = readJson(USERS_FILE, null);
  settings = readJson(SETTINGS_FILE, null);
  try {
    const raw = fs.readFileSync(AUDIT_FILE, 'utf8').trim();
    activity = raw ? raw.split('\n').slice(-ACTIVITY_MEMORY_LIMIT).map(safeParse) : [];
  } catch {
    activity = [];
  }
  mode = 'file';
  console.log('Data store: local files (./data)');
  return mode;
}

function safeParse(line) {
  try {
    return JSON.parse(line);
  } catch {
    return { ts: '', user: '?', action: 'unparsable', details: line };
  }
}

function parseDbName(uri) {
  const m = uri.match(/\/([^/?]+)(\?|$)/);
  return m && m[1] ? m[1] : null;
}

// ---- Users ----
function getUsers() {
  return users || [];
}

function setUsers(next) {
  users = next;
  writeJson(USERS_FILE, users); // local mirror (also the file-mode store)
  if (mongo) {
    const ops = users.map((u) => ({
      replaceOne: { filter: { username: u.username }, replacement: clone(u), upsert: true },
    }));
    const names = users.map((u) => u.username);
    mongo.users
      .bulkWrite(ops)
      .then(() => mongo.users.deleteMany({ username: { $nin: names } }))
      .catch((err) => console.error('Mongo users write failed:', err.message));
  }
}

// ---- Settings ----
function getSettings() {
  return settings;
}

function setSettings(next) {
  settings = next;
  writeJson(SETTINGS_FILE, settings);
  if (mongo) {
    mongo.settings
      .replaceOne({ _id: 'app' }, { _id: 'app', value: clone(settings) }, { upsert: true })
      .catch((err) => console.error('Mongo settings write failed:', err.message));
  }
}

// ---- Activity log ----
function appendActivity(entry) {
  activity.push(entry);
  if (activity.length > ACTIVITY_MEMORY_LIMIT) {
    activity = activity.slice(-ACTIVITY_MEMORY_LIMIT);
  }
  try {
    ensureDataDir();
    fs.appendFileSync(AUDIT_FILE, JSON.stringify(entry) + '\n', 'utf8');
  } catch (err) {
    console.error('Failed to write local activity log:', err.message);
  }
  if (mongo) {
    mongo.activity.insertOne(clone(entry)).catch((err) => console.error('Mongo activity write failed:', err.message));
  }
}

function getActivity(limit) {
  return activity.slice(-limit);
}

function getMode() {
  return mode;
}

function clone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

module.exports = {
  init,
  getUsers,
  setUsers,
  getSettings,
  setSettings,
  appendActivity,
  getActivity,
  getMode,
  DATA_DIR,
};
