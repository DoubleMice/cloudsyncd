const fs = require('fs');
const os = require('os');
const path = require('path');

function configDir() {
  if (process.env.CLOUDSYNCD_CONFIG_DIR) return process.env.CLOUDSYNCD_CONFIG_DIR;
  if (process.env.XDG_CONFIG_HOME) return path.join(process.env.XDG_CONFIG_HOME, 'cloudsyncd');
  return path.join(os.homedir(), '.config', 'cloudsyncd');
}

function profileFile() {
  return process.env.CLOUDSYNCD_CLIENT_PROFILE_FILE || path.join(configDir(), 'client-profiles.json');
}

function normalizeBaseUrl(input) {
  const url = new URL(input);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('share-url must start with http:// or https://');
  }
  url.hash = '';
  url.search = '';
  url.pathname = url.pathname.replace(/\/+$/, '') || '/';
  return url.origin + (url.pathname === '/' ? '' : url.pathname);
}

function emptyStore() {
  return { version: 1, profiles: {} };
}

function readStore() {
  const file = profileFile();
  try {
    if (!fs.existsSync(file)) return emptyStore();
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    return data && data.profiles ? data : emptyStore();
  } catch {
    return emptyStore();
  }
}

function writeStore(store) {
  const file = profileFile();
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, JSON.stringify(store, null, 2), { mode: 0o600 });
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    // chmod can fail on some filesystems; the write mode above is the primary guard.
  }
}

function getProfile(baseUrl) {
  const key = normalizeBaseUrl(baseUrl);
  return readStore().profiles[key] || null;
}

function saveProfile(baseUrl, profile) {
  const key = normalizeBaseUrl(baseUrl);
  const store = readStore();
  store.profiles[key] = {
    baseUrl: key,
    deviceId: profile.deviceId,
    masterKey: profile.masterKey,
    pairedAt: profile.pairedAt || new Date().toISOString(),
  };
  writeStore(store);
  return store.profiles[key];
}

function deleteProfile(baseUrl) {
  const key = normalizeBaseUrl(baseUrl);
  const store = readStore();
  const existed = !!store.profiles[key];
  delete store.profiles[key];
  writeStore(store);
  return existed;
}

module.exports = {
  configDir,
  profileFile,
  normalizeBaseUrl,
  readStore,
  writeStore,
  getProfile,
  saveProfile,
  deleteProfile,
};
