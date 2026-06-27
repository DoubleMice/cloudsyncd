// Secure-by-default: hide Express development error pages (stack traces) unless
// explicitly overridden (e.g. NODE_ENV=development for local development).
process.env.NODE_ENV = process.env.NODE_ENV || 'production';

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { pipeline, Transform } = require('stream');
const tar = require('tar');

const app = express();
app.disable('x-powered-by');
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = Buffer.from(buf);
  },
}));
app.use(securityHeaders);
app.use(express.static(path.join(__dirname, 'public')));

// Admin app: a SEPARATE listener bound to loopback only (default :21900).
// The Cloudflare Tunnel forwards only the client port (PORT = 21891), so
// /admin and /api/local/* are never reachable via the public hostname —
// only from this machine (http://127.0.0.1:ADMIN_PORT/admin). For remote
// admin, SSH port-forward ADMIN_PORT instead of exposing it publicly.
const adminApp = express();
adminApp.use(express.json());
adminApp.use(express.static(path.join(__dirname, 'admin')));
adminApp.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin', 'admin.html')));

const MAX_TEXTS = 100;
const TEXT_EXPIRY_MS = 24 * 60 * 60 * 1000;
const MAX_CONCURRENT_DOWNLOADS = 3;
const REQUEST_AUTH_WINDOW_MS = 5 * 60 * 1000;
const REQUEST_NONCE_TTL_MS = 10 * 60 * 1000;
const MAX_NONCES_PER_DEVICE = 512;
let activeDownloads = 0;
const seenRequestNonces = new Map();

const DATA_DIR = path.join(__dirname, 'data');
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const sharedDir = path.join(__dirname, 'shared');

// ============ Security Middleware ============

// Security headers for the tunnel-facing client app. HSTS is intentionally not
// set here: the origin speaks plain HTTP on loopback; HTTPS (and therefore
// HSTS) is terminated by the Cloudflare Tunnel in front of it — set HSTS there.
function securityHeaders(req, res, next) {
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: blob:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join('; '));
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  next();
}

// Minimal in-memory per-IP rate limiter for the unauthenticated pairing
// endpoints (the only unauthenticated routes on the tunnel-facing port). Keyed
// by CF-Connecting-IP (set by the Cloudflare Tunnel) with a socket-IP fallback.
// Caps PIN brute-force / pairing-session-burn DoS from a single source; a legit
// operator pairing from a different IP is unaffected.
const PAIR_RATE_WINDOW_MS = 60_000;
const PAIR_RATE_MAX = 10;
const pairRateBuckets = new Map();
function pairRateLimit(req, res, next) {
  const ip = req.headers['cf-connecting-ip'] || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  let bucket = pairRateBuckets.get(ip);
  if (!bucket || bucket.resetAt < now) {
    bucket = { count: 0, resetAt: now + PAIR_RATE_WINDOW_MS };
    pairRateBuckets.set(ip, bucket);
  }
  bucket.count++;
  if (bucket.count > PAIR_RATE_MAX) {
    res.setHeader('Retry-After', String(Math.ceil((bucket.resetAt - now) / 1000)));
    return res.status(429).json({ error: 'Too many requests' });
  }
  if (pairRateBuckets.size > 4096) {
    for (const [k, v] of pairRateBuckets) if (v.resetAt < now) pairRateBuckets.delete(k);
  }
  next();
}

// Uniform 401 for every request-auth failure — prevents a deviceId-existence
// oracle (differential 401 bodies) on the public endpoints.
function authFail(res) {
  return res.status(401).json({ error: 'Invalid request authentication' });
}

// ============ Persistent State ============

function loadState() {
  try {
    if (fs.existsSync(STATE_FILE)) {
      return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    }
  } catch (e) { console.error('[STATE] Failed to load:', e.message); }
  return null;
}

function saveState(data) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(STATE_FILE, JSON.stringify(data, null, 2));
}

// Master key + admin token: persisted to state.json so they survive restarts.
// The master key is rotated only via the admin "rotate-key" action.
let masterKey = null; // Buffer, 32 bytes
let devices = [];      // [{ id, pairedAt }]
let adminToken = null; // string, 32 hex chars

const saved = loadState();
if (saved && saved.masterKey) {
  masterKey = Buffer.from(saved.masterKey, 'hex');
  devices = saved.devices || [];
  adminToken = saved.adminToken || crypto.randomBytes(16).toString('hex');
  console.log(`[STATE] Loaded master key, ${devices.length} paired device(s)`);
} else {
  masterKey = crypto.randomBytes(32);
  devices = [];
  adminToken = crypto.randomBytes(16).toString('hex');
  console.log('[STATE] Generated new master key');
}

function persistState() {
  saveState({ masterKey: masterKey.toString('hex'), devices, adminToken });
}

// Persist on boot so any freshly generated admin token is durably stored.
persistState();

function persistDevices() {
  persistState();
}

// Rotate the master key: every paired device's derived auth key becomes invalid,
// so all devices are dropped and must re-pair. Files on disk stay plaintext
// (encrypted per request with the current key), so they remain available to
// re-paired devices. Ephemeral texts (encrypted with the old key) won't decrypt.
function rotateMasterKey() {
  masterKey = crypto.randomBytes(32);
  devices = [];
  seenRequestNonces.clear();
  persistState();
}

const ADMIN_TOKEN_FILE = path.join(DATA_DIR, '.admin-token');
const startedAt = Date.now();
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.writeFileSync(ADMIN_TOKEN_FILE, adminToken, { mode: 0o600 });

// ============ Crypto Helpers ============

function generatePin() { return crypto.randomInt(100000, 999999).toString(); }

function generateECDHKeyPair() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return { ecdh, publicKey: ecdh.getPublicKey('hex') };
}

function hkdf(ikm, salt, info, length = 32) {
  return crypto.hkdfSync('sha256', ikm, salt, info, length);
}

function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function deriveRequestAuthKey(deviceId) {
  return Buffer.from(hkdf(masterKey, 'syncd-request-auth', `device:${deviceId}`, 32));
}

function safeEqualHex(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  if (left.length !== right.length || left.length % 2 !== 0) return false;
  try {
    const leftBuf = Buffer.from(left, 'hex');
    const rightBuf = Buffer.from(right, 'hex');
    return leftBuf.length === rightBuf.length && crypto.timingSafeEqual(leftBuf, rightBuf);
  } catch {
    return false;
  }
}

// Constant-time check for the local admin token (used by the admin UI + CLI).
function safeEqualAdminToken(token) {
  if (typeof token !== 'string' || token.length === 0) return false;
  try {
    const a = Buffer.from(token);
    const b = Buffer.from(adminToken);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function buildRequestSignatureMessage(method, originalUrl, timestamp, nonce, bodyHash) {
  return [method.toUpperCase(), originalUrl, timestamp, nonce, bodyHash].join('\n');
}

function pruneSeenNonces(now = Date.now()) {
  for (const [deviceId, entries] of seenRequestNonces.entries()) {
    for (const [nonce, seenAt] of entries.entries()) {
      if (now - seenAt > REQUEST_NONCE_TTL_MS) {
        entries.delete(nonce);
      }
    }
    if (entries.size === 0) {
      seenRequestNonces.delete(deviceId);
    }
  }
}

function hasSeenNonce(deviceId, nonce) {
  const entries = seenRequestNonces.get(deviceId);
  return !!entries && entries.has(nonce);
}

function rememberNonce(deviceId, nonce, now = Date.now()) {
  let entries = seenRequestNonces.get(deviceId);
  if (!entries) {
    entries = new Map();
    seenRequestNonces.set(deviceId, entries);
  }

  entries.set(nonce, now);
  if (entries.size <= MAX_NONCES_PER_DEVICE) return;

  const overflow = entries.size - MAX_NONCES_PER_DEVICE;
  let removed = 0;
  for (const key of entries.keys()) {
    entries.delete(key);
    removed++;
    if (removed >= overflow) break;
  }
}

function requireDeviceAuth(req, res, next) {
  if (devices.length === 0) return res.status(403).json({ error: 'Not paired' });

  const deviceId = req.headers['x-device-id'];
  const timestamp = req.headers['x-auth-timestamp'];
  const nonce = req.headers['x-auth-nonce'];
  const signature = req.headers['x-auth-signature'];
  if (!deviceId || !timestamp || !nonce || !signature) {
    return authFail(res);
  }

  const timestampMs = Number(timestamp);
  if (!Number.isFinite(timestampMs)) {
    return authFail(res);
  }

  const now = Date.now();
  if (Math.abs(now - timestampMs) > REQUEST_AUTH_WINDOW_MS) {
    return authFail(res);
  }

  // Look up the device, but derive an auth key and run the constant-time
  // signature check on the same code path for known AND unknown deviceIds, so
  // an unknown deviceId yields the same 401 as a bad signature — no
  // deviceId-existence oracle via differential responses. An unknown device can
  // never authenticate.
  const device = devices.find((entry) => entry.id === deviceId);
  const bodyHash = sha256Hex(req.rawBody || Buffer.alloc(0));
  const expectedSignature = hmac(
    deriveRequestAuthKey(deviceId),
    buildRequestSignatureMessage(req.method, req.originalUrl, String(timestamp), String(nonce), bodyHash)
  );
  const signatureOk = safeEqualHex(expectedSignature, signature) && !!device;
  if (!signatureOk) {
    return authFail(res);
  }

  pruneSeenNonces(now);
  // A replayed (already-seen) nonce returns the same 401 as any other failure —
  // do not reveal that the signature was otherwise valid.
  if (hasSeenNonce(deviceId, nonce)) {
    return authFail(res);
  }

  rememberNonce(deviceId, nonce, now);
  req.authenticatedDeviceId = deviceId;
  next();
}

function encrypt(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString('hex'), ciphertext: encrypted.toString('hex'), tag: tag.toString('hex') };
}

function createEncryptStream(key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  return { cipher, iv };
}

function streamEncryptedResponse({ res, sourceStream, extraHeaders = {}, label, onComplete }) {
  const { cipher, iv } = createEncryptStream(masterKey);
  let completed = false;
  const appendAuthTag = new Transform({
    transform(chunk, encoding, callback) {
      callback(null, chunk);
    },
    flush(callback) {
      try {
        this.push(cipher.getAuthTag());
        callback();
      } catch (err) {
        callback(err);
      }
    },
  });

  const finish = (err) => {
    if (completed) return;
    completed = true;
    if (onComplete) onComplete(err);
  };

  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Encrypted-IV', iv.toString('hex'));
  res.setHeader('X-Encrypted-Tag-Length', '16');

  for (const [header, value] of Object.entries(extraHeaders)) {
    res.setHeader(header, value);
  }

  pipeline(sourceStream, cipher, appendAuthTag, res, (err) => {
    if (completed) return;
    if (err) {
      console.error(`[${label}] Stream error:`, err.message);
      finish(err);
      if (!res.headersSent) {
        res.status(500).json({ error: `${label} failed` });
      } else if (!res.destroyed) {
        res.destroy(err);
      }
      return;
    }

    finish();
  });
}

// ============ Pending Pairing Session ============
// Ephemeral — only lives in memory, one at a time

let pendingPair = null; // { pin, keyPair, attempts, createdAt }

function createPairSession() {
  pendingPair = {
    pin: generatePin(),
    keyPair: generateECDHKeyPair(),
    attempts: 0,
    maxAttempts: 5,
  };
  console.log('\n========================================');
  console.log(`  Pairing PIN: ${pendingPair.pin}`);
  console.log('  Enter this PIN on the remote device');
  console.log('========================================\n');
  return pendingPair.pin;
}

// ============ API: Pairing ============

app.get('/api/status', (req, res) => {
  res.json({ paired: devices.length > 0 });
});

app.get('/api/pair/init', pairRateLimit, (req, res) => {
  if (!pendingPair) {
    return res.status(400).json({ error: 'No active pairing session. Generate a new PIN on the server.' });
  }
  res.json({ serverPublicKey: pendingPair.keyPair.publicKey });
});

app.post('/api/pair/verify', pairRateLimit, (req, res) => {
  if (!pendingPair) {
    return res.status(400).json({ error: 'No active pairing session' });
  }
  if (pendingPair.attempts >= pendingPair.maxAttempts) {
    pendingPair = null;
    return res.status(403).json({ error: 'Too many attempts. Generate a new PIN.' });
  }

  const { clientPublicKey, proof, deviceId } = req.body || {};
  if (!clientPublicKey || !proof) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  try {
    // Validate the client public key before the ECDH op and BEFORE burning an
    // attempt: a P-256 uncompressed public key is 65 bytes (0x04 + 32 + 32).
    // Malformed keys are rejected with 400 without counting as a PIN guess, so
    // an attacker cannot cheaply burn the 5-attempt budget with garbage.
    const pubBuf = Buffer.from(clientPublicKey, 'hex');
    if (pubBuf.length !== 65 || pubBuf[0] !== 0x04) {
      return res.status(400).json({ error: 'Invalid client public key' });
    }

    const sharedSecret = pendingPair.keyPair.ecdh.computeSecret(pubBuf);
    const authKey = Buffer.from(hkdf(sharedSecret, 'syncd-auth', 'pin-verify', 32));
    const expectedProof = hmac(authKey, pendingPair.pin);

    // Constant-time compare (consistent with the request-auth and admin-token
    // paths). Only a real PIN mismatch counts as an attempt.
    if (!safeEqualHex(expectedProof, proof)) {
      pendingPair.attempts++;
      const remaining = pendingPair.maxAttempts - pendingPair.attempts;
      console.log(`[PAIR] Invalid PIN attempt (${remaining} remaining)`);
      if (pendingPair.attempts >= pendingPair.maxAttempts) {
        pendingPair = null;
        return res.status(403).json({ error: 'Too many attempts. Generate a new PIN.' });
      }
      return res.status(401).json({ error: 'Invalid PIN' });
    }

    // PIN verified — encrypt master key with transport key and send to client
    const transportKey = Buffer.from(hkdf(sharedSecret, 'syncd-transport', 'master-key-delivery', 32));
    const encryptedMasterKey = encrypt(transportKey, masterKey);
    const serverProof = hmac(authKey, 'server-confirmed');

    const id = deviceId || 'unknown';
    const pairedAt = new Date().toISOString();
    const existingDevice = devices.find((entry) => entry.id === id);
    if (existingDevice) {
      existingDevice.pairedAt = pairedAt;
    } else {
      devices.push({ id, pairedAt });
    }
    persistDevices();
    pendingPair = null; // Invalidate PIN

    console.log(`[PAIR] Device paired: ${id} (${devices.length} total)`);

    res.json({ success: true, serverProof, encryptedMasterKey });
  } catch (err) {
    console.error('[PAIR] Error:', err.message);
    // computeSecret throws on an off-curve/invalid point despite the 0x04
    // length check — treat as a bad client key (400), not a server error, and
    // do NOT burn an attempt or leak internal details.
    res.status(400).json({ error: 'Invalid client public key' });
  }
});

// ============ Local-only (admin app): Generate new PIN ============

adminApp.post('/api/local/new-pin', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (!safeEqualAdminToken(token)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const pin = createPairSession();
  res.json({ pin });
});

// ============ Local-only (admin app): Device Management ============

function revokeDevice(id) {
  const before = devices.length;
  devices = devices.filter((entry) => entry.id !== id);
  if (devices.length !== before) persistDevices();
  return before - devices.length;
}

adminApp.get('/api/local/status', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (!safeEqualAdminToken(token)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  if (!fs.existsSync(sharedDir)) fs.mkdirSync(sharedDir, { recursive: true });
  const entries = walkDir(sharedDir);
  let fileCount = 0;
  let totalSize = 0;
  for (const entry of entries) {
    if (entry.type === 'file') {
      fileCount++;
      totalSize += entry.size;
    }
  }
  cleanExpiredTexts();
  res.json({
    startedAt,
    paired: devices.length > 0,
    deviceCount: devices.length,
    hasMasterKey: !!masterKey,
    textsCount: sharedTexts.length,
    textsMax: MAX_TEXTS,
    textsExpiryMs: TEXT_EXPIRY_MS,
    sharedFiles: fileCount,
    sharedSize: totalSize,
  });
});

adminApp.get('/api/local/files', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (!safeEqualAdminToken(token)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  if (!fs.existsSync(sharedDir)) fs.mkdirSync(sharedDir, { recursive: true });
  res.json({ entries: walkDir(sharedDir) });
});

adminApp.get('/api/local/devices', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (!safeEqualAdminToken(token)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json({ devices });
});

adminApp.post('/api/local/revoke', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (!safeEqualAdminToken(token)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const { deviceId } = req.body || {};
  if (!deviceId || typeof deviceId !== 'string') {
    return res.status(400).json({ error: 'Missing deviceId' });
  }
  const removed = revokeDevice(deviceId);
  if (removed === 0) {
    return res.status(404).json({ error: 'Device not found', devices });
  }
  console.log(`[DEVICE] Revoked: ${deviceId} (${devices.length} remaining)`);
  res.json({ success: true, revoked: deviceId, remaining: devices.length });
});

adminApp.post('/api/local/revoke-all', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (!safeEqualAdminToken(token)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const count = devices.length;
  devices = [];
  persistDevices();
  console.log(`[DEVICE] Revoked all devices (${count} removed)`);
  res.json({ success: true, revoked: count, remaining: 0 });
});

adminApp.post('/api/local/rotate-key', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (!safeEqualAdminToken(token)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const revoked = devices.length;
  rotateMasterKey();
  console.log(`[KEY] Master key rotated; ${revoked} device(s) must re-pair`);
  res.json({ success: true, revoked, message: 'Master key rotated. All devices must re-pair.' });
});

adminApp.post('/api/local/rotate-token', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (!safeEqualAdminToken(token)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  adminToken = crypto.randomBytes(16).toString('hex');
  persistState();
  fs.writeFileSync(ADMIN_TOKEN_FILE, adminToken, { mode: 0o600 });
  console.log('[ADMIN] Admin token rotated');
  // Return the new token so the admin session can stay logged in.
  res.json({ success: true, adminToken });
});

// ============ File Sharing (encrypted) ============

function walkDir(dir, prefix = '') {
  if (!fs.existsSync(dir)) return [];
  let results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith('.')) continue;
    const relPath = prefix ? `${prefix}/${entry.name}` : entry.name;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push({ name: relPath, type: 'dir' });
      results = results.concat(walkDir(fullPath, relPath));
    } else if (entry.isFile()) {
      const stat = fs.statSync(fullPath);
      results.push({ name: relPath, type: 'file', size: stat.size, modified: stat.mtime.toISOString() });
    }
  }
  return results;
}

app.get('/api/files', requireDeviceAuth, (req, res) => {
  if (!fs.existsSync(sharedDir)) fs.mkdirSync(sharedDir, { recursive: true });
  const tree = walkDir(sharedDir);
  res.json({ encrypted: encrypt(masterKey, Buffer.from(JSON.stringify(tree))) });
});

app.get(/^\/api\/files\/(.*)/, requireDeviceAuth, (req, res) => {
  const relPath = req.params[0] || '';
  const filePath = path.resolve(path.join(sharedDir, relPath));

  // Containment with real symlink resolution. path.resolve is purely lexical
  // (it does not follow symlinks), so a string startsWith() guard can be
  // bypassed by a shared* sibling directory or by a symlink placed inside
  // shared/. Resolve the real path and require it to stay strictly under the
  // real shared/ root.
  let realFile;
  try {
    realFile = fs.realpathSync(filePath);
  } catch {
    return res.status(404).json({ error: 'Not found' });
  }
  const realShared = fs.realpathSync(sharedDir);
  const rel = path.relative(realShared, realFile);
  if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  let stat;
  try {
    stat = fs.statSync(realFile);
  } catch {
    return res.status(404).json({ error: 'Not found' });
  }
  if (!stat.isFile()) return res.status(404).json({ error: 'Not found' });

  const fileSize = stat.size;

  if (activeDownloads >= MAX_CONCURRENT_DOWNLOADS) {
    return res.status(503).json({ error: 'Too many concurrent downloads. Please try again later.' });
  }

  activeDownloads++;
  streamEncryptedResponse({
    res,
    sourceStream: fs.createReadStream(realFile),
    label: 'FILE',
    extraHeaders: {
      'Content-Length': String(fileSize + 16),
      'X-File-Name': encodeURIComponent(path.basename(relPath)),
      'X-File-Size': String(fileSize),
    },
    onComplete: () => {
      activeDownloads--;
    },
  });
});

// ============ Batch Download ============

app.get('/api/batch', requireDeviceAuth, (req, res) => {
  if (!fs.existsSync(sharedDir)) fs.mkdirSync(sharedDir, { recursive: true });

  const since = req.query.since ? new Date(req.query.since) : null;

  const files = [];
  let totalSize = 0;
  for (const entry of walkDir(sharedDir)) {
    if (entry.type !== 'file') continue;
    if (since && new Date(entry.modified) <= since) continue;
    files.push(entry.name);
    totalSize += entry.size;
  }

  if (files.length === 0) {
    return res.status(204).end();
  }

  if (activeDownloads >= MAX_CONCURRENT_DOWNLOADS) {
    return res.status(503).json({ error: 'Too many concurrent downloads. Please try again later.' });
  }

  activeDownloads++;
  streamEncryptedResponse({
    res,
    sourceStream: tar.create({ gzip: true, cwd: sharedDir }, files),
    label: 'BATCH',
    extraHeaders: {
      'X-Batch-Count': String(files.length),
      'X-Batch-Total-Size': String(totalSize),
    },
    onComplete: () => {
      activeDownloads--;
    },
  });
});

// ============ Text Sharing ============

let sharedTexts = [];

function cleanExpiredTexts() {
  const now = Date.now();
  const before = sharedTexts.length;
  sharedTexts = sharedTexts.filter(t => now - new Date(t.timestamp).getTime() < TEXT_EXPIRY_MS);
  if (sharedTexts.length < before) {
    console.log(`[TEXT] Cleaned ${before - sharedTexts.length} expired texts`);
  }
}

app.post('/api/text', requireDeviceAuth, (req, res) => {
  const { encryptedText } = req.body;
  if (!encryptedText) return res.status(400).json({ error: 'Missing encryptedText' });
  
  cleanExpiredTexts();
  
  if (sharedTexts.length >= MAX_TEXTS) {
    sharedTexts.shift();
  }
  
  sharedTexts.push({ id: crypto.randomUUID(), data: encryptedText, timestamp: new Date().toISOString() });
  console.log(`[TEXT] New encrypted text (${sharedTexts.length} total)`);
  res.json({ success: true });
});

app.get('/api/texts', requireDeviceAuth, (req, res) => {
  cleanExpiredTexts();
  res.json({ texts: sharedTexts });
});

// Catch-all error handler: never leak stack traces to clients, regardless of
// env. Catches body-parser SyntaxError (400) on malformed JSON and any thrown
// error on the public surface, returning only generic messages.
app.use((err, req, res, next) => {
  const status = (err && (err.status || err.statusCode)) || 500;
  console.error(`[ERROR] ${req.method} ${req.originalUrl}:`, err && err.message);
  res.status(status >= 400 && status < 600 ? status : 500).json({
    error: status === 400 ? 'Bad request' : 'Internal error',
  });
});

// ============ Start Server ============

const PORT = process.env.PORT || 21891;
// Client port: bound to loopback by default so it's only reachable via the
// local Cloudflare Tunnel (or on this machine). Set HOST=0.0.0.0 to expose on LAN.
const HOST = process.env.HOST || '127.0.0.1';
app.listen(PORT, HOST, () => {
  console.log(`cloudsyncd client  on http://${HOST}:${PORT}  (tunnel-facing)`);
  console.log(`Shared directory: ${sharedDir}`);
  console.log(`Paired devices: ${devices.length}`);
  if (devices.length === 0) {
    createPairSession();
  } else {
    console.log('\nReady. Run `node pin.js` to generate a PIN for a new device.');
    console.log('Run `node devices.js` to list or revoke paired devices.\n');
  }
});

// Admin port: loopback only, NOT forwarded by the tunnel. Manage at
// http://127.0.0.1:ADMIN_PORT/admin. Override ADMIN_HOST only if you know
// exactly what network you're exposing the admin surface to.
const ADMIN_PORT = process.env.ADMIN_PORT || 21900;
const ADMIN_HOST = process.env.ADMIN_HOST || '127.0.0.1';
adminApp.listen(ADMIN_PORT, ADMIN_HOST, () => {
  console.log(`cloudsyncd admin   on http://${ADMIN_HOST}:${ADMIN_PORT}/admin  (local only)`);
});
