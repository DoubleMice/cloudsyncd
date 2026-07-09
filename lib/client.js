const fs = require('fs');
const path = require('path');
const { pipeline } = require('stream/promises');
const { Readable } = require('stream');
const readline = require('readline/promises');

const {
  decryptEnvelope,
  derivePairingMaterial,
  createClientPairKey,
  encodeRemotePath,
  signRequest,
} = require('./protocol');
const {
  CHUNKED_ENCRYPTION_MODE,
  createChunkedDecryptStream,
} = require('./chunked-encryption');
const profiles = require('./client-profiles');

class HttpError extends Error {
  constructor(status, message) {
    super(message || `HTTP ${status}`);
    this.name = 'HttpError';
    this.status = status;
  }
}

function fetchFailureDetail(err) {
  const cause = err && err.cause;
  if (cause && cause.code) {
    const target = cause.address && cause.port ? ` ${cause.address}:${cause.port}` : '';
    return `${cause.code}${target}`;
  }
  if (cause && cause.message) return cause.message;
  if (err && err.message && err.message !== 'fetch failed') return err.message;
  return 'network request failed';
}

function networkErrorMessage(url, err) {
  const detail = fetchFailureDetail(err);
  return [
    `Cannot reach cloudsyncd share URL: ${url} (${detail}).`,
    'Check the URL, DNS/TLS, firewall, and that the share-side server is running.',
    'If using Cloudflare Tunnel, test /api/status from this client and verify the origin is listening on 127.0.0.1:21891.',
  ].join(' ');
}

async function requestFetch(url, options = {}) {
  try {
    return await fetch(url, options);
  } catch (err) {
    throw new Error(networkErrorMessage(url, err));
  }
}

function joinBasePath(basePath, apiPath) {
  const cleanBase = basePath.replace(/\/+$/, '');
  const cleanApi = apiPath.startsWith('/') ? apiPath : `/${apiPath}`;
  return `${cleanBase}${cleanApi}` || '/';
}

function buildApiUrl(baseUrl, apiPath) {
  const normalized = profiles.normalizeBaseUrl(baseUrl);
  const base = new URL(normalized);
  const api = new URL(apiPath, 'http://cloudsyncd.local');
  base.pathname = joinBasePath(base.pathname, api.pathname);
  base.search = api.search;
  base.hash = '';
  return base;
}

async function readErrorMessage(res, fallback) {
  try {
    const text = await res.text();
    if (!text) return fallback;
    try {
      const data = JSON.parse(text);
      return data.error || fallback;
    } catch {
      return text.slice(0, 180);
    }
  } catch {
    return fallback;
  }
}

async function fetchJson(url, options = {}) {
  const res = await requestFetch(url, options);
  const contentType = res.headers.get('content-type') || '';
  let data = null;
  if (contentType.includes('application/json')) {
    data = await res.json();
  } else {
    const text = await res.text();
    if (text) {
      try { data = JSON.parse(text); } catch { data = { error: text }; }
    }
  }
  if (!res.ok) {
    throw new HttpError(res.status, data && data.error ? data.error : `HTTP ${res.status}`);
  }
  return data;
}

function signedFetch(profile, apiPath, options = {}) {
  const url = buildApiUrl(profile.baseUrl, apiPath);
  const method = (options.method || 'GET').toUpperCase();
  const body = options.body || Buffer.alloc(0);
  const headers = {
    ...(options.headers || {}),
    ...signRequest({
      masterKey: Buffer.from(profile.masterKey, 'hex'),
      deviceId: profile.deviceId,
      method,
      signedPath: url.pathname + url.search,
      body,
    }),
  };
  return requestFetch(url, { ...options, method, headers, body: options.body });
}

async function promptPin(baseUrl, io = {}) {
  if (io.pin) return String(io.pin).trim();
  if (!process.stdin.isTTY) {
    throw new Error('Missing --pin. Non-interactive pairing cannot prompt for a PIN.');
  }
  const rl = readline.createInterface({
    input: io.stdin || process.stdin,
    output: io.stderr || process.stderr,
  });
  try {
    const pin = await rl.question(`Enter pairing PIN for ${baseUrl}: `);
    return pin.trim();
  } finally {
    rl.close();
  }
}

function makeDeviceId() {
  const safeHost = require('os').hostname().replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 24) || 'host';
  const suffix = require('crypto').randomBytes(4).toString('hex');
  return `client-${safeHost}-${suffix}`;
}

async function pair(baseUrl, options = {}) {
  const normalized = profiles.normalizeBaseUrl(baseUrl);
  const initUrl = buildApiUrl(normalized, '/api/pair/init');
  let init;
  try {
    init = await fetchJson(initUrl);
  } catch (err) {
    if (err instanceof HttpError && err.status === 400) {
      throw new Error(`${err.message}. Generate a PIN on the server with: cloudsyncd server pin`);
    }
    throw err;
  }
  if (!init || !init.serverPublicKey) {
    throw new Error('Pairing init response is missing serverPublicKey');
  }

  const pin = await promptPin(normalized, options);
  const client = createClientPairKey();
  const material = derivePairingMaterial(client.ecdh, init.serverPublicKey, pin);
  const deviceId = options.deviceId || makeDeviceId();
  const verifyUrl = buildApiUrl(normalized, '/api/pair/verify');
  const verified = await fetchJson(verifyUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      clientPublicKey: client.publicKeyHex,
      proof: material.proof,
      deviceId,
    }),
  });

  if (verified.serverProof !== material.expectedServerProof) {
    throw new Error('Server proof verification failed');
  }

  const masterKey = decryptEnvelope(material.transportKey, verified.encryptedMasterKey);
  return profiles.saveProfile(normalized, {
    deviceId,
    masterKey: masterKey.toString('hex'),
    pairedAt: new Date().toISOString(),
  });
}

async function ensurePaired(baseUrl, options = {}) {
  const normalized = profiles.normalizeBaseUrl(baseUrl);
  const existing = profiles.getProfile(normalized);
  if (existing) return existing;
  const profile = await pair(normalized, options);
  if (options.stderr) options.stderr.write(`Paired receiver device: ${profile.deviceId}\n`);
  return profile;
}

async function withAuthRetry(baseUrl, options, action) {
  const normalized = profiles.normalizeBaseUrl(baseUrl);
  let profile = await ensurePaired(normalized, options);
  try {
    return await action(profile);
  } catch (err) {
    if (!(err instanceof HttpError) || err.status !== 401) throw err;
    profiles.deleteProfile(normalized);
    if (options.stderr) options.stderr.write('Stored receiver profile was rejected; re-pairing once.\n');
    profile = await pair(normalized, options);
    return action(profile);
  }
}

async function listFiles(baseUrl, options = {}) {
  return withAuthRetry(baseUrl, options, async (profile) => {
    const res = await signedFetch(profile, '/api/files');
    if (!res.ok) throw new HttpError(res.status, await readErrorMessage(res, `HTTP ${res.status}`));
    const data = await res.json();
    const plain = decryptEnvelope(Buffer.from(profile.masterKey, 'hex'), data.encrypted);
    return JSON.parse(plain.toString('utf8'));
  });
}

function decodeHeaderFilename(value) {
  if (!value) return '';
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function timestampName() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function resolveOutputPath(output, fallbackName) {
  if (!output) return path.resolve(process.cwd(), fallbackName);
  if (output.endsWith('/') || output.endsWith(path.sep)) {
    return path.join(path.resolve(output), fallbackName);
  }
  const resolved = path.resolve(output);
  if (fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) {
    return path.join(resolved, fallbackName);
  }
  return resolved;
}

function tempPathFor(finalPath, suffix) {
  const dir = path.dirname(finalPath);
  const base = path.basename(finalPath);
  return path.join(dir, `.${base}.cloudsyncd-${process.pid}-${Date.now()}-${suffix}`);
}

function parseResponseInteger(value, label, min = 0) {
  const n = Number.parseInt(value || '', 10);
  if (!Number.isSafeInteger(n) || n < min) throw new Error(`Invalid ${label}`);
  return n;
}

function normalizeRemoteRelPath(remotePath) {
  return String(remotePath || '').replace(/\\/g, '/').replace(/^\/+/, '');
}

async function decryptEncryptedFile({ encryptedPath, outputPath, key, ivHex, tagLength }) {
  const stat = fs.statSync(encryptedPath);
  if (stat.size < tagLength) throw new Error('Encrypted payload is truncated');
  const tagFd = fs.openSync(encryptedPath, 'r');
  const tag = Buffer.alloc(tagLength);
  try {
    fs.readSync(tagFd, tag, 0, tagLength, stat.size - tagLength);
  } finally {
    fs.closeSync(tagFd);
  }

  const crypto = require('crypto');
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(key, 'hex'), Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(tag);
  const ciphertextEnd = stat.size - tagLength - 1;
  const source = ciphertextEnd >= 0
    ? fs.createReadStream(encryptedPath, { start: 0, end: ciphertextEnd })
    : Readable.from([]);
  await pipeline(source, decipher, fs.createWriteStream(outputPath, { mode: 0o600 }));
}

async function writeResponseToFile(res, filePath) {
  if (!res.body) throw new Error('Response body is empty');
  await pipeline(Readable.fromWeb(res.body), fs.createWriteStream(filePath, { mode: 0o600 }));
}

async function streamChunkedResponseToFile({ res, filePath, key, relPath, onManifest }) {
  if (!res.body) throw new Error('Response body is empty');
  if (res.headers.get('x-encrypted-mode') !== CHUNKED_ENCRYPTION_MODE) {
    throw new Error('Response is missing chunked encrypted stream headers');
  }

  const ivPrefix = Buffer.from(res.headers.get('x-encrypted-iv-prefix') || '', 'hex');
  const tagLength = parseResponseInteger(res.headers.get('x-encrypted-tag-length') || '16', 'encrypted tag length', 1);
  const chunkSize = parseResponseInteger(res.headers.get('x-encrypted-chunk-size'), 'encrypted chunk size', 1);
  const fileSize = parseResponseInteger(res.headers.get('x-file-size'), 'file size', 0);
  const decrypt = createChunkedDecryptStream(Buffer.from(key, 'hex'), {
    ivPrefix,
    tagLength,
    chunkSize,
    fileSize,
    relPath,
    onManifest,
  });

  await pipeline(Readable.fromWeb(res.body), decrypt, fs.createWriteStream(filePath, { mode: 0o600 }));
  return { fileSize };
}

async function downloadChunkedEncryptedResponse(profile, apiPath, output, options = {}) {
  const res = await signedFetch(profile, apiPath);
  if (res.status === 204) return { empty: true };
  if (!res.ok) throw new HttpError(res.status, await readErrorMessage(res, `HTTP ${res.status}`));

  const responseFilename = decodeHeaderFilename(res.headers.get('x-file-name'));
  const finalPath = resolveOutputPath(output, responseFilename || options.fallbackName);
  if (fs.existsSync(finalPath) && !options.force) {
    throw new Error(`Output file already exists: ${finalPath}. Use --force to overwrite.`);
  }
  fs.mkdirSync(path.dirname(finalPath), { recursive: true });

  const plainTmp = tempPathFor(finalPath, 'plain');
  let manifest = null;
  try {
    const { fileSize } = await streamChunkedResponseToFile({
      res,
      filePath: plainTmp,
      key: profile.masterKey,
      relPath: options.relPath || '',
      onManifest: (m) => { manifest = m; },
    });
    if (fs.existsSync(finalPath)) fs.rmSync(finalPath, { force: true });
    fs.renameSync(plainTmp, finalPath);
    return {
      outputPath: finalPath,
      filename: responseFilename,
      size: fileSize,
      manifest,
      streamed: true,
    };
  } finally {
    fs.rmSync(plainTmp, { force: true });
  }
}

async function downloadEncryptedResponse(profile, apiPath, output, options = {}) {
  const res = await signedFetch(profile, apiPath);
  if (res.status === 204) return { empty: true };
  if (!res.ok) throw new HttpError(res.status, await readErrorMessage(res, `HTTP ${res.status}`));

  const ivHex = res.headers.get('x-encrypted-iv');
  const tagLength = Number.parseInt(res.headers.get('x-encrypted-tag-length') || '16', 10);
  if (!ivHex || !Number.isFinite(tagLength) || tagLength <= 0) {
    throw new Error('Response is missing encrypted stream headers');
  }

  const responseFilename = decodeHeaderFilename(res.headers.get('x-file-name'));
  const finalPath = resolveOutputPath(output, responseFilename || options.fallbackName);
  if (fs.existsSync(finalPath) && !options.force) {
    throw new Error(`Output file already exists: ${finalPath}. Use --force to overwrite.`);
  }
  fs.mkdirSync(path.dirname(finalPath), { recursive: true });

  const encryptedTmp = tempPathFor(finalPath, 'encrypted');
  const plainTmp = tempPathFor(finalPath, 'plain');
  try {
    await writeResponseToFile(res, encryptedTmp);
    await decryptEncryptedFile({
      encryptedPath: encryptedTmp,
      outputPath: plainTmp,
      key: profile.masterKey,
      ivHex,
      tagLength,
    });
    if (fs.existsSync(finalPath)) fs.rmSync(finalPath, { force: true });
    fs.renameSync(plainTmp, finalPath);
    return {
      outputPath: finalPath,
      filename: responseFilename,
      size: Number.parseInt(res.headers.get('x-file-size') || '0', 10) || null,
    };
  } finally {
    fs.rmSync(encryptedTmp, { force: true });
    fs.rmSync(plainTmp, { force: true });
  }
}

async function downloadFile(baseUrl, remotePath, options = {}) {
  const encoded = encodeRemotePath(remotePath);
  return withAuthRetry(baseUrl, options, async (profile) => {
    const fallbackName = path.basename(remotePath.replace(/\/+$/, '')) || 'download.bin';
    return downloadChunkedEncryptedResponse(profile, `/api/files-chunked/${encoded}`, options.output, {
      fallbackName,
      force: options.force,
      relPath: normalizeRemoteRelPath(remotePath),
    });
  });
}

async function downloadBatch(baseUrl, options = {}) {
  const params = new URLSearchParams();
  if (options.since) params.set('since', options.since);
  const apiPath = `/api/batch${params.toString() ? `?${params}` : ''}`;
  return withAuthRetry(baseUrl, options, async (profile) => {
    return downloadEncryptedResponse(profile, apiPath, options.output, {
      fallbackName: `cloudsyncd-batch-${timestampName()}.tar.gz`,
      force: options.force,
    });
  });
}

function logout(baseUrl) {
  return profiles.deleteProfile(baseUrl);
}

module.exports = {
  HttpError,
  buildApiUrl,
  fetchFailureDetail,
  networkErrorMessage,
  requestFetch,
  signedFetch,
  pair,
  ensurePaired,
  withAuthRetry,
  listFiles,
  downloadFile,
  downloadBatch,
  logout,
};
