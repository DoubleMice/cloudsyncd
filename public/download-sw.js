const DOWNLOAD_PREFIX = '/__cloudsyncd_download__/';
const DOWNLOAD_SW_PROTOCOL = 'chunked-fetch-v1';
const DOWNLOAD_INIT_TIMEOUT_MS = 5 * 60 * 1000;
const DOWNLOAD_FETCH_RECORD_TIMEOUT_MS = 15 * 1000;
const CHUNKED_ENCRYPTION_MODE = 'chunked-v2';
const FINAL_FRAME_MARKER = 0;
const FINAL_MANIFEST_MAX_BYTES = 64 * 1024;
const downloads = new Map();
const pendingRecordWaiters = new Map();
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

function fallbackFilename(filename) {
  const cleaned = String(filename || 'download.bin').replace(/[^\x20-\x7e]+/g, '_').replace(/["\\]/g, '_');
  return cleaned || 'download.bin';
}

function contentDisposition(filename) {
  const fallback = fallbackFilename(filename);
  return `attachment; filename="${fallback}"; filename*=UTF-8''${encodeURIComponent(filename || fallback)}`;
}

function postToRecord(record, message) {
  try {
    if (record.port) record.port.postMessage(message);
  } catch {
    // The page may have navigated away. Browser-managed downloads should keep
    // going even when there is no page left to receive progress messages.
  }
}

function hex2buf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return bytes;
}

function buf2hex(buf) {
  return Array.from(buf).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function readUint32BE(bytes) {
  return ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
}

function chunkIv(prefix, counter) {
  const iv = new Uint8Array(12);
  iv.set(prefix, 0);
  new DataView(iv.buffer).setUint32(8, counter, false);
  return iv;
}

function chunkFrameAad(kind, counter, context) {
  return textEncoder.encode([
    'cloudsyncd',
    CHUNKED_ENCRYPTION_MODE,
    kind,
    String(counter),
    String(context.fileSize),
    String(context.chunkSize),
    context.relPath,
  ].join('\n'));
}

function parseSafeInteger(value, label, min = 0) {
  const number = Number.parseInt(value || '', 10);
  if (!Number.isSafeInteger(number) || number < min) throw new Error(`${label} invalid`);
  return number;
}

function validateChunkedManifest(manifest, context, chunkCount) {
  if (!manifest || typeof manifest !== 'object') throw new Error('Chunked download is missing final manifest');
  if (manifest.mode !== CHUNKED_ENCRYPTION_MODE) throw new Error('Chunked manifest mode mismatch');
  if (manifest.fileSize !== context.fileSize) throw new Error('Chunked manifest file size mismatch');
  if (manifest.chunkSize !== context.chunkSize) throw new Error('Chunked manifest chunk size mismatch');
  if (manifest.chunkCount !== chunkCount) throw new Error('Chunked manifest chunk count mismatch');
  if (manifest.relPath !== context.relPath) throw new Error('Chunked manifest path mismatch');
}

async function sha256Hex(data) {
  const digest = await crypto.subtle.digest('SHA-256', data);
  return buf2hex(new Uint8Array(digest));
}

async function hmacHex(keyBytes, data) {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, textEncoder.encode(data));
  return buf2hex(new Uint8Array(signature));
}

async function deriveRequestAuthKey(masterKeyBytes, deviceId) {
  const baseKey = await crypto.subtle.importKey('raw', masterKeyBytes, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({
    name: 'HKDF',
    hash: 'SHA-256',
    salt: textEncoder.encode('syncd-request-auth'),
    info: textEncoder.encode(`device:${deviceId}`),
  }, baseKey, 256);
  return new Uint8Array(bits);
}

async function importAesKey(keyBytes) {
  return crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
}

async function decryptCombinedBytes(aesKey, ivBytes, encryptedBytes, tagLength = 16, additionalData = null) {
  const algorithm = {
    name: 'AES-GCM',
    iv: ivBytes,
    tagLength: tagLength * 8,
  };
  if (additionalData) algorithm.additionalData = additionalData;
  return new Uint8Array(await crypto.subtle.decrypt(algorithm, aesKey, encryptedBytes));
}

function randomNonce() {
  return crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

async function signedFetch(record, signal) {
  const url = new URL(record.apiPath, self.location.origin);
  if (url.origin !== self.location.origin) throw new Error('Download API must be same-origin');
  if (!url.pathname.startsWith('/api/files-chunked/')) throw new Error('Unsupported download API path');

  const method = 'GET';
  const signedPath = url.pathname + url.search;
  const timestamp = Date.now().toString();
  const nonce = randomNonce();
  const bodyHash = await sha256Hex(new Uint8Array());
  const masterKeyBytes = hex2buf(record.keyHex);
  const authKey = await deriveRequestAuthKey(masterKeyBytes, record.deviceId);
  const signature = await hmacHex(authKey, [method, signedPath, timestamp, nonce, bodyHash].join('\n'));
  const headers = new Headers({
    'X-Device-Id': record.deviceId,
    'X-Auth-Timestamp': timestamp,
    'X-Auth-Nonce': nonce,
    'X-Auth-Signature': signature,
  });

  return fetch(signedPath, { method, headers, signal, cache: 'no-store' });
}

async function readErrorMessage(res, fallback) {
  try {
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      const body = await res.json();
      if (body && body.error) return `${fallback}: ${res.status} ${body.error}`;
    }
    const text = await res.text();
    if (text) return `${fallback}: ${res.status} ${text.slice(0, 160)}`;
  } catch {
    // Preserve the original failure when the error body is not readable.
  }
  return `${fallback}: ${res.status}`;
}

async function* decryptChunkedDownloadResponse(res, record) {
  if (!res.body || !res.body.getReader) {
    throw new Error('ReadableStream is unavailable for this download');
  }
  if (res.headers.get('x-encrypted-mode') !== CHUNKED_ENCRYPTION_MODE) {
    throw new Error('Server did not return a chunked encrypted response');
  }

  const ivPrefix = hex2buf(res.headers.get('x-encrypted-iv-prefix') || '');
  if (ivPrefix.length !== 8) throw new Error('Chunked response is missing IV prefix');

  const tagLength = Number.parseInt(res.headers.get('x-encrypted-tag-length') || '16', 10);
  const chunkSize = parseSafeInteger(res.headers.get('x-encrypted-chunk-size'), 'chunk size', 1);
  const fileSize = parseSafeInteger(res.headers.get('x-file-size'), 'file size');
  const context = { fileSize, chunkSize, relPath: record.relPath };
  if (!Number.isFinite(tagLength) || tagLength <= 0) throw new Error('Invalid encrypted tag length');

  const aesKey = await importAesKey(hex2buf(record.keyHex));
  const reader = res.body.getReader();
  const pendingChunks = [];
  let pendingBytes = 0;
  let counter = 0;
  let plaintextBytes = 0;

  function enqueue(chunk) {
    if (!chunk || chunk.length === 0) return;
    pendingChunks.push(chunk);
    pendingBytes += chunk.length;
  }

  function readQueued(size) {
    if (pendingBytes < size) return null;
    if (size === 0) return new Uint8Array(0);

    const first = pendingChunks[0];
    if (first.length === size) {
      pendingChunks.shift();
      pendingBytes -= size;
      return first;
    }
    if (first.length > size) {
      const out = first.subarray(0, size);
      pendingChunks[0] = first.subarray(size);
      pendingBytes -= size;
      return out;
    }

    const out = new Uint8Array(size);
    let offset = 0;
    let remaining = size;
    while (remaining > 0) {
      const head = pendingChunks[0];
      const take = Math.min(head.length, remaining);
      out.set(head.subarray(0, take), offset);
      offset += take;
      remaining -= take;
      if (take === head.length) pendingChunks.shift();
      else pendingChunks[0] = head.subarray(take);
    }
    pendingBytes -= size;
    return out;
  }

  async function readExact(size) {
    while (pendingBytes < size) {
      const { value, done } = await reader.read();
      if (done) {
        if (pendingBytes === 0) return null;
        throw new Error('Chunked encrypted response was truncated');
      }
      enqueue(value);
    }
    return readQueued(size);
  }

  for (;;) {
    const header = await readExact(4);
    if (!header) throw new Error('Chunked encrypted response is missing final manifest');

    const encryptedLength = readUint32BE(header);
    if (encryptedLength === FINAL_FRAME_MARKER) {
      const manifestHeader = await readExact(4);
      if (!manifestHeader) throw new Error('Final manifest header was truncated');
      const manifestLength = readUint32BE(manifestHeader);
      if (manifestLength < tagLength || manifestLength > FINAL_MANIFEST_MAX_BYTES) {
        throw new Error('Invalid final manifest length');
      }
      const encryptedManifest = await readExact(manifestLength);
      if (!encryptedManifest) throw new Error('Final manifest was truncated');
      const manifestBytes = await decryptCombinedBytes(
        aesKey,
        chunkIv(ivPrefix, counter),
        encryptedManifest,
        tagLength,
        chunkFrameAad('final', counter, context)
      );
      const manifest = JSON.parse(textDecoder.decode(manifestBytes));
      validateChunkedManifest(manifest, context, counter);
      const extra = await readExact(1);
      if (extra) throw new Error('Unexpected data after final manifest');
      if (plaintextBytes !== fileSize) throw new Error('Plaintext size mismatch');
      return { bytes: plaintextBytes, manifest };
    }

    if (encryptedLength < tagLength || encryptedLength > chunkSize + tagLength) {
      throw new Error('Invalid chunk frame length');
    }
    const encrypted = await readExact(encryptedLength);
    if (!encrypted) throw new Error('Chunked encrypted response was truncated');
    const plain = await decryptCombinedBytes(
      aesKey,
      chunkIv(ivPrefix, counter),
      encrypted,
      tagLength,
      chunkFrameAad('data', counter, context)
    );
    plaintextBytes += plain.length;
    counter += 1;
    yield plain;
  }
}

function resolvePendingRecord(id, record) {
  const waiters = pendingRecordWaiters.get(id);
  if (!waiters) return;
  pendingRecordWaiters.delete(id);
  waiters.forEach(({ resolve, timer }) => {
    clearTimeout(timer);
    resolve(record);
  });
}

function waitForDownloadRecord(id) {
  const existing = downloads.get(id);
  if (existing) return Promise.resolve(existing);
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      const waiters = pendingRecordWaiters.get(id) || [];
      const remaining = waiters.filter((entry) => entry.timer !== timer);
      if (remaining.length) pendingRecordWaiters.set(id, remaining);
      else pendingRecordWaiters.delete(id);
      resolve(null);
    }, DOWNLOAD_FETCH_RECORD_TIMEOUT_MS);
    const waiters = pendingRecordWaiters.get(id) || [];
    waiters.push({ resolve, timer });
    pendingRecordWaiters.set(id, waiters);
  });
}

function forgetDownload(id) {
  const record = downloads.get(id);
  if (record && record.abortController) record.abortController.abort();
  downloads.delete(id);
  const waiters = pendingRecordWaiters.get(id);
  if (!waiters) return;
  pendingRecordWaiters.delete(id);
  waiters.forEach(({ resolve, timer }) => {
    clearTimeout(timer);
    resolve(null);
  });
}

function makeDownloadStream(id, port) {
  const queue = [];
  let done = false;
  let failure = null;
  let wakePull = null;

  const wake = () => {
    if (!wakePull) return;
    const resolve = wakePull;
    wakePull = null;
    resolve();
  };

  port.onmessage = (event) => {
    const data = event.data || {};
    if (data.type === 'chunk') {
      queue.push(data.chunk);
      wake();
      return;
    }
    if (data.type === 'close') {
      done = true;
      wake();
      return;
    }
    if (data.type === 'abort') {
      failure = new Error(data.error || 'Download aborted');
      done = true;
      wake();
    }
  };

  return new ReadableStream({
    async pull(controller) {
      const record = downloads.get(id);
      if (record) record.started = true;
      while (!queue.length && !done && !failure) {
        await new Promise((resolve) => { wakePull = resolve; });
      }

      if (failure) {
        forgetDownload(id);
        port.postMessage({ type: 'error', error: failure.message });
        controller.error(failure);
        return;
      }

      if (queue.length) {
        controller.enqueue(new Uint8Array(queue.shift()));
        port.postMessage({ type: 'ack' });
        return;
      }

      if (done) {
        forgetDownload(id);
        port.postMessage({ type: 'closed' });
        controller.close();
      }
    },
    cancel(reason) {
      forgetDownload(id);
      port.postMessage({ type: 'cancel', reason: String(reason || '') });
    },
  });
}

function makeFetchDecryptStream(id, record, res) {
  const iterator = decryptChunkedDownloadResponse(res, record);
  let settled = false;

  async function closeRecord(message) {
    if (settled) return;
    settled = true;
    downloads.delete(id);
    postToRecord(record, message);
  }

  return new ReadableStream({
    async pull(controller) {
      try {
        const next = await iterator.next();
        if (next.done) {
          await closeRecord({ type: 'closed', ...(next.value || {}) });
          controller.close();
          return;
        }
        controller.enqueue(next.value);
      } catch (err) {
        console.error('cloudsyncd download stream failed:', err);
        await closeRecord({ type: 'error', error: err.message || String(err) });
        controller.error(err);
      }
    },
    async cancel(reason) {
      record.abortController.abort();
      if (iterator.return) {
        try { await iterator.return(); } catch {}
      }
      await closeRecord({ type: 'cancel', reason: String(reason || '') });
    },
  });
}

function validFetchRecord(data) {
  return (
    data.source === 'chunked-fetch'
    && typeof data.apiPath === 'string'
    && typeof data.relPath === 'string'
    && typeof data.keyHex === 'string'
    && /^[0-9a-fA-F]{64}$/.test(data.keyHex)
    && typeof data.deviceId === 'string'
    && data.deviceId.length > 0
  );
}

self.addEventListener('message', (event) => {
  const data = event.data || {};
  if (data.type === 'cloudsyncd-download-ping') {
    if (event.ports && event.ports[0]) {
      event.ports[0].postMessage({
        type: 'cloudsyncd-download-pong',
        protocol: DOWNLOAD_SW_PROTOCOL,
      });
    }
    return;
  }
  if (data.type === 'cloudsyncd-skip-waiting') {
    event.waitUntil(self.skipWaiting());
    return;
  }
  if (data.type !== 'cloudsyncd-download-init' || !data.id || !event.ports || !event.ports[0]) return;

  const port = event.ports[0];
  let record;
  if (validFetchRecord(data)) {
    record = {
      source: 'chunked-fetch',
      filename: data.filename || 'download.bin',
      size: Number.isSafeInteger(data.size) && data.size >= 0 ? data.size : null,
      apiPath: data.apiPath,
      relPath: data.relPath,
      keyHex: data.keyHex,
      deviceId: data.deviceId,
      port,
      started: false,
      abortController: new AbortController(),
    };
    port.onmessage = (event) => {
      const message = event.data || {};
      if (message.type === 'abort') forgetDownload(data.id);
    };
  } else {
    record = {
      source: 'port',
      filename: data.filename || 'download.bin',
      size: Number.isSafeInteger(data.size) && data.size >= 0 ? data.size : null,
      port,
      stream: makeDownloadStream(data.id, port),
      started: false,
    };
  }

  downloads.set(data.id, record);
  resolvePendingRecord(data.id, record);
  postToRecord(record, { type: 'initialized' });

  setTimeout(() => {
    const current = downloads.get(data.id);
    if (!current || current.started) return;
    forgetDownload(data.id);
    postToRecord(record, { type: 'timeout' });
  }, DOWNLOAD_INIT_TIMEOUT_MS);
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || !url.pathname.startsWith(DOWNLOAD_PREFIX)) return;

  const id = decodeURIComponent(url.pathname.slice(DOWNLOAD_PREFIX.length).split('/')[0] || '');
  event.respondWith((async () => {
    let record = null;
    try {
      record = await waitForDownloadRecord(id);
      if (!record) {
        return new Response('Download stream not found', { status: 404 });
      }

      record.started = true;
      const headers = new Headers({
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': contentDisposition(record.filename),
        'Cache-Control': 'no-store',
      });

      if (record.source === 'chunked-fetch') {
        let res;
        try {
          res = await signedFetch(record, record.abortController.signal);
        } catch (err) {
          console.error('cloudsyncd signed download request failed:', err);
          forgetDownload(id);
          postToRecord(record, { type: 'error', error: err.message || String(err) });
          return new Response('Download request failed', { status: 502 });
        }
        if (!res.ok) {
          const message = await readErrorMessage(res, 'Download failed');
          console.error('cloudsyncd signed download request returned error:', message);
          forgetDownload(id);
          postToRecord(record, { type: 'error', status: res.status, error: message });
          return new Response(message, { status: res.status, headers: { 'Cache-Control': 'no-store' } });
        }
        postToRecord(record, { type: 'ready' });
        return new Response(makeFetchDecryptStream(id, record, res), { headers });
      }

      postToRecord(record, { type: 'ready' });
      return new Response(record.stream, { headers });
    } catch (err) {
      console.error('cloudsyncd download response failed:', err);
      if (record) {
        forgetDownload(id);
        postToRecord(record, { type: 'error', error: err.message || String(err) });
      }
      return new Response('Download response failed', { status: 500, headers: { 'Cache-Control': 'no-store' } });
    }
  })());
});
